const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { NodeSSH } = require('node-ssh');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'warops-secret-key-change-this';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database Setup
const db = new sqlite3.Database('./warops.db');

// ایجاد جداول
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    ip TEXT,
    username TEXT,
    auth_method TEXT,
    password TEXT,
    ssh_key TEXT,
    status TEXT DEFAULT 'offline',
    last_check DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS installations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    template_name TEXT,
    status TEXT,
    progress INTEGER DEFAULT 0,
    logs TEXT,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY (server_id) REFERENCES servers(id)
  )`);
  
  // ایجاد کاربر پیش‌فرض
  const defaultPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', ?)`, [defaultPassword]);
});

// Middleware احراز هویت
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ================== AUTH APIs ==================

// لاگین
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: user.username });
  });
});

// تغییر رمز
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    
    const validPassword = await bcrypt.compare(oldPassword, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid old password' });
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ message: 'Password changed successfully' });
    });
  });
});

// ================== SERVER APIs ==================

// اتصال و بررسی سرور
app.post('/api/server/connect', authenticateToken, async (req, res) => {
  const { ip, username, authMethod, password, sshKey } = req.body;
  
  const ssh = new NodeSSH();
  
  try {
    const config = {
      host: ip,
      username: username,
      port: 22
    };
    
    if (authMethod === 'password') {
      config.password = password;
    } else {
      config.privateKey = sshKey;
    }
    
    await ssh.connect(config);
    
    // دریافت مشخصات سرور
    const cpuInfo = await ssh.execCommand("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
    const ramInfo = await ssh.execCommand("free -g | awk 'NR==2{printf \"%s %s\", $3,$2}'");
    const diskInfo = await ssh.execCommand("df -h / | awk 'NR==2{printf \"%s %s\", $3,$2}'");
    const osInfo = await ssh.execCommand("lsb_release -d | cut -f2");
    const kernelInfo = await ssh.execCommand("uname -r");
    const cpuModel = await ssh.execCommand("lscpu | grep 'Model name' | cut -d':' -f2 | xargs");
    
    const [ramUsed, ramTotal] = ramInfo.stdout.split(' ');
    const [diskUsed, diskTotal] = diskInfo.stdout.split(' ');
    
    ssh.dispose();
    
    res.json({
      success: true,
      specs: {
        cpu: parseFloat(cpuInfo.stdout) || 0,
        cpuModel: cpuModel.stdout || 'Unknown',
        ramUsed: parseInt(ramUsed) || 0,
        ramTotal: parseInt(ramTotal) || 0,
        diskUsed: parseInt(diskUsed) || 0,
        diskTotal: parseInt(diskTotal) || 0,
        network: Math.floor(Math.random() * 500) + 100,
        os: osInfo.stdout || 'Unknown',
        kernel: kernelInfo.stdout || 'Unknown'
      }
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ذخیره سرور
app.post('/api/servers', authenticateToken, (req, res) => {
  const { name, ip, username, authMethod, password, sshKey } = req.body;
  
  db.run(
    'INSERT INTO servers (name, ip, username, auth_method, password, ssh_key) VALUES (?, ?, ?, ?, ?, ?)',
    [name, ip, username, authMethod, password || null, sshKey || null],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ id: this.lastID, message: 'Server saved successfully' });
    }
  );
});

// لیست سرورها
app.get('/api/servers', authenticateToken, (req, res) => {
  db.all('SELECT id, name, ip, username, status, last_check, created_at FROM servers', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// حذف سرور
app.delete('/api/servers/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM servers WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ message: 'Server deleted successfully' });
  });
});

// ================== INSTALLATION APIs ==================

// شروع نصب
app.post('/api/install/start', authenticateToken, async (req, res) => {
  const { serverId, templates, config } = req.body;
  
  // ذخیره در دیتابیس
  const installId = Date.now();
  
  res.json({ success: true, installId });
  
  // اجرای نصب در background
  performInstallation(serverId, templates, config, installId);
});

// دریافت وضعیت نصب
app.get('/api/install/status/:id', authenticateToken, (req, res) => {
  db.get(
    'SELECT * FROM installations WHERE id = ?',
    [req.params.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'Installation not found' });
      
      res.json({
        status: row.status,
        progress: row.progress,
        logs: JSON.parse(row.logs || '[]')
      });
    }
  );
});

// تاریخچه نصب‌ها
app.get('/api/installations', authenticateToken, (req, res) => {
  db.all(
    `SELECT i.*, s.name as server_name, s.ip 
     FROM installations i 
     JOIN servers s ON i.server_id = s.id 
     ORDER BY i.started_at DESC 
     LIMIT 50`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// ================== TEMPLATES APIs ==================

app.get('/api/templates', (req, res) => {
  const templates = [
    {
      id: '1',
      nameEn: 'Docker Engine',
      nameFa: 'موتور Docker',
      category: 'Core',
      description: 'Container platform for modern apps',
      descriptionFa: 'پلتفرم کانتینری برای برنامه‌های مدرن',
      version: '24.0.7',
      verified: true,
      requirements: 'Ubuntu 20.04+, 2GB RAM',
      ports: '2375, 2376',
      icon: '🐳',
      size: '180 MB',
      installTime: '3-5 min',
      installScript: `
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl software-properties-common
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
        add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
        systemctl enable docker
        systemctl start docker
      `
    },
    {
      id: '2',
      nameEn: 'Nginx',
      nameFa: 'وب سرور Nginx',
      category: 'Core',
      description: 'High-performance web server',
      descriptionFa: 'وب سرور پرسرعت',
      version: '1.24.0',
      verified: true,
      requirements: 'Ubuntu 18.04+, 512MB RAM',
      ports: '80, 443',
      icon: '🌐',
      size: '45 MB',
      installTime: '2-3 min',
      installScript: `
        apt-get update
        apt-get install -y nginx
        systemctl enable nginx
        systemctl start nginx
      `
    },
    {
      id: '3',
      nameEn: 'X-UI Panel',
      nameFa: 'پنل X-UI',
      category: 'Panels',
      description: 'Advanced VPN panel',
      descriptionFa: 'پنل VPN پیشرفته',
      version: '2.3.5',
      verified: true,
      requirements: 'Docker, 1GB RAM',
      ports: '54321, 443',
      icon: '🎛️',
      size: '320 MB',
      installTime: '5-8 min',
      installScript: `
        bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)
      `
    }
  ];
  
  res.json(templates);
});

// ================== تابع نصب ==================

async function performInstallation(serverId, templates, config, installId) {
  const logs = [];
  
  function addLog(type, message) {
    logs.push({
      type,
      message,
      timestamp: new Date().toISOString()
    });
  }
  
  try {
    // دریافت اطلاعات سرور
    db.get('SELECT * FROM servers WHERE id = ?', [serverId], async (err, server) => {
      if (err || !server) {
        addLog('error', 'Server not found');
        return;
      }
      
      const ssh = new NodeSSH();
      
      try {
        // اتصال SSH
        addLog('info', `Connecting to ${server.ip}...`);
        
        const sshConfig = {
          host: server.ip,
          username: server.username,
          port: 22
        };
        
        if (server.auth_method === 'password') {
          sshConfig.password = server.password;
        } else {
          sshConfig.privateKey = server.ssh_key;
        }
        
        await ssh.connect(sshConfig);
        addLog('success', 'Connected successfully');
        
        // نصب هر Template
        for (let i = 0; i < templates.length; i++) {
          const template = templates[i];
          addLog('info', `Installing ${template.nameEn} (${i + 1}/${templates.length})...`);
          
          try {
            const result = await ssh.execCommand(template.installScript);
            
            if (result.code === 0) {
              addLog('success', `${template.nameEn} installed successfully`);
            } else {
              addLog('error', `Failed to install ${template.nameEn}: ${result.stderr}`);
            }
          } catch (error) {
            addLog('error', `Error installing ${template.nameEn}: ${error.message}`);
          }
        }
        
        ssh.dispose();
        addLog('success', 'Installation completed!');
        
      } catch (error) {
        addLog('error', `SSH Error: ${error.message}`);
      }
      
      // ذخیره لاگ‌ها
      db.run(
        'INSERT INTO installations (server_id, template_name, status, progress, logs, completed_at) VALUES (?, ?, ?, ?, ?, ?)',
        [serverId, templates.map(t => t.nameEn).join(', '), 'completed', 100, JSON.stringify(logs), new Date().toISOString()]
      );
    });
    
  } catch (error) {
    addLog('error', `Installation failed: ${error.message}`);
  }
}

// ================== راه‌اندازی سرور ==================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 WarOps Panel Backend running on port ${PORT}`);
  console.log(`📡 API: http://localhost:${PORT}/api`);
  console.log(`🌐 Frontend: http://localhost:${PORT}`);
});
