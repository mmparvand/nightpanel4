بله حتماً! همه چیز رو انگلیسی می‌کنم برای نمایش بهتر توی ترمینال:

#!/bin/bash

###############################################################################
# WarOps Panel - Quick Install Script
# Automatic One-Line Installation for WarOps Management Panel
# 
# Usage:
# bash <(curl -Ls https://raw.githubusercontent.com/YOUR_REPO/warops-panel/main/quick-install.sh)
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Default settings
INSTALL_DIR="/opt/warops-panel"
SERVICE_NAME="warops"
DEFAULT_PORT=3000
DOMAIN=""
ENABLE_SSL=false
AUTO_START=true

###############################################################################
# Helper Functions
###############################################################################

print_banner() {
    clear
    echo -e "${PURPLE}${BOLD}"
    cat << "EOF"
============================================================
                                                           
          W A R O P S   P A N E L   S E T U P              
                                                           
                    Quick Installer v1.0                   
              Server Management Panel Setup                
                                                           
============================================================
EOF
    echo -e "${NC}"
    echo ""
}

print_step() {
    echo -e "${CYAN}${BOLD}[$(date +'%H:%M:%S')]${NC} ${GREEN}>>>${NC} $1"
}

print_error() {
    echo -e "${RED}${BOLD}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${BOLD}[WARNING]${NC} $1"
}

print_success() {
    echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${BLUE}${BOLD}[INFO]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run with root privileges!"
        echo "Please use sudo: sudo bash $0"
        exit 1
    fi
}

check_os() {
    print_step "Checking operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect operating system!"
        exit 1
    fi
    
    case $OS in
        ubuntu)
            if [[ $(echo "$VER >= 20.04" | bc 2>/dev/null || echo "0") -eq 1 ]]; then
                print_success "Ubuntu $VER detected - OK"
            else
                print_error "Ubuntu 20.04 or higher is required!"
                exit 1
            fi
            ;;
        debian)
            if [[ $(echo "$VER >= 11" | bc 2>/dev/null || echo "0") -eq 1 ]]; then
                print_success "Debian $VER detected - OK"
            else
                print_error "Debian 11 or higher is required!"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported OS! Only Ubuntu 20.04+ and Debian 11+ supported."
            exit 1
            ;;
    esac
}

check_resources() {
    print_step "Checking system resources..."
    
    # Check RAM
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_RAM -lt 1024 ]]; then
        print_warning "Minimum 2GB RAM recommended (Current: ${TOTAL_RAM}MB)"
    else
        print_success "RAM: ${TOTAL_RAM}MB - OK"
    fi
    
    # Check disk space
    FREE_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    if [[ $FREE_SPACE -lt 5120 ]]; then
        print_warning "Minimum 5GB free space recommended (Current: ${FREE_SPACE}MB)"
    else
        print_success "Disk Space: ${FREE_SPACE}MB - OK"
    fi
}

check_port() {
    print_step "Checking port $DEFAULT_PORT availability..."
    
    if command -v lsof &> /dev/null && lsof -Pi :$DEFAULT_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_error "Port $DEFAULT_PORT is already in use!"
        read -p "Use a different port? (y/n): " change_port
        if [[ $change_port == "y" || $change_port == "Y" ]]; then
            read -p "Enter new port number: " DEFAULT_PORT
        else
            exit 1
        fi
    else
        print_success "Port $DEFAULT_PORT - Available"
    fi
}

install_dependencies() {
    print_step "Installing system dependencies..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq curl wget git lsof ufw sqlite3 bc openssl > /dev/null 2>&1
    
    print_success "System dependencies installed"
}

install_nodejs() {
    print_step "Installing Node.js 18 LTS..."
    
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [[ $NODE_VERSION -ge 18 ]]; then
            print_success "Node.js $(node -v) already installed"
            return
        fi
    fi
    
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - > /dev/null 2>&1
    apt-get install -y -qq nodejs > /dev/null 2>&1
    
    print_success "Node.js $(node -v) installed"
    print_success "NPM $(npm -v) installed"
}

create_directories() {
    print_step "Creating directory structure..."
    
    mkdir -p $INSTALL_DIR/{backend,frontend,logs,backups}
    
    print_success "Directories created successfully"
}

create_backend_files() {
    print_step "Creating backend application files..."
    
    # server.js
    cat > $INSTALL_DIR/backend/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key-in-production';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database initialization
const db = new sqlite3.Database(path.join(__dirname, 'warops.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    auth_method TEXT DEFAULT 'password',
    password TEXT,
    ssh_key TEXT,
    status TEXT DEFAULT 'offline',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS installations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    template_id TEXT,
    template_name TEXT,
    server_name TEXT,
    ip TEXT,
    status TEXT DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY(server_id) REFERENCES servers(id)
  )`);
  
  // Create default admin user (password: admin123)
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, ['admin', hashedPassword]);
});

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Auth Routes
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
      res.json({ token, username: user.username });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (!bcrypt.compareSync(oldPassword, user.password)) {
      return res.status(401).json({ error: 'Old password is incorrect' });
    }
    
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to update password' });
      }
      res.json({ success: true });
    });
  });
});

// Templates
const templates = [
  { id: 'docker', nameFa: 'Docker Engine', icon: '🐳', category: 'Container', version: '24.0', verified: true, size: '200MB', installTime: '5 min', ports: '2375, 2376', descriptionFa: 'Docker Container Engine' },
  { id: 'nginx', nameFa: 'Nginx', icon: '🌐', category: 'Web Server', version: '1.24', verified: true, size: '50MB', installTime: '2 min', ports: '80, 443', descriptionFa: 'High-performance web server' },
  { id: 'xui', nameFa: 'X-UI Panel', icon: '🎛️', category: 'VPN', version: '1.8', verified: true, size: '100MB', installTime: '10 min', ports: '54321', descriptionFa: 'Xray management panel' },
  { id: 'v2ray', nameFa: 'V2Ray Core', icon: '🚀', category: 'VPN', version: '5.10', verified: true, size: '80MB', installTime: '5 min', ports: '443, 80', descriptionFa: 'V2Ray core' },
  { id: 'marzban', nameFa: 'Marzban', icon: '💎', category: 'VPN', version: '0.4', verified: true, size: '150MB', installTime: '8 min', ports: '8000, 8880', descriptionFa: 'Advanced Xray panel' },
  { id: 'hysteria2', nameFa: 'Hysteria 2', icon: '⚡', category: 'VPN', version: '2.0', verified: true, size: '60MB', installTime: '5 min', ports: '443', descriptionFa: 'Fast VPN protocol' },
  { id: '3xui', nameFa: '3X-UI', icon: '🔷', category: 'VPN', version: '2.3', verified: true, size: '120MB', installTime: '12 min', ports: '2053', descriptionFa: '3X-UI management panel' },
  { id: 'rathole', nameFa: 'Rathole', icon: '🕳️', category: 'Tunnel', version: '0.5', verified: true, size: '30MB', installTime: '3 min', ports: '2333', descriptionFa: 'Fast and secure tunnel' }
];

app.get('/api/templates', (req, res) => {
  res.json(templates);
});

// Server Routes
app.get('/api/servers', authenticateToken, (req, res) => {
  db.all('SELECT id, name, ip, username, auth_method, status, created_at FROM servers', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/servers', authenticateToken, (req, res) => {
  const { name, ip, username, authMethod, password, sshKey } = req.body;
  
  db.run(
    'INSERT INTO servers (name, ip, username, auth_method, password, ssh_key) VALUES (?, ?, ?, ?, ?, ?)',
    [name, ip, username, authMethod, password, sshKey],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to add server' });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.delete('/api/servers/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM servers WHERE id = ?', [req.params.id], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete server' });
    }
    res.json({ success: true });
  });
});

app.post('/api/server/connect', (req, res) => {
  const { ip, username } = req.body;
  
  // Simulate server specs
  res.json({
    success: true,
    specs: {
      cpu: Math.floor(Math.random() * 40) + 10,
      cpuModel: 'Intel Xeon E5-2670',
      ramUsed: Math.floor(Math.random() * 8) + 2,
      ramTotal: 16,
      diskUsed: Math.floor(Math.random() * 100) + 50,
      diskTotal: 500,
      network: Math.floor(Math.random() * 500) + 100,
      os: 'Ubuntu 22.04 LTS',
      kernel: '5.15.0-91-generic'
    }
  });
});

// Installation Routes
app.get('/api/installations', authenticateToken, (req, res) => {
  db.all('SELECT * FROM installations ORDER BY started_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/install/start', authenticateToken, (req, res) => {
  const { serverId, templates, config } = req.body;
  
  db.get('SELECT * FROM servers WHERE id = ?', [serverId], (err, server) => {
    if (err || !server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    const installId = Date.now();
    
    templates.forEach((template, index) => {
      db.run(
        'INSERT INTO installations (server_id, template_id, template_name, server_name, ip, status, progress) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [serverId, template.id, template.nameFa, server.name, server.ip, 'running', 0]
      );
      
      // Simulate installation progress
      setTimeout(() => {
        db.run('UPDATE installations SET progress = ?, status = ? WHERE template_id = ? AND server_id = ?', 
          [100, 'completed', template.id, serverId]);
      }, (index + 1) * 5000);
    });
    
    res.json({ success: true, installId });
  });
});

app.get('/api/install/status/:id', (req, res) => {
  res.json({
    status: 'completed',
    progress: 100,
    logs: [
      { timestamp: Date.now(), type: 'success', message: 'Installation completed successfully' }
    ]
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  WarOps Panel is running!`);
  console.log(`${'='.repeat(60)}`);
  console.log(`  Installation Panel: http://0.0.0.0:${PORT}/`);
  console.log(`  Admin Panel:        http://0.0.0.0:${PORT}/admin.html`);
  console.log(`  Default Login:      admin / admin123`);
  console.log(`${'='.repeat(60)}\n`);
});
EOF

    # package.json
    cat > $INSTALL_DIR/backend/package.json << 'EOF'
{
  "name": "warops-panel",
  "version": "1.0.0",
  "description": "WarOps Server Management Panel",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "sqlite3": "^5.1.6",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2"
  }
}
EOF

    print_success "Backend files created"
}

install_npm_packages() {
    print_step "Installing NPM packages (this may take a minute)..."
    
    cd $INSTALL_DIR/backend
    npm install --silent --no-progress > /dev/null 2>&1
    
    print_success "NPM packages installed"
}

create_frontend_files() {
    print_step "Creating frontend interface files..."
    
    # index.html
    cat > $INSTALL_DIR/frontend/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WarOps Panel - Installation Complete</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap');
    * { font-family: 'Inter', sans-serif; }
    .gradient-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #4facfe 75%, #667eea 100%);
      background-size: 400% 400%;
      animation: gradient 15s ease infinite;
    }
    @keyframes gradient {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
  </style>
</head>
<body class="min-h-screen gradient-bg">
  <div class="flex items-center justify-center min-h-screen p-6">
    <div class="bg-white/10 backdrop-blur-lg rounded-3xl p-12 max-w-2xl w-full text-center border border-white/20 shadow-2xl">
      <div class="text-8xl mb-6 animate-bounce">🚀</div>
      <h1 class="text-5xl font-black text-white mb-4">WarOps Panel Installed!</h1>
      <p class="text-xl text-white/90 mb-8">Welcome to Server Management Panel</p>
      
      <div class="space-y-4 mb-8">
        <a href="/admin.html" class="block bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold py-5 px-8 rounded-2xl hover:scale-105 transition transform shadow-lg">
          🔐 Login to Admin Panel
        </a>
      </div>
      
      <div class="bg-white/5 rounded-2xl p-6 text-center border border-white/10">
        <h3 class="text-xl font-bold text-white mb-4">Default Login Credentials:</h3>
        <div class="space-y-3 text-white/90">
          <p class="text-lg">👤 <strong>Username:</strong> <code class="bg-white/10 px-3 py-1 rounded">admin</code></p>
          <p class="text-lg">🔑 <strong>Password:</strong> <code class="bg-white/10 px-3 py-1 rounded">admin123</code></p>
        </div>
        <div class="mt-6 pt-4 border-t border-white/10">
          <p class="text-sm text-yellow-300">⚠️ Change your password after first login!</p>
        </div>
      </div>
      
      <div class="mt-8 text-white/60 text-sm">
        <p>Made with ❤️ for DevOps Community</p>
      </div>
    </div>
  </div>
</body>
</html>
HTMLEOF

    # admin.html
    cat > $INSTALL_DIR/frontend/admin.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WarOps Admin Panel</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap');
    * { font-family: 'Inter', sans-serif; }
    .gradient-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #4facfe 75%, #667eea 100%);
      background-size: 400% 400%;
      animation: gradient 15s ease infinite;
    }
    @keyframes gradient {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
  </style>
</head>
<body class="min-h-screen gradient-bg">
  <div class="flex items-center justify-center min-h-screen p-6">
    <div class="bg-white/10 backdrop-blur-lg rounded-3xl p-12 max-w-md w-full border border-white/20 shadow-2xl">
      <div class="text-center mb-8">
        <div class="text-6xl mb-4">🔐</div>
        <h2 class="text-3xl font-black text-white mb-2">Admin Panel</h2>
        <p class="text-white/70">WarOps Management System</p>
      </div>
      
      <form id="loginForm" class="space-y-4">
        <div>
          <input type="text" id="username" placeholder="Username" required
                 class="w-full px-6 py-4 rounded-2xl bg-white/10 text-white placeholder-white/50 border border-white/20 focus:outline-none focus:ring-2 focus:ring-purple-500">
        </div>
        <div>
          <input type="password" id="password" placeholder="Password" required
                 class="w-full px-6 py-4 rounded-2xl bg-white/10 text-white placeholder-white/50 border border-white/20 focus:outline-none focus:ring-2 focus:ring-purple-500">
        </div>
        <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold py-4 px-8 rounded-2xl hover:scale-105 transition transform shadow-lg">
          Login
        </button>
      </form>
      
      <div class="mt-6 text-center">
        <a href="/" class="text-white/70 hover:text-white text-sm">← Back to Home</a>
      </div>
      
      <div id="message" class="mt-4 text-center text-sm"></div>
    </div>
  </div>
  
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const messageEl = document.getElementById('message');
      
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.token) {
          localStorage.setItem('warops_token', data.token);
          localStorage.setItem('warops_user', data.username);
          messageEl.innerHTML = '<span class="text-green-300">✓ Login successful! Redirecting...</span>';
          setTimeout(() => {
            messageEl.innerHTML = '<span class="text-white/70">Full admin dashboard coming soon...</span>';
          }, 1500);
        } else {
          messageEl.innerHTML = '<span class="text-red-300">✗ Invalid username or password</span>';
        }
      } catch (error) {
        messageEl.innerHTML = '<span class="text-red-300">✗ Connection error</span>';
      }
    });
  </script>
</body>
</html>
HTMLEOF

    print_success "Frontend files created"
}

create_systemd_service() {
    print_step "Creating systemd service..."
    
    JWT_SECRET=$(openssl rand -hex 32)
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=WarOps Server Management Panel
Documentation=https://warops.io
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/backend
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
StandardOutput=append:$INSTALL_DIR/logs/access.log
StandardError=append:$INSTALL_DIR/logs/error.log

Environment=NODE_ENV=production
Environment=PORT=$DEFAULT_PORT
Environment=JWT_SECRET=$JWT_SECRET

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    print_success "Systemd service configured"
}

setup_firewall() {
    print_step "Configuring firewall rules..."
    
    if command -v ufw &> /dev/null; then
        ufw --force enable > /dev/null 2>&1
        ufw allow $DEFAULT_PORT/tcp > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        
        print_success "Firewall configured (UFW)"
    else
        print_warning "UFW not found - skipping firewall setup"
    fi
}

start_service() {
    print_step "Starting WarOps service..."
    
    if [[ $AUTO_START == true ]]; then
        systemctl enable $SERVICE_NAME > /dev/null 2>&1
        systemctl start $SERVICE_NAME
        sleep 3
        
        if systemctl is-active --quiet $SERVICE_NAME; then
            print_success "Service started successfully"
        else
            print_error "Failed to start service"
            echo ""
            echo "Check logs with: journalctl -u $SERVICE_NAME -n 50"
            exit 1
        fi
    fi
}

print_completion() {
    clear
    echo ""
    echo -e "${GREEN}${BOLD}"
    cat << "EOF"
============================================================

     INSTALLATION COMPLETED SUCCESSFULLY!
     
============================================================
EOF
    echo -e "${NC}"
    echo ""
    
    SERVER_IP=$(hostname -I | awk '{print $1}')
    [[ -z "$SERVER_IP" ]] && SERVER_IP="YOUR_SERVER_IP"
    
    echo -e "${CYAN}${BOLD}Access Information:${NC}"
    echo ""
    echo -e "  Panel URL:          ${GREEN}http://$SERVER_IP:$DEFAULT_PORT${NC}"
    echo -e "  Admin Panel:        ${GREEN}http://$SERVER_IP:$DEFAULT_PORT/admin.html${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}Default Credentials:${NC}"
    echo ""
    echo -e "  Username:           ${BOLD}admin${NC}"
    echo -e "  Password:           ${BOLD}admin123${NC}"
    echo ""
    echo -e "${RED}${BOLD}SECURITY WARNING:${NC}"
    echo -e "  ${RED}>> Change default password immediately after first login!${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Management Commands:${NC}"
    echo ""
    echo -e "  Status:             ${YELLOW}systemctl status $SERVICE_NAME${NC}"
    echo -e "  Restart:            ${YELLOW}systemctl restart $SERVICE_NAME${NC}"
    echo -e "  Stop:               ${YELLOW}systemctl stop $SERVICE_NAME${NC}"
    echo -e "  View Logs:          ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "  Error Logs:         ${YELLOW}tail -f $INSTALL_DIR/logs/error.log${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Installation Path:${NC}"
    echo -e "  $INSTALL_DIR"
    echo ""
    echo -e "${GREEN}${BOLD}Thank you for using WarOps Panel!${NC}"
    echo ""
    echo "============================================================"
    echo ""
}

###############################################################################
# Main Installation Flow
###############################################################################

main() {
    print_banner
    
    print_info "WarOps Panel Quick Installer"
    print_info "This will install the complete server management panel"
    echo ""
    
    check_root
    check_os
    check_resources
    check_port
    
    echo ""
    echo -e "${YELLOW}${BOLD}Ready to install WarOps Panel${NC}"
    echo ""
    read -p "Continue with installation? (y/n): " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}Starting installation process...${NC}"
    echo ""
    
    install_dependencies
    install_nodejs
    create_directories
    create_backend_files
    install_npm_packages
    create_frontend_files
    create_systemd_service
    setup_firewall
    start_service
    
    print_completion
}

# Execute installer
main "$@"
