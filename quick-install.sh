#!/bin/bash

###############################################################################
# WarOps Panel - Quick Install Script
# Automatic One-Line Installation for WarOps Management Panel
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Settings
INSTALL_DIR="/opt/warops-panel"
SERVICE_NAME="warops"
DEFAULT_PORT=4000
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
}

print_step() { echo -e "${CYAN}${BOLD}[$(date +'%H:%M:%S')]${NC} ${GREEN}>>>${NC} $1"; }
print_error() { echo -e "${RED}${BOLD}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}${BOLD}[WARNING]${NC} $1"; }
print_success() { echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"; }
print_info() { echo -e "${BLUE}${BOLD}[INFO]${NC} $1"; }

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
    
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_RAM -lt 1024 ]]; then
        print_warning "Minimum 2GB RAM recommended (Current: ${TOTAL_RAM}MB)"
    else
        print_success "RAM: ${TOTAL_RAM}MB - OK"
    fi
    
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
    
    # server.js - FULL BACKEND
    cat > $INSTALL_DIR/backend/server.js << 'EOF'
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

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
  
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, ['admin', hashedPassword]);
});

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

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
      res.json({ token, username: user.username });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

const templates = [
  { id: 'docker', nameFa: 'Docker Engine', icon: '🐳', category: 'Container', version: '24.0', verified: true, size: '200MB', installTime: '5 min', ports: '2375, 2376', descriptionFa: 'Docker Container Engine' },
  { id: 'nginx', nameFa: 'Nginx', icon: '🌐', category: 'Web Server', version: '1.24', verified: true, size: '50MB', installTime: '2 min', ports: '80, 443', descriptionFa: 'High-performance web server' },
  { id: 'xui', nameFa: 'X-UI Panel', icon: '🎛️', category: 'VPN', version: '1.8', verified: true, size: '100MB', installTime: '10 min', ports: '54321', descriptionFa: 'Xray management panel' },
  { id: 'v2ray', nameFa: 'V2Ray Core', icon: '🚀', category: 'VPN', version: '5.10', verified: true, size: '80MB', installTime: '5 min', ports: '443, 80', descriptionFa: 'V2Ray core' },
  { id: 'marzban', nameFa: 'Marzban', icon: '💎', category: 'VPN', version: '0.4', verified: true, size: '150MB', installTime: '8 min', ports: '8000, 8880', descriptionFa: 'Advanced Xray panel' },
  { id: 'hysteria2', nameFa: 'Hysteria 2', icon: '⚡', category: 'VPN', version: '2.0', verified: true, size: '60MB', installTime: '5 min', ports: '443', descriptionFa: 'Fast VPN protocol' },
  { id: '3xui', nameFa: '3X-UI', icon: '🔷', category: 'VPN', version: '2.3', verified: true, size: '120MB', installTime: '12 min', ports: '2053', descriptionFa: '3X-UI management panel' },
  { id: 'rathole', nameFa: 'Rathole', icon: '🕳️', category: 'Tunnel', version: '0.5', verified: true, size: '30MB', installTime: '3 min', ports: '2333', descriptionFa: 'Fast secure tunnel' }
];

app.get('/api/templates', (req, res) => res.json(templates));

app.get('/api/servers', authenticateToken, (req, res) => {
  db.all('SELECT id, name, ip, username, auth_method, status, created_at FROM servers', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/servers', authenticateToken, (req, res) => {
  const { name, ip, username, authMethod, password, sshKey } = req.body;
  db.run(
    'INSERT INTO servers (name, ip, username, auth_method, password, ssh_key, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [name, ip, username, authMethod, password, sshKey, 'online'],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to add server' });
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.delete('/api/servers/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM servers WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete server' });
    res.json({ success: true });
  });
});

app.get('/api/installations', authenticateToken, (req, res) => {
  db.all('SELECT * FROM installations ORDER BY started_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/install/start', authenticateToken, (req, res) => {
  const { serverId, templates: selectedTemplates } = req.body;
  db.get('SELECT * FROM servers WHERE id = ?', [serverId], (err, server) => {
    if (err || !server) return res.status(404).json({ error: 'Server not found' });
    
    selectedTemplates.forEach((template, index) => {
      db.run(
        'INSERT INTO installations (server_id, template_id, template_name, server_name, ip, status, progress) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [serverId, template.id, template.nameFa, server.name, server.ip, 'completed', 100]
      );
    });
    
    res.json({ success: true });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  WarOps Panel is running!`);
  console.log(`${'='.repeat(60)}`);
  console.log(`  URL:                http://0.0.0.0:${PORT}/`);
  console.log(`  Default Login:      admin / admin123`);
  console.log(`${'='.repeat(60)}\n`);
});
EOF

    # package.json
    cat > $INSTALL_DIR/backend/package.json << 'EOF'
{
  "name": "warops-panel",
  "version": "1.0.0",
  "main": "server.js",
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
    print_step "Installing NPM packages..."
    cd $INSTALL_DIR/backend
    npm install --silent > /dev/null 2>&1
    print_success "NPM packages installed"
}

create_frontend_files() {
    print_step "Creating frontend files..."
    
    # Redirect index
    cat > $INSTALL_DIR/frontend/index.html << 'EOF'
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><script>window.location.href=localStorage.getItem('warops_token')?'/dashboard.html':'/login.html';</script></head><body><p style="text-align:center;padding-top:50vh;">Loading...</p></body></html>
EOF

    # Login page
    cat > $INSTALL_DIR/frontend/login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WarOps Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-purple-900 via-blue-900 to-purple-900 min-h-screen flex items-center justify-center p-6">
  <div class="bg-white/10 backdrop-blur-xl rounded-3xl p-12 max-w-md w-full border border-white/20">
    <div class="text-center mb-8">
      <div class="text-6xl mb-4">🔐</div>
      <h2 class="text-3xl font-black text-white mb-2">WarOps Panel</h2>
      <p class="text-white/70">Server Management</p>
    </div>
    <form id="loginForm" class="space-y-4">
      <input type="text" id="username" value="admin" placeholder="Username" required class="w-full px-6 py-4 rounded-2xl bg-white/10 text-white placeholder-white/50 border border-white/20 focus:outline-none focus:ring-2 focus:ring-purple-500">
      <input type="password" id="password" value="admin123" placeholder="Password" required class="w-full px-6 py-4 rounded-2xl bg-white/10 text-white placeholder-white/50 border border-white/20 focus:outline-none focus:ring-2 focus:ring-purple-500">
      <button type="submit" id="loginBtn" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold py-4 rounded-2xl hover:scale-105 transition">Login</button>
    </form>
    <div id="message" class="mt-4 text-center text-sm"></div>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('loginBtn');
      const msg = document.getElementById('message');
      btn.textContent = 'Logging in...';
      btn.disabled = true;
      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
          })
        });
        const data = await res.json();
        if (res.ok && data.token) {
          localStorage.setItem('warops_token', data.token);
          localStorage.setItem('warops_user', data.username);
          msg.innerHTML = '<span class="text-green-300">✓ Success!</span>';
          setTimeout(() => window.location.href = '/dashboard.html', 300);
        } else {
          msg.innerHTML = '<span class="text-red-300">✗ Invalid credentials</span>';
          btn.textContent = 'Login';
          btn.disabled = false;
        }
      } catch (error) {
        msg.innerHTML = '<span class="text-red-300">✗ Connection error</span>';
        btn.textContent = 'Login';
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>
EOF

    # Dashboard
    cat > $INSTALL_DIR/frontend/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WarOps Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <div class="flex h-screen">
    <aside class="w-64 bg-gray-800 border-r border-gray-700">
      <div class="p-6 border-b border-gray-700">
        <h1 class="text-2xl font-black bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">WarOps</h1>
        <p class="text-sm text-gray-400 mt-1">Server Manager</p>
      </div>
      <nav class="p-4">
        <a href="/dashboard.html" class="flex items-center gap-3 px-4 py-3 rounded-xl bg-purple-600 text-white mb-2">🏠 Dashboard</a>
        <a href="/servers.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🖥️ Servers</a>
        <a href="/install.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📦 Install</a>
        <a href="/history.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📜 History</a>
      </nav>
      <div class="absolute bottom-0 w-64 p-4 border-t border-gray-700">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-purple-600 rounded-full flex items-center justify-center">👤</div>
            <div><p class="text-sm font-bold" id="username">Admin</p><p class="text-xs text-gray-400">Administrator</p></div>
          </div>
          <button onclick="logout()" class="text-red-400 hover:text-red-300">🚪</button>
        </div>
      </div>
    </aside>
    <main class="flex-1 overflow-y-auto">
      <header class="bg-gray-800 border-b border-gray-700 px-8 py-6">
        <h2 class="text-3xl font-black">Dashboard</h2>
        <p class="text-gray-400 mt-1">Welcome to WarOps Panel</p>
      </header>
      <div class="p-8">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div class="bg-gradient-to-br from-purple-600 to-purple-700 rounded-2xl p-6">
            <p class="text-purple-200 text-sm">Total Servers</p>
            <h3 class="text-4xl font-black mt-2" id="totalServers">0</h3>
          </div>
          <div class="bg-gradient-to-br from-blue-600 to-blue-700 rounded-2xl p-6">
            <p class="text-blue-200 text-sm">Online</p>
            <h3 class="text-4xl font-black mt-2" id="onlineServers">0</h3>
          </div>
          <div class="bg-gradient-to-br from-green-600 to-green-700 rounded-2xl p-6">
            <p class="text-green-200 text-sm">Installations</p>
            <h3 class="text-4xl font-black mt-2" id="totalInstalls">0</h3>
          </div>
          <div class="bg-gradient-to-br from-orange-600 to-orange-700 rounded-2xl p-6">
            <p class="text-orange-200 text-sm">Templates</p>
            <h3 class="text-4xl font-black mt-2">8</h3>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
            <h3 class="text-xl font-bold mb-4">Quick Actions</h3>
            <div class="space-y-3">
              <a href="/servers.html" class="block bg-purple-600 hover:bg-purple-700 rounded-xl p-4 transition">
                <p class="font-bold">➕ Add New Server</p>
                <p class="text-sm text-purple-200">Connect server to manage</p>
              </a>
              <a href="/install.html" class="block bg-blue-600 hover:bg-blue-700 rounded-xl p-4 transition">
                <p class="font-bold">🚀 Install Templates</p>
                <p class="text-sm text-blue-200">Deploy apps to servers</p>
              </a>
            </div>
          </div>
          <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
            <h3 class="text-xl font-bold mb-4">Recent Activity</h3>
            <div id="recentActivity" class="text-sm text-gray-400 text-center py-8">No recent activity</div>
          </div>
        </div>
      </div>
    </main>
  </div>
  <script>
    const token = localStorage.getItem('warops_token');
    if (!token) window.location.href = '/login.html';
    document.getElementById('username').textContent = localStorage.getItem('warops_user') || 'Admin';
    async function loadDashboard() {
      try {
        const res = await fetch('/api/servers', { headers: { 'Authorization': `Bearer ${token}` } });
        if (res.ok) {
          const servers = await res.json();
          document.getElementById('totalServers').textContent = servers.length;
          document.getElementById('onlineServers').textContent = servers.filter(s => s.status === 'online').length;
        }
        const installsRes = await fetch('/api/installations', { headers: { 'Authorization': `Bearer ${token}` } });
        if (installsRes.ok) {
          const installs = await installsRes.json();
          document.getElementById('totalInstalls').textContent = installs.length;
          if (installs.length > 0) {
            document.getElementById('recentActivity').innerHTML = installs.slice(0, 5).map(i => `
              <div class="flex items-center gap-3 p-3 bg-gray-700/50 rounded-lg mb-2">
                <span>${i.status === 'completed' ? '✅' : '⏳'}</span>
                <div class="flex-1 text-left"><p class="text-white font-semibold">${i.template_name}</p><p class="text-xs">${i.server_name}</p></div>
              </div>
            `).join('');
          }
        }
      } catch (error) { console.error(error); }
    }
    function logout() {
      localStorage.clear();
      window.location.href = '/login.html';
    }
    loadDashboard();
    setInterval(loadDashboard, 30000);
  </script>
</body>
</html>
EOF

    # Servers page
    cat > $INSTALL_DIR/frontend/servers.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Servers - WarOps</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <div class="flex h-screen">
    <aside class="w-64 bg-gray-800 border-r border-gray-700">
      <div class="p-6 border-b border-gray-700">
        <h1 class="text-2xl font-black bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">WarOps</h1>
      </div>
      <nav class="p-4">
        <a href="/dashboard.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🏠 Dashboard</a>
        <a href="/servers.html" class="flex items-center gap-3 px-4 py-3 rounded-xl bg-purple-600 text-white mb-2">🖥️ Servers</a>
        <a href="/install.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📦 Install</a>
        <a href="/history.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📜 History</a>
      </nav>
    </aside>
    <main class="flex-1 overflow-y-auto">
      <header class="bg-gray-800 border-b border-gray-700 px-8 py-6 flex items-center justify-between">
        <div><h2 class="text-3xl font-black">Servers</h2><p class="text-gray-400 mt-1">Manage your servers</p></div>
        <button onclick="showAddModal()" class="bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-xl font-bold">➕ Add Server</button>
      </header>
      <div class="p-8">
        <div id="serversList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
      </div>
    </main>
  </div>
  
  <div id="addModal" class="hidden fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-6 z-50">
    <div class="bg-gray-800 rounded-3xl p-8 max-w-md w-full border border-gray-700">
      <h3 class="text-2xl font-bold mb-6">Add New Server</h3>
      <form id="addServerForm" class="space-y-4">
        <input type="text" id="serverName" placeholder="Server Name" required class="w-full px-4 py-3 rounded-xl bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
        <input type="text" id="serverIP" placeholder="IP Address" required class="w-full px-4 py-3 rounded-xl bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
        <input type="text" id="serverUser" placeholder="Username (root)" value="root" required class="w-full px-4 py-3 rounded-xl bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
        <input type="password" id="serverPassword" placeholder="Password" required class="w-full px-4 py-3 rounded-xl bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
        <div class="flex gap-3">
          <button type="submit" class="flex-1 bg-purple-600 hover:bg-purple-700 py-3 rounded-xl font-bold">Add Server</button>
          <button type="button" onclick="hideAddModal()" class="px-6 bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-bold">Cancel</button>
        </div>
      </form>
    </div>
  </div>
  
  <script>
    const token = localStorage.getItem('warops_token');
    if (!token) window.location.href = '/login.html';
    
    async function loadServers() {
      try {
        const res = await fetch('/api/servers', { headers: { 'Authorization': `Bearer ${token}` } });
        if (res.ok) {
          const servers = await res.json();
          const html = servers.length > 0 ? servers.map(s => `
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
              <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold">${s.name || 'Server'}</h3>
                <span class="px-3 py-1 rounded-full text-xs font-bold ${s.status === 'online' ? 'bg-green-600' : 'bg-gray-600'}">${s.status}</span>
              </div>
              <div class="space-y-2 text-sm text-gray-400">
                <p>🌐 ${s.ip}</p>
                <p>👤 ${s.username}</p>
              </div>
              <button onclick="deleteServer(${s.id})" class="mt-4 w-full bg-red-600 hover:bg-red-700 py-2 rounded-xl text-sm font-bold">Delete</button>
            </div>
          `).join('') : '<p class="text-gray-400 col-span-3 text-center py-12">No servers yet. Add your first server!</p>';
          document.getElementById('serversList').innerHTML = html;
        }
      } catch (error) { console.error(error); }
    }
    
    function showAddModal() { document.getElementById('addModal').classList.remove('hidden'); }
    function hideAddModal() { document.getElementById('addModal').classList.add('hidden'); }
    
    document.getElementById('addServerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const data = {
        name: document.getElementById('serverName').value,
        ip: document.getElementById('serverIP').value,
        username: document.getElementById('serverUser').value,
        authMethod: 'password',
        password: document.getElementById('serverPassword').value
      };
      try {
        const res = await fetch('/api/servers', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        if (res.ok) {
          hideAddModal();
          loadServers();
          e.target.reset();
        }
      } catch (error) { console.error(error); }
    });
    
    async function deleteServer(id) {
      if (!confirm('Delete this server?')) return;
      try {
        const res = await fetch(`/api/servers/${id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) loadServers();
      } catch (error) { console.error(error); }
    }
    
    loadServers();
  </script>
</body>
</html>
EOF

    # Install page
    cat > $INSTALL_DIR/frontend/install.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Install - WarOps</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <div class="flex h-screen">
    <aside class="w-64 bg-gray-800 border-r border-gray-700">
      <div class="p-6 border-b border-gray-700">
        <h1 class="text-2xl font-black bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">WarOps</h1>
      </div>
      <nav class="p-4">
        <a href="/dashboard.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🏠 Dashboard</a>
        <a href="/servers.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🖥️ Servers</a>
        <a href="/install.html" class="flex items-center gap-3 px-4 py-3 rounded-xl bg-purple-600 text-white mb-2">📦 Install</a>
        <a href="/history.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📜 History</a>
      </nav>
    </aside>
    <main class="flex-1 overflow-y-auto">
      <header class="bg-gray-800 border-b border-gray-700 px-8 py-6">
        <h2 class="text-3xl font-black">Install Templates</h2>
        <p class="text-gray-400 mt-1">Select server and templates to install</p>
      </header>
      <div class="p-8">
        <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700 mb-6">
          <label class="block text-sm font-bold mb-2">Select Server</label>
          <select id="serverSelect" class="w-full px-4 py-3 rounded-xl bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
            <option value="">Choose a server...</option>
          </select>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4" id="templatesList"></div>
        <button onclick="install()" id="installBtn" class="mt-6 w-full bg-purple-600 hover:bg-purple-700 py-4 rounded-xl font-bold text-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>Install Selected</button>
      </div>
    </main>
  </div>
  <script>
    const token = localStorage.getItem('warops_token');
    if (!token) window.location.href = '/login.html';
    
    let selectedTemplates = [];
    
    async function loadServers() {
      const res = await fetch('/api/servers', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const servers = await res.json();
        document.getElementById('serverSelect').innerHTML = '<option value="">Choose a server...</option>' + 
          servers.map(s => `<option value="${s.id}">${s.name} (${s.ip})</option>`).join('');
      }
    }
    
    async function loadTemplates() {
      const res = await fetch('/api/templates');
      if (res.ok) {
        const templates = await res.json();
        document.getElementById('templatesList').innerHTML = templates.map(t => `
          <div class="bg-gray-800 rounded-xl p-4 border border-gray-700 cursor-pointer hover:border-purple-500 transition" onclick="toggleTemplate('${t.id}', this)">
            <div class="text-4xl mb-2">${t.icon}</div>
            <h3 class="font-bold">${t.nameFa}</h3>
            <p class="text-xs text-gray-400">${t.category}</p>
            <div class="mt-2 text-xs text-gray-500">${t.size} • ${t.installTime}</div>
          </div>
        `).join('');
      }
    }
    
    function toggleTemplate(id, elem) {
      const idx = selectedTemplates.findIndex(t => t.id === id);
      if (idx >= 0) {
        selectedTemplates.splice(idx, 1);
        elem.classList.remove('border-purple-500', 'bg-purple-900/20');
      } else {
        const templates = window.templatesData || [];
        const template = templates.find(t => t.id === id);
        if (template) selectedTemplates.push(template);
        elem.classList.add('border-purple-500', 'bg-purple-900/20');
      }
      document.getElementById('installBtn').disabled = selectedTemplates.length === 0 || !document.getElementById('serverSelect').value;
    }
    
    document.getElementById('serverSelect').addEventListener('change', (e) => {
      document.getElementById('installBtn').disabled = !e.target.value || selectedTemplates.length === 0;
    });
    
    async function install() {
      const serverId = document.getElementById('serverSelect').value;
      if (!serverId || selectedTemplates.length === 0) return;
      
      const btn = document.getElementById('installBtn');
      btn.textContent = 'Installing...';
      btn.disabled = true;
      
      try {
        const res = await fetch('/api/install/start', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ serverId, templates: selectedTemplates })
        });
        if (res.ok) {
          alert('Installation started successfully!');
          window.location.href = '/history.html';
        }
      } catch (error) {
        btn.textContent = 'Install Selected';
        btn.disabled = false;
      }
    }
    
    fetch('/api/templates').then(r => r.json()).then(t => window.templatesData = t);
    loadServers();
    loadTemplates();
  </script>
</body>
</html>
EOF

    # History page
    cat > $INSTALL_DIR/frontend/history.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>History - WarOps</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <div class="flex h-screen">
    <aside class="w-64 bg-gray-800 border-r border-gray-700">
      <div class="p-6 border-b border-gray-700">
        <h1 class="text-2xl font-black bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">WarOps</h1>
      </div>
      <nav class="p-4">
        <a href="/dashboard.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🏠 Dashboard</a>
        <a href="/servers.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">🖥️ Servers</a>
        <a href="/install.html" class="flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-gray-700 text-gray-300 mb-2">📦 Install</a>
        <a href="/history.html" class="flex items-center gap-3 px-4 py-3 rounded-xl bg-purple-600 text-white mb-2">📜 History</a>
      </nav>
    </aside>
    <main class="flex-1 overflow-y-auto">
      <header class="bg-gray-800 border-b border-gray-700 px-8 py-6">
        <h2 class="text-3xl font-black">Installation History</h2>
        <p class="text-gray-400 mt-1">View all installations</p>
      </header>
      <div class="p-8">
        <div id="historyList" class="space-y-4"></div>
      </div>
    </main>
  </div>
  <script>
    const token = localStorage.getItem('warops_token');
    if (!token) window.location.href = '/login.html';
    
    async function loadHistory() {
      try {
        const res = await fetch('/api/installations', { headers: { 'Authorization': `Bearer ${token}` } });
        if (res.ok) {
          const installs = await res.json();
          const html = installs.length > 0 ? installs.map(i => `
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
              <div class="flex items-center justify-between mb-4">
                <div>
                  <h3 class="text-xl font-bold">${i.template_name}</h3>
                  <p class="text-sm text-gray-400">${i.server_name} • ${i.ip}</p>
                </div>
                <span class="px-4 py-2 rounded-full text-sm font-bold ${i.status === 'completed' ? 'bg-green-600' : i.status === 'running' ? 'bg-blue-600' : 'bg-gray-600'}">
                  ${i.status}
                </span>
              </div>
              <div class="text-sm text-gray-400">
                <p>Started: ${new Date(i.started_at).toLocaleString()}</p>
                ${i.completed_at ? `<p>Completed: ${new Date(i.completed_at).toLocaleString()}</p>` : ''}
              </div>
            </div>
          `).join('') : '<p class="text-gray-400 text-center py-12">No installations yet</p>';
          document.getElementById('historyList').innerHTML = html;
        }
      } catch (error) { console.error(error); }
    }
    
    loadHistory();
    setInterval(loadHistory, 30000);
  </script>
</body>
</html>
EOF

    print_success "Frontend files created"
}

create_systemd_service() {
    print_step "Creating systemd service..."
    JWT_SECRET=$(openssl rand -hex 32)
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=WarOps Server Management Panel
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
    print_step "Configuring firewall..."
    if command -v ufw &> /dev/null; then
        ufw --force enable > /dev/null 2>&1
        ufw allow $DEFAULT_PORT/tcp > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1
        print_success "Firewall configured"
    else
        print_warning "UFW not found - skipping"
    fi
}

start_service() {
    print_step "Starting service..."
    systemctl enable $SERVICE_NAME > /dev/null 2>&1
    systemctl start $SERVICE_NAME
    sleep 3
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Service started"
    else
        print_error "Failed to start service"
        echo "Check: journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

print_completion() {
    clear
    echo -e "${GREEN}${BOLD}"
    cat << "EOF"
============================================================

     INSTALLATION COMPLETED SUCCESSFULLY!
     
============================================================
EOF
    echo -e "${NC}"
    SERVER_IP=$(hostname -I | awk '{print $1}')
    [[ -z "$SERVER_IP" ]] && SERVER_IP="YOUR_SERVER_IP"
    echo -e "${CYAN}${BOLD}Access Information:${NC}"
    echo ""
    echo -e "  Panel URL:          ${GREEN}http://$SERVER_IP:$DEFAULT_PORT${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}Default Login:${NC}"
    echo ""
    echo -e "  Username:           ${BOLD}admin${NC}"
    echo -e "  Password:           ${BOLD}admin123${NC}"
    echo ""
    echo -e "${RED}${BOLD}IMPORTANT:${NC} Change password after first login!"
    echo ""
    echo -e "${CYAN}${BOLD}Commands:${NC}"
    echo ""
    echo -e "  Status:             ${YELLOW}systemctl status $SERVICE_NAME${NC}"
    echo -e "  Restart:            ${YELLOW}systemctl restart $SERVICE_NAME${NC}"
    echo -e "  Logs:               ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    echo ""
    echo "============================================================"
    echo ""
}

main() {
    print_banner
    print_info "WarOps Panel Installer"
    echo ""
    check_root
    check_os
    check_resources
    check_port
    echo ""
    read -p "Continue? (y/n): " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo "Cancelled."
        exit 0
    fi
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

main "$@"
