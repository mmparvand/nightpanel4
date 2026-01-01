#!/bin/bash

echo "🚀 WarOps Panel Installation Started..."
echo ""

# بررسی root
if [ "$EUID" -ne 0 ]; then 
  echo "❌ Please run as root (use: sudo bash install.sh)"
  exit 1
fi

# نصب Node.js و npm
echo "📦 Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# نصب PM2
echo "📦 Installing PM2..."
npm install -g pm2

# ساخت دایرکتوری
echo "📁 Creating directories..."
mkdir -p /opt/warops-panel/backend
mkdir -p /opt/warops-panel/frontend
cd /opt/warops-panel

# دانلود فایل‌ها (شما باید فایل‌ها رو آپلود کنید)
echo "📥 Please upload your files to /opt/warops-panel/"
echo ""

# نصب وابستگی‌های backend
cd /opt/warops-panel/backend
npm install express cors body-parser node-ssh bcrypt jsonwebtoken sqlite3

# تنظیم فایروال
echo "🛡️ Configuring firewall..."
ufw allow 3000/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# ساخت systemd service
cat > /etc/systemd/system/warops.service << EOF
[Unit]
Description=WarOps Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/warops-panel/backend
ExecStart=/usr/bin/node server.js
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# راه‌اندازی سرویس
systemctl daemon-reload
systemctl enable warops
systemctl start warops

echo ""
echo "✅ Installation completed!"
echo "🌐 Panel URL: http://YOUR_SERVER_IP:3000"
echo "👤 Default admin: admin / admin123"
echo ""
echo "⚠️ Please change default password immediately!"
