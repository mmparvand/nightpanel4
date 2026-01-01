# WarOps Panel - Installation & Admin Panel

پنل مدیریت و نصب خودکار Template های سرور

## 📋 نیازمندی‌ها

- Ubuntu 20.04+ یا Debian 11+
- دسترسی Root
- حداقل 2GB RAM
- Node.js 18+

## 🚀 نصب سریع

```bash
# دانلود اسکریپت نصب
wget https://your-domain.com/install.sh

# اجرای نصب
sudo bash install.sh

📦 نصب دستی
1. نصب Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

2. ساخت دایرکتوری و کپی فایل‌ها
sudo mkdir -p /opt/warops-panel/backend
sudo mkdir -p /opt/warops-panel/frontend

# کپی فایل‌های backend
sudo cp backend/* /opt/warops-panel/backend/

# کپی فایل‌های frontend
sudo cp frontend/* /opt/warops-panel/frontend/

3. نصب وابستگی‌ها
cd /opt/warops-panel/backend
sudo npm install

4. راه‌اندازی سرویس
# ساخت systemd service
sudo nano /etc/systemd/system/warops.service

محتوای فایل:

[Unit]
Description=WarOps Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/warops-panel/backend
ExecStart=/usr/bin/node server.js
Restart=always
Environment=PORT=3000
Environment=JWT_SECRET=change-this-secret-key

[Install]
WantedBy=multi-user.target

فعال‌سازی:

sudo systemctl daemon-reload
sudo systemctl enable warops
sudo systemctl start warops

5. تنظیم Firewall
sudo ufw allow 3000/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

🌐 دسترسی به پنل
پنل نصب: http://YOUR_SERVER_IP:3000
پنل مدیریت: http://YOUR_SERVER_IP:3000/admin.html
اطلاعات ورود پیش‌فرض:

Username: admin
Password: admin123
⚠️ مهم: بلافاصله پس از اولین ورود، رمز عبور را تغییر دهید!

🔧 پیکربندی
تنظیمات محیطی (Environment Variables)
# ویرایش فایل سرویس
sudo nano /etc/systemd/system/warops.service

تنظیمات قابل تغییر:

PORT: پورت سرور (پیش‌فرض: 3000)
JWT_SECRET: کلید رمزنگاری JWT (حتما تغییر دهید!)
تنظیمات Nginx (اختیاری - برای HTTPS)
sudo nano /etc/nginx/sites-available/warops

server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

فعال‌سازی:

sudo ln -s /etc/nginx/sites-available/warops /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

📊 مدیریت سرویس
# مشاهده وضعیت
sudo systemctl status warops

# راه‌اندازی مجدد
sudo systemctl restart warops

# توقف سرویس
sudo systemctl stop warops

# مشاهده لاگ‌ها
sudo journalctl -u warops -f

🔐 امنیت
تغییر رمز عبور پیش‌فرض
بلافاصله پس از نصب وارد پنل مدیریت شوید
از بخش تنظیمات رمز عبور را تغییر دهید
تغییر JWT Secret
sudo nano /etc/systemd/system/warops.service
# تغییر مقدار JWT_SECRET
sudo systemctl daemon-reload
sudo systemctl restart warops
محدود کردن دسترسی
# فقط اجازه دسترسی از IP خاص
sudo ufw allow from YOUR_IP to any port 3000
🛠️ عیب‌یابی
سرویس راه‌اندازی نمی‌شود
# بررسی لاگ‌ها
sudo journalctl -u warops -n 50

# بررسی پورت
sudo netstat -tulpn | grep 3000

# بررسی وابستگی‌ها
cd /opt/warops-panel/backend
npm install

خطای اتصال به دیتابیس
# بررسی وجود فایل دیتابیس
ls -la /opt/warops-panel/backend/warops.db

# دادن مجوز
sudo chown root:root /opt/warops-panel/backend/warops.db
sudo chmod 644 /opt/warops-panel/backend/warops.db

خطای SSH در نصب Template
مطمئن شوید کلید SSH یا رمز عبور صحیح است
پورت 22 روی سرور هدف باز باشد
از IP سرور پنل به سرور هدف دسترسی SSH وجود داشته باشد
📝 Template های پشتیبانی شده
🐳 Docker Engine
🌐 Nginx Web Server
🎛️ X-UI Panel
🚀 V2Ray Core
💎 Marzban Panel
⚡ Hysteria 2
🔷 3X-UI Panel
🕳️ Rathole Tunnel
🔄 بروزرسانی
cd /opt/warops-panel
sudo systemctl stop warops

# دانلود نسخه جدید
# کپی فایل‌های جدید

cd /opt/warops-panel/backend
sudo npm install

sudo systemctl start warops

📞 پشتیبانی
Website: https://warops.io
Email: support@warops.io
Telegram: @warops_support
📄 لایسنس
MIT License - Copyright (c) 2024 WarOps

ساخته شده با ❤️ برای جامعه DevOps ایران
