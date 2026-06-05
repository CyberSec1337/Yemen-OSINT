# 🐧 Kali Linux Installation Guide
## Security Dashboard Project Setup

This guide provides step-by-step instructions for setting up the Security Dashboard project on Kali Linux.

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Kali Linux Installation](#kali-linux-installation)
3. [System Preparation](#system-preparation)
4. [Project Dependencies](#project-dependencies)
5. [Database Setup](#database-setup)
6. [Project Configuration](#project-configuration)
7. [Running the Application](#running-the-application)
8. [Troubleshooting](#troubleshooting)

---

## 🔧 System Requirements

### Minimum Requirements
- **RAM**: 4GB (8GB recommended)
- **Storage**: 50GB free space
- **Processor**: 64-bit CPU (Intel/AMD)
- **Network**: Internet connection for dependencies

### Recommended Requirements
- **RAM**: 16GB or more
- **Storage**: 100GB+ SSD
- **Processor**: Multi-core CPU
- **Graphics**: Dedicated GPU (for advanced visualizations)

---

## 🐾 Kali Linux Installation

### Option 1: Virtual Machine Installation

#### 1. Download Kali Linux
```bash
# Download Kali Linux ISO
wget https://cdimage.kali.org/kali-2023.4/kali-linux-2023.4-installer-amd64.iso
```

#### 2. Create Virtual Machine (VirtualBox)
```bash
# Install VirtualBox
sudo apt update
sudo apt install virtualbox

# Create VM with recommended settings:
# - Memory: 8GB
# - Storage: 80GB
# - Network: Bridged Adapter
```

#### 3. Install Kali Linux
1. Boot from ISO in VirtualBox
2. Select "Graphical Install"
3. Follow installation wizard:
   - Language: English
   - Location: Your country
   - Keyboard: American English
   - Network: Configure automatically
   - Hostname: kali-security
   - Domain: local
   - User: Create security user account
   - Password: Set strong password
   - Partition: Use entire disk
   - Software: Check "Kali Linux" and "SSH server"

### Option 2: Bare Metal Installation

#### 1. Create Bootable USB
```bash
# Insert USB drive (minimum 8GB)
sudo fdisk -l  # Identify USB device

# Create bootable USB
sudo dd if=kali-linux-2023.4-installer-amd64.iso of=/dev/sdX bs=4M status=progress
sync
```

#### 2. Boot from USB
1. Restart computer
2. Enter BIOS/UEFI (usually F2, F12, or Del)
3. Set USB as first boot device
4. Save and exit

#### 3. Follow Installation Steps
Same as VM installation steps above

---

## 🛠️ System Preparation

### 1. Update System
```bash
# Update package lists
sudo apt update

# Upgrade system packages
sudo apt upgrade -y

# Install system updates
sudo apt dist-upgrade -y

# Clean up
sudo apt autoremove -y
sudo apt autoclean
```

### 2. Install Essential Tools
```bash
# Install development tools
sudo apt install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    tree \
    unzip \
    build-essential \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release
```

### 3. Configure Firewall
```bash
# Install UFW (Uncomplicated Firewall)
sudo apt install ufw

# Configure firewall rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 3000/tcp  # For Next.js application
sudo ufw enable

# Check firewall status
sudo ufw status
```

---

## 📦 Project Dependencies

### 1. Install Node.js (Latest LTS)
```bash
# Install Node.js 18.x LTS
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### 2. Install Python 3.11
```bash
# Install Python and development tools
sudo apt install -y python3.11 python3.11-dev python3-pip python3-venv

# Verify installation
python3.11 --version
pip3 --version
```

### 3. Install Additional Dependencies
```bash
# Install system libraries required for the project
sudo apt install -y \
    sqlite3 \
    libsqlite3-dev \
    pkg-config \
    libnss3-dev \
    libatk-bridge2.0-dev \
    libdrm2 \
    libxkbcommon-dev \
    libxcomposite-dev \
    libxdamage-dev \
    libxrandr-dev \
    libgbm-dev \
    libxss-dev \
    libasound2-dev
```

---

## 🗄️ Database Setup

### 1. Install SQLite
```bash
# SQLite is usually pre-installed, but ensure it's updated
sudo apt install sqlite3 libsqlite3-dev

# Verify installation
sqlite3 --version
```

### 2. Create Database Directory
```bash
# Create database directory
mkdir -p ~/security-dashboard/db
cd ~/security-dashboard/db

# Create initial database
sqlite3 security.db << EOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOF
```

---

## 🚀 Project Configuration

### 1. Clone or Create Project Directory
```bash
# Create project directory
mkdir -p ~/security-dashboard
cd ~/security-dashboard

# If cloning from repository (replace with actual repo)
# git clone https://github.com/your-repo/security-dashboard.git .
```

### 2. Install Node.js Dependencies
```bash
# Install project dependencies
npm install

# Install global packages if needed
sudo npm install -g prisma
```

### 3. Configure Environment Variables
```bash
# Create environment file
cat > .env << EOF
# Database
DATABASE_URL="file:./db/custom.db"

# Next.js
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-secret-key-here"

# API Keys (add your actual keys)
ABSTRACT_API_KEY="your-abstract-api-key"
VIRUSTOTAL_API_KEY="your-virustotal-key"
SHODAN_API_KEY="your-shodan-key"
ALIENVAULT_API_KEY="your-alienvault-key"
ABUSEIPDB_API_KEY="your-abuseipdb-key"

# Application Settings
NODE_ENV="development"
PORT=3000
EOF

# Set proper permissions
chmod 600 .env
```

### 4. Setup Database Schema
```bash
# Initialize Prisma
npx prisma generate

# Push database schema
npx prisma db push

# (Optional) View database
npx prisma studio
```

---

## 🏃‍♂️ Running the Application

### 1. Development Mode
```bash
# Start development server
npm run dev

# The application will be available at:
# http://localhost:3000
```

### 2. Production Mode
```bash
# Build application
npm run build

# Start production server
npm start
```

### 3. Background Service (Systemd)
```bash
# Create systemd service file
sudo tee /etc/systemd/system/security-dashboard.service > /dev/null << EOF
[Unit]
Description=Security Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/security-dashboard
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable security-dashboard
sudo systemctl start security-dashboard

# Check status
sudo systemctl status security-dashboard
```

---

## 🔍 Security Configuration

### 1. SSL/TLS Setup (Optional)
```bash
# Install Certbot for SSL certificates
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate (replace with your domain)
sudo certbot --nginx -d your-domain.com
```

### 2. Reverse Proxy (Nginx)
```bash
# Install Nginx
sudo apt install nginx

# Create Nginx configuration
sudo tee /etc/nginx/sites-available/security-dashboard > /dev/null << EOF
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/security-dashboard /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. Port Already in Use
```bash
# Check what's using port 3000
sudo lsof -i :3000

# Kill the process
sudo kill -9 <PID>

# Or use different port
PORT=3001 npm run dev
```

#### 2. Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:$USER ~/security-dashboard
chmod -R 755 ~/security-dashboard
```

#### 3. Database Connection Issues
```bash
# Check database file permissions
ls -la ~/security-dashboard/db/

# Recreate database
rm ~/security-dashboard/db/custom.db
npx prisma db push
```

#### 4. Node.js Version Issues
```bash
# Check Node.js version
node --version

# Install correct version using nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18
```

#### 5. Memory Issues
```bash
# Check memory usage
free -h
htop

# Increase swap space if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Log Files Location
```bash
# Application logs
tail -f ~/security-dashboard/dev.log

# System logs
sudo journalctl -u security-dashboard -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

---

## 📚 Additional Resources

### Kali Linux Documentation
- [Official Kali Linux Documentation](https://www.kali.org/docs/)
- [Kali Tools Documentation](https://www.kali.org/tools-listing/)

### Project Documentation
- [Project README](./README.md)
- [API Documentation](./ABSTRACTAPI_INTEGRATION.md)

### Security Best Practices
- Regular system updates
- Strong password policies
- Firewall configuration
- Regular backups
- Monitor system logs

---

## 🎯 Next Steps

After successful installation:

1. **Configure API Keys**: Add your actual API keys to the `.env` file
2. **Setup Monitoring**: Configure system monitoring and alerting
3. **Backup Strategy**: Implement regular database backups
4. **Security Hardening**: Additional security configurations
5. **User Training**: Train users on the dashboard functionality

---

## 📞 Support

If you encounter issues during installation:

1. Check the troubleshooting section above
2. Review system logs for error messages
3. Ensure all dependencies are properly installed
4. Verify network connectivity for API calls

**Happy Hacking! 🐧🔒**