# 🐧 Kali Linux Security Dashboard Setup

## 🚀 Quick Start Installation

### Prerequisites
- Kali Linux (2023.4 or later)
- Internet connection
- 4GB+ RAM (8GB recommended)
- 50GB+ free storage

### One-Click Installation

1. **Download and run the installation script:**
```bash
# Make the script executable
chmod +x install-kali-setup.sh

# Run the installation
./install-kali-setup.sh
```

2. **Follow the on-screen prompts**
3. **Access your dashboard at:** `http://localhost:3000`

---

## 📋 Manual Installation Steps

If you prefer manual installation, follow these steps:

### 1. System Update
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Dependencies
```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs

# Install Python and other tools
sudo apt install -y python3.11 python3.11-dev sqlite3 git ufw
```

### 3. Setup Project
```bash
# Clone or create project directory
mkdir -p ~/security-dashboard
cd ~/security-dashboard

# Install dependencies
npm install

# Setup database
npx prisma db push
```

### 4. Configure Environment
```bash
# Create .env file
cp .env.example .env
# Edit .env with your API keys
```

### 5. Start Application
```bash
npm run dev
```

---

## 🔧 Post-Installation Configuration

### 1. API Keys Configuration
Edit the `.env` file and add your API keys:
```bash
nano ~/security-dashboard/.env
```

Required API keys:
- Abstract API
- VirusTotal
- Shodan
- AlienVault OTX
- AbuseIPDB

### 2. Firewall Configuration
```bash
# Check firewall status
sudo ufw status

# Allow additional ports if needed
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### 3. Service Management
```bash
# Start the service
sudo systemctl start security-dashboard

# Enable auto-start on boot
sudo systemctl enable security-dashboard

# Check service status
sudo systemctl status security-dashboard
```

---

## 🌐 Accessing the Dashboard

### Local Access
- **URL:** `http://localhost:3000`
- **Default credentials:** Create during first run

### Network Access
To access from other devices on your network:
```bash
# Find your IP address
ip addr show

# Access from other devices: http://YOUR_IP:3000
```

---

## 🔍 Security Features

The Security Dashboard includes:

### 🛡️ Core Security Tools
- **Threat Intelligence Integration**
- **Vulnerability Scanning**
- **Network Analysis**
- **OSINT Capabilities**
- **Custom API Management**

### 📊 Monitoring & Analytics
- **Real-time Threat Detection**
- **Security Score Assessment**
- **Historical Data Analysis**
- **Custom Reports Generation**

### 🔧 Advanced Features
- **API Endpoint Management**
- **Automated Scanning**
- **Threat Level Classification**
- **Geographic Threat Mapping**

---

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port 3000
sudo lsof -i :3000

# Kill the process
sudo kill -9 <PID>

# Or use different port
PORT=3001 npm run dev
```

#### Database Issues
```bash
# Reset database
rm ~/security-dashboard/db/custom.db
npx prisma db push
```

#### Permission Issues
```bash
# Fix permissions
sudo chown -R $USER:$USER ~/security-dashboard
chmod -R 755 ~/security-dashboard
```

### Log Files
- **Application logs:** `~/security-dashboard/dev.log`
- **System logs:** `sudo journalctl -u security-dashboard`
- **Installation logs:** `~/security-dashboard-install.log`

---

## 📚 Documentation

- [Full Installation Guide](./KALI_LINUX_INSTALLATION.md)
- [API Documentation](./ABSTRACTAPI_INTEGRATION.md)
- [Project README](./README.md)

---

## 🛠️ Advanced Configuration

### SSL/TLS Setup
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com
```

### Reverse Proxy (Nginx)
```bash
# Install Nginx
sudo apt install nginx

# Configure reverse proxy
sudo nano /etc/nginx/sites-available/security-dashboard
```

### Database Backup
```bash
# Create backup script
cat > ~/backup-dashboard.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
cp ~/security-dashboard/db/custom.db ~/backups/security-dashboard_$DATE.db
EOF

chmod +x ~/backup-dashboard.sh
```

---

## 🔒 Security Best Practices

1. **Regular Updates**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Strong Passwords**
   - Use unique, strong passwords
   - Enable two-factor authentication where possible

3. **Network Security**
   - Keep firewall enabled
   - Use VPN for remote access
   - Monitor network traffic

4. **Application Security**
   - Regularly update dependencies
   - Monitor application logs
   - Implement rate limiting

---

## 📞 Support

### Getting Help
1. Check the troubleshooting section
2. Review log files for errors
3. Consult the full documentation
4. Join our community forums

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 🎯 Next Steps

After installation:

1. **Configure API Keys** - Add your security API keys
2. **Run First Scan** - Test the vulnerability scanning features
3. **Explore Features** - Familiarize yourself with all tools
4. **Setup Monitoring** - Configure alerts and notifications
5. **Regular Maintenance** - Schedule updates and backups

---

**🐧 Happy Hacking with Kali Linux! 🔒**

*This Security Dashboard transforms your Kali Linux system into a comprehensive security monitoring platform.*