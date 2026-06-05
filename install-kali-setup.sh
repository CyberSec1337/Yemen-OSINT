#!/bin/bash

# =============================================================================
# Kali Linux Security Dashboard Installation Script
# =============================================================================
# This script automates the installation of the Security Dashboard on Kali Linux
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="$HOME/security-dashboard-install.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root!"
        exit 1
    fi
}

# Check if Kali Linux
check_kali() {
    if ! grep -q "Kali" /etc/os-release; then
        print_warning "This script is optimized for Kali Linux"
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# System update
update_system() {
    print_status "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    sudo apt dist-upgrade -y
    sudo apt autoremove -y
    sudo apt autoclean
    print_success "System updated successfully"
}

# Install essential tools
install_essentials() {
    print_status "Installing essential tools..."
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
        lsb-release \
        ufw \
        sqlite3 \
        libsqlite3-dev \
        pkg-config
    print_success "Essential tools installed"
}

# Install Node.js
install_nodejs() {
    print_status "Installing Node.js LTS..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    # Verify installation
    NODE_VERSION=$(node --version)
    NPM_VERSION=$(npm --version)
    print_success "Node.js $NODE_VERSION and npm $NPM_VERSION installed"
}

# Install Python
install_python() {
    print_status "Installing Python 3.11..."
    sudo apt install -y python3.11 python3.11-dev python3-pip python3-venv
    
    # Verify installation
    PYTHON_VERSION=$(python3.11 --version)
    print_success "$PYTHON_VERSION installed"
}

# Setup firewall
setup_firewall() {
    print_status "Configuring firewall..."
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow 3000/tcp
    sudo ufw --force enable
    print_success "Firewall configured"
}

# Create project directory
setup_project() {
    print_status "Setting up project directory..."
    mkdir -p "$HOME/security-dashboard"
    cd "$HOME/security-dashboard"
    
    # Create database directory
    mkdir -p db
    
    # Create initial database
    sqlite3 db/custom.db << EOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOF
    
    print_success "Project directory created"
}

# Install project dependencies
install_dependencies() {
    print_status "Installing project dependencies..."
    cd "$HOME/security-dashboard"
    
    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        print_warning "package.json not found. Creating minimal package.json..."
        cat > package.json << EOF
{
  "name": "security-dashboard",
  "version": "1.0.0",
  "description": "Security Dashboard for Kali Linux",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "^15.0.0",
    "react": "^18.0.0",
    "react-dom": "^18.0.0",
    "typescript": "^5.0.0",
    "@types/node": "^20.0.0",
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "tailwindcss": "^4.0.0",
    "prisma": "^5.0.0",
    "@prisma/client": "^5.0.0"
  },
  "devDependencies": {
    "eslint": "^8.0.0",
    "eslint-config-next": "^15.0.0"
  }
}
EOF
    fi
    
    # Install dependencies
    npm install
    
    # Install global packages
    sudo npm install -g prisma
    
    print_success "Dependencies installed"
}

# Create environment file
create_env() {
    print_status "Creating environment file..."
    cd "$HOME/security-dashboard"
    
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# Database
DATABASE_URL="file:./db/custom.db"

# Next.js
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="$(openssl rand -base64 32)"

# API Keys (replace with your actual keys)
ABSTRACT_API_KEY="your-abstract-api-key"
VIRUSTOTAL_API_KEY="your-virustotal-key"
SHODAN_API_KEY="your-shodan-key"
ALIENVAULT_API_KEY="your-alienvault-key"
ABUSEIPDB_API_KEY="your-abuseipdb-key"

# Application Settings
NODE_ENV="development"
PORT=3000
EOF
        
        chmod 600 .env
        print_success "Environment file created"
    else
        print_warning "Environment file already exists"
    fi
}

# Setup database
setup_database() {
    print_status "Setting up database..."
    cd "$HOME/security-dashboard"
    
    # Generate Prisma client
    npx prisma generate
    
    # Push database schema
    npx prisma db push
    
    print_success "Database setup completed"
}

# Create systemd service
create_service() {
    print_status "Creating systemd service..."
    
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
    
    sudo systemctl daemon-reload
    sudo systemctl enable security-dashboard
    
    print_success "Systemd service created"
}

# Create start/stop scripts
create_scripts() {
    print_status "Creating management scripts..."
    
    # Start script
    cat > "$HOME/security-dashboard/start.sh" << 'EOF'
#!/bin/bash
cd "$HOME/security-dashboard"
npm run dev
EOF
    
    # Stop script
    cat > "$HOME/security-dashboard/stop.sh" << 'EOF'
#!/bin/bash
sudo systemctl stop security-dashboard
EOF
    
    # Status script
    cat > "$HOME/security-dashboard/status.sh" << 'EOF'
#!/bin/bash
sudo systemctl status security-dashboard
EOF
    
    # Make scripts executable
    chmod +x "$HOME/security-dashboard/start.sh"
    chmod +x "$HOME/security-dashboard/stop.sh"
    chmod +x "$HOME/security-dashboard/status.sh"
    
    print_success "Management scripts created"
}

# Final checks
final_checks() {
    print_status "Performing final checks..."
    
    # Check if Node.js is installed
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_success "Node.js: $NODE_VERSION"
    else
        print_error "Node.js not found"
    fi
    
    # Check if npm is installed
    if command -v npm &> /dev/null; then
        NPM_VERSION=$(npm --version)
        print_success "npm: $NPM_VERSION"
    else
        print_error "npm not found"
    fi
    
    # Check if database exists
    if [ -f "$HOME/security-dashboard/db/custom.db" ]; then
        print_success "Database: custom.db exists"
    else
        print_error "Database not found"
    fi
    
    # Check firewall status
    if sudo ufw status | grep -q "Status: active"; then
        print_success "Firewall: Active"
    else
        print_warning "Firewall: Inactive"
    fi
}

# Print completion message
print_completion() {
    echo
    echo "=================================================================="
    print_success "Installation completed successfully!"
    echo "=================================================================="
    echo
    echo "Project Location: $HOME/security-dashboard"
    echo "Log File: $LOG_FILE"
    echo
    echo "To start the application:"
    echo "  cd ~/security-dashboard"
    echo "  ./start.sh"
    echo
    echo "Or start the service:"
    echo "  sudo systemctl start security-dashboard"
    echo
    echo "Access the application at: http://localhost:3000"
    echo
    echo "Next steps:"
    echo "1. Edit .env file and add your API keys"
    echo "2. Configure additional security settings"
    echo "3. Set up SSL certificates for production"
    echo
    echo "For troubleshooting, check: $LOG_FILE"
    echo "=================================================================="
}

# Main installation function
main() {
    echo "=================================================================="
    echo "🐧 Kali Linux Security Dashboard Installation Script"
    echo "=================================================================="
    echo
    
    check_root
    check_kali
    
    read -p "Do you want to proceed with the installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installation cancelled"
        exit 0
    fi
    
    update_system
    install_essentials
    install_nodejs
    install_python
    setup_firewall
    setup_project
    install_dependencies
    create_env
    setup_database
    create_service
    create_scripts
    final_checks
    print_completion
}

# Run main function
main "$@"