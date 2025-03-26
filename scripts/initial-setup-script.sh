#!/bin/bash
# Initial setup script for blog platform on Ubuntu

# Exit on error
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print colored message
print_message() {
  echo -e "${GREEN}[*] $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
  echo -e "${RED}[✗] $1${NC}"
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root. Try 'sudo ./setup.sh'"
    exit 1
fi

# Get username for the new sudo user
read -p "Enter the username for the new sudo user: " USERNAME

# Update system
print_message "Updating system packages..."
apt update && apt upgrade -y

# Install essential packages
print_message "Installing essential packages..."
apt install -y \
    curl \
    git \
    vim \
    htop \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    net-tools \
    ca-certificates \
    gnupg

# Configure automatic updates
print_message "Setting up automatic security updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Create a sudo user
print_message "Creating sudo user: $USERNAME..."
adduser --gecos "" $USERNAME
usermod -aG sudo $USERNAME

# Setup SSH directory for the new user
mkdir -p /home/$USERNAME/.ssh
chmod 700 /home/$USERNAME/.ssh

# Ask for SSH public key
read -p "Enter your SSH public key (or press enter to skip): " SSH_KEY

if [ ! -z "$SSH_KEY" ]; then
    echo "$SSH_KEY" > /home/$USERNAME/.ssh/authorized_keys
    chmod 600 /home/$USERNAME/.ssh/authorized_keys
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
    print_message "SSH key added to $USERNAME's authorized_keys"
else
    print_warning "No SSH key provided. You can add it later using ssh-copy-id."
fi

# Secure SSH
print_message "Securing SSH configuration..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Configure firewall
print_message "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

# Configure fail2ban
print_message "Setting up fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF

systemctl restart fail2ban

# Install Docker
print_message "Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group
usermod -aG docker $USERNAME

# Install Docker Compose
print_message "Installing Docker Compose..."
mkdir -p /usr/local/lib/docker/cli-plugins/
curl -SL https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
ln -s /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

# Create directory structure for blog project
print_message "Creating directory structure for blog project..."
mkdir -p /home/$USERNAME/blog/{frontend,api,nginx/{conf,ssl},backups}
chown -R $USERNAME:$USERNAME /home/$USERNAME/blog

# Restart SSH service to apply changes
print_message "Restarting SSH service..."
systemctl restart sshd

# Summary
print_message "Initial setup completed successfully!"
print_message "Summary:"
echo "- System updated and essential packages installed"
echo "- Automatic security updates configured"
echo "- New sudo user '$USERNAME' created"
echo "- SSH secured (root login disabled, password authentication disabled)"
echo "- Firewall configured (SSH, HTTP, HTTPS allowed)"
echo "- Fail2ban installed and configured"
echo "- Docker and Docker Compose installed"
echo "- Directory structure for blog project created at /home/$USERNAME/blog/"

print_warning "IMPORTANT: Before logging out, verify you can log in as the new user in a new session!"

# Provide next steps
echo ""
print_message "Next steps:"
echo "1. Log in as $USERNAME in a new session to verify access"
echo "2. Set up your domain name to point to this server's IP address"
echo "3. Create and upload your docker-compose.yml and related files"
echo "4. Build and deploy your blog application"
echo ""
echo "To connect to your server in the future:"
echo "ssh $USERNAME@your_server_ip"
