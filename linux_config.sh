#!/bin/bash
# Linux Auto Configuration Script
echo "Starting Linux auto-configuration..."

# Update system
echo "Updating package lists..."
apt update -y || yum update -y

# Install common tools
echo "Installing common tools..."
apt install -y htop curl wget git || yum install -y htop curl wget git

# Configure timezone
echo "Configuring timezone..."
timedatectl set-timezone UTC

# Show system info
echo "System information:"
uname -a
cat /etc/os-release

echo "Linux auto-configuration completed!"
