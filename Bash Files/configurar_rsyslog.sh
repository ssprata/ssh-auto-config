#!/bin/bash

# Simple rsyslog configuration script for line-by-line execution
echo "Starting rsyslog configuration..."

echo "1. Updating package lists..."
apt-get update -y

echo "2. Installing rsyslog..."
apt-get install -y rsyslog

echo "3. Enabling rsyslog service..."
systemctl enable rsyslog

echo "4. Starting rsyslog service..."
systemctl start rsyslog

echo "5. Checking rsyslog status..."
systemctl status rsyslog --no-pager

echo "6. Creating backup of rsyslog configuration..."
cp /etc/rsyslog.conf /etc/rsyslog.conf.bak

echo "7. Adding remote log server configuration..."
echo "" >> /etc/rsyslog.conf
echo "# Remote log server configuration" >> /etc/rsyslog.conf
echo "*.* @$IP_SERVIDOR" >> /etc/rsyslog.conf

echo "8. Restarting rsyslog service..."
systemctl restart rsyslog

echo "9. Verifying rsyslog is running..."
systemctl status rsyslog --no-pager

echo "✅ Configuration complete. Logs are being sent to $IP_SERVIDOR"