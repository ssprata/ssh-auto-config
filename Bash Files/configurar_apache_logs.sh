#!/bin/bash

# Simple Apache configuration script for line-by-line execution
echo "Starting Apache configuration..."

echo "1. Updating package lists..."
apt-get update -y

echo "2. Installing Apache2..."
apt-get install -y apache2

echo "3. Installing curl for testing..."
apt-get install -y curl

echo "4. Enabling Apache2 service..."
systemctl enable apache2

echo "5. Starting Apache2 service..."
systemctl start apache2

echo "6. Checking Apache2 status..."
systemctl status apache2 --no-pager

echo "7. Creating backup of Apache configuration..."
cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.bak

echo "8. Commenting out original log lines..."
sudo sed -i 's/^[[:space:]]*ErrorLog/#&/' /etc/apache2/sites-available/000-default.conf
sudo sed -i 's/^[[:space:]]*CustomLog/#&/' /etc/apache2/sites-available/000-default.conf

echo "9. Adding syslog configuration to Apache..."
sudo sed -i '/<VirtualHost \*:80>/a \    ErrorLog "syslog:local1"' /etc/apache2/sites-available/000-default.conf
sudo sed -i '/ErrorLog "syslog:local1"/a \    CustomLog "syslog:local2" combined' /etc/apache2/sites-available/000-default.conf

echo "10. Creating rsyslog configuration for Apache..."
sudo mkdir -p /etc/rsyslog.d
echo "local1.* @$IP_SERVIDOR:514" > /tmp/apache-rsyslog.conf
echo "local2.* @$IP_SERVIDOR:514" >> /tmp/apache-rsyslog.conf
sudo mv /tmp/apache-rsyslog.conf /etc/rsyslog.d/20-apache.conf

echo "11. Restarting Apache2..."
systemctl restart apache2

echo "12. Restarting rsyslog..."
systemctl restart rsyslog

echo "13. Testing Apache response..."
curl -I http://localhost

echo "✅ Apache configuration complete. Logs are being sent to $IP_SERVIDOR"
