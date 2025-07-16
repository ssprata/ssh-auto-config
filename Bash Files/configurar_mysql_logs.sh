#!/bin/bash

# Simple MySQL configuration script for line-by-line execution
echo "Starting MySQL configuration..."

echo "1. Stopping MySQL service if running..."
systemctl stop mysql 2>/dev/null || true

echo "2. Removing broken MySQL installation..."
apt-get remove --purge -y mysql-server mysql-server-8.0 mysql-client-8.0

echo "3. Cleaning up MySQL data and config..."
sudo rm -rf /var/lib/mysql
sudo rm -rf /etc/mysql
sudo rm -rf /var/log/mysql

echo "4. Updating package lists..."
apt-get update -y

echo "5. Installing MySQL server fresh..."
DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server

echo "5.1. Fixing broken MySQL installation if needed..."
apt-get --fix-broken install -y

echo "6. Creating MySQL log directory..."
sudo mkdir -p /var/log/mysql
sudo chown mysql:mysql /var/log/mysql

echo "7. Creating MySQL configuration directory..."
sudo mkdir -p /etc/mysql/mysql.conf.d
sudo mkdir -p /etc/mysql/conf.d

echo "7.1. Creating basic MySQL configuration..."
echo "[mysqld_safe]" | sudo tee /etc/mysql/conf.d/basic.cnf
echo "socket = /var/run/mysqld/mysqld.sock" | sudo tee -a /etc/mysql/conf.d/basic.cnf
echo "nice = 0" | sudo tee -a /etc/mysql/conf.d/basic.cnf

echo "8. Initializing MySQL database..."
sudo mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql

echo "9. Creating proper MySQL configuration..."
echo "[mysqld]" > /tmp/mysql-syslog.conf
echo "bind-address = 127.0.0.1" >> /tmp/mysql-syslog.conf
echo "port = 3306" >> /tmp/mysql-syslog.conf
echo "datadir = /var/lib/mysql" >> /tmp/mysql-syslog.conf
echo "socket = /var/run/mysqld/mysqld.sock" >> /tmp/mysql-syslog.conf
echo "pid-file = /var/run/mysqld/mysqld.pid" >> /tmp/mysql-syslog.conf
echo "log-error = /var/log/mysql/error.log" >> /tmp/mysql-syslog.conf
echo "general_log = 1" >> /tmp/mysql-syslog.conf
echo "general_log_file = /var/log/mysql/mysql.log" >> /tmp/mysql-syslog.conf
echo "slow_query_log = 1" >> /tmp/mysql-syslog.conf
echo "slow_query_log_file = /var/log/mysql/mysql-slow.log" >> /tmp/mysql-syslog.conf
sudo mv /tmp/mysql-syslog.conf /etc/mysql/mysql.conf.d/mysqld.cnf

echo "10. Starting MySQL service..."
sudo systemctl daemon-reload
sudo systemctl start mysql

echo "11. Waiting for MySQL to start..."
sleep 5

echo "12. Enabling MySQL service..."
sudo systemctl enable mysql

echo "13. Checking MySQL status..."
sudo systemctl status mysql --no-pager

echo "14. Adding MySQL logs to rsyslog..."
echo "# MySQL logs forwarding" > /tmp/mysql-rsyslog.conf
echo "\$ModLoad imfile" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileName /var/log/mysql/error.log" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileTag mysql-error:" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileStateFile mysql-error-state" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileSeverity info" >> /tmp/mysql-rsyslog.conf
echo "\$InputRunFileMonitor" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileName /var/log/mysql/mysql.log" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileTag mysql-general:" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileStateFile mysql-general-state" >> /tmp/mysql-rsyslog.conf
echo "\$InputFileSeverity info" >> /tmp/mysql-rsyslog.conf
echo "\$InputRunFileMonitor" >> /tmp/mysql-rsyslog.conf
echo "mysql-error:* @$IP_SERVIDOR:514" >> /tmp/mysql-rsyslog.conf
echo "mysql-general:* @$IP_SERVIDOR:514" >> /tmp/mysql-rsyslog.conf
sudo mv /tmp/mysql-rsyslog.conf /etc/rsyslog.d/21-mysql.conf

echo "15. Restarting rsyslog service..."
sudo systemctl restart rsyslog

echo "16. Testing MySQL connection..."
mysql -e "SELECT 'MySQL is working!' as status;" 2>/dev/null || echo "MySQL needs manual setup"

echo "17. Testing MySQL log..."
logger -t mysql "MySQL configuration test log"

echo "✅ MySQL configuration complete. Logs are being sent to $IP_SERVIDOR"
