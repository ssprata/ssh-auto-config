#!/bin/bash

# Simple MySQL configuration script for line-by-line execution
echo "Starting MySQL configuration..."

echo "1. Stopping MySQL service if running..."
systemctl stop mysql 2>/dev/null || echo "MySQL service not running or already stopped"

echo "2. Fixing any broken package installations first..."
dpkg --configure -a 2>/dev/null || true
apt-get --fix-broken install -y 2>/dev/null || true

echo "3. Checking if MySQL is installed and working..."
if systemctl is-active --quiet mysql 2>/dev/null; then
    echo "MySQL is already running and working. Skipping installation."
    MYSQL_ALREADY_WORKING=true
else
    echo "MySQL not working properly. Proceeding with installation."
    MYSQL_ALREADY_WORKING=false
fi

if [ "$MYSQL_ALREADY_WORKING" = "false" ]; then
    echo "4. Stopping any MySQL processes..."
    pkill -f mysql 2>/dev/null || true
    sleep 3

    echo "5. Cleaning up MySQL data and config..."
    sudo rm -rf /var/lib/mysql 2>/dev/null || true
    sudo rm -rf /etc/mysql 2>/dev/null || true
    sudo rm -rf /var/log/mysql 2>/dev/null || true
    sudo rm -rf /var/run/mysqld 2>/dev/null || true

    echo "6. Completely removing MySQL packages..."
    apt-get remove --purge -y mysql-server mysql-server-8.0 mysql-client-8.0 mysql-common mysql-server-core-8.0 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    apt-get autoclean 2>/dev/null || true

    echo "7. Updating package lists..."
    apt-get update -y

    echo "8. Installing MySQL server fresh..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server

    echo "9. Fixing any installation issues..."
    apt-get --fix-broken install -y

    echo "9.1. Verifying MySQL installation..."
    if ! dpkg -l | grep -q mysql-server; then
        echo "MySQL installation failed. Trying alternative method..."
        apt-get update
        apt-get install -y mysql-server-8.0
    fi

    echo "9.2. Ensuring MySQL user exists..."
    if ! id mysql >/dev/null 2>&1; then
        echo "Creating mysql user..."
        sudo useradd -r -s /bin/false mysql 2>/dev/null || true
    fi
fi

echo "10. Creating MySQL directories and setting permissions..."
sudo mkdir -p /var/log/mysql
sudo mkdir -p /var/lib/mysql
sudo mkdir -p /var/run/mysqld
sudo mkdir -p /etc/mysql/mysql.conf.d
sudo mkdir -p /etc/mysql/conf.d

# Verify directories were created before setting permissions
if [ -d "/var/log/mysql" ]; then
    sudo chown mysql:mysql /var/log/mysql
    sudo chmod 755 /var/log/mysql
else
    echo "Warning: /var/log/mysql directory creation failed"
fi

if [ -d "/var/lib/mysql" ]; then
    sudo chown mysql:mysql /var/lib/mysql
    sudo chmod 755 /var/lib/mysql
else
    echo "Warning: /var/lib/mysql directory creation failed"
fi

if [ -d "/var/run/mysqld" ]; then
    sudo chown mysql:mysql /var/run/mysqld
    sudo chmod 755 /var/run/mysqld
else
    echo "Warning: /var/run/mysqld directory creation failed"
    echo "Attempting to create /var/run/mysqld with different method..."
    sudo install -d -o mysql -g mysql -m 755 /var/run/mysqld
fi

echo "11. Creating basic MySQL configuration..."
echo "[mysqld_safe]" | sudo tee /etc/mysql/conf.d/basic.cnf > /dev/null
echo "socket = /var/run/mysqld/mysqld.sock" | sudo tee -a /etc/mysql/conf.d/basic.cnf > /dev/null
echo "nice = 0" | sudo tee -a /etc/mysql/conf.d/basic.cnf > /dev/null

echo "12. Checking if MySQL database needs initialization..."
if [ "$MYSQL_ALREADY_WORKING" = "false" ] && [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "12a. Initializing MySQL database..."
    sudo mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql 2>/dev/null || echo "Database initialization completed with warnings"
else
    echo "12a. MySQL database already exists or was working, skipping initialization"
fi

echo "13. Creating proper MySQL configuration..."
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
echo "user = mysql" >> /tmp/mysql-syslog.conf
sudo mv /tmp/mysql-syslog.conf /etc/mysql/mysql.conf.d/mysqld.cnf

echo "14. Reloading systemd and starting MySQL service..."
sudo systemctl daemon-reload
sleep 3

echo "15. Starting MySQL service with retries..."
for i in {1..3}; do
    echo "15.$i. Attempt $i to start MySQL..."
    if sudo systemctl start mysql; then
        echo "MySQL started successfully on attempt $i"
        break
    else
        echo "MySQL start attempt $i failed. Waiting before retry..."
        sleep 10
        if [ $i -eq 3 ]; then
            echo "MySQL failed to start after 3 attempts. Checking logs..."
            sudo journalctl -u mysql --no-pager -n 20 || true
            echo "Trying alternative start method..."
            sudo mysqld_safe --user=mysql --datadir=/var/lib/mysql &
            sleep 10
        fi
    fi
done

echo "16. Waiting for MySQL to fully start..."
sleep 15

echo "17. Checking MySQL status..."
if systemctl is-active --quiet mysql; then
    echo "✅ MySQL is running successfully"
    sudo systemctl enable mysql
else
    echo "❌ MySQL failed to start properly"
    sudo systemctl status mysql --no-pager || true
fi

echo "18. Adding MySQL logs to rsyslog..."
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

echo "19. Restarting rsyslog service..."
sudo systemctl restart rsyslog

echo "20. Testing MySQL connection..."
for i in {1..5}; do
    if mysql -e "SELECT 'MySQL is working!' as status;" 2>/dev/null; then
        echo "✅ MySQL connection test successful"
        break
    else
        echo "MySQL connection test $i failed, retrying in 5 seconds..."
        sleep 5
        if [ $i -eq 5 ]; then
            echo "❌ MySQL connection failed after 5 attempts"
            echo "Socket status:"
            ls -la /var/run/mysqld/ 2>/dev/null || echo "Socket directory not found"
        fi
    fi
done

echo "21. Testing MySQL log..."
logger -t mysql "MySQL configuration test log"

if systemctl is-active --quiet mysql; then
    echo "✅ MySQL configuration complete. Logs are being sent to $IP_SERVIDOR"
else
    echo "⚠️  MySQL configuration completed but service may need manual attention"
fi
