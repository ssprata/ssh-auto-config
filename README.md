# SSH Auto Configuration Tool

A powerful GUI application for automatically configuring Linux servers for centralized logging via SSH.

## Features

- **🔐 SSH Connection**: Connect to remote Linux servers with SSH
- **📋 Auto Configuration**: Configure rsyslog, Apache, and MySQL with one click
- **📊 Real-time Output**: View command execution in real-time terminal
- **🛡️ Privilege Management**: Automatic sudo detection and handling
- **📁 Script-based**: Uses customizable bash scripts for configurations
- **🖥️ User-friendly GUI**: Intuitive interface with progress indicators

## What It Configures

### 1. **rsyslog Configuration**
- Installs and configures rsyslog service
- Sets up remote log forwarding to your log server

### 2. **Apache Configuration** 
- Installs Apache2 web server
- Configures error and access logs to forward via syslog
- Tests Apache functionality

### 3. **MySQL Configuration**
- Installs MySQL server
- Configures error, general, and slow query logs
- Sets up rsyslog monitoring for MySQL logs

## Download

### 🚀 Ready-to-Use Executable (Windows)
Download the latest version:
- **[NewAutoLog.exe](https://github.com/ssprata/ssh-auto-config/releases/tag/v1.0.0)** (Windows 64-bit)

*No Python installation required! Just download and run.*

### 📋 Requirements for Executable
- Windows 7/8/10/11 (64-bit)
- Network access to target Linux servers
- SSH credentials for target servers

## Usage

1. **Launch the application** (NewAutoLog.exe)
2. **Enter connection details**:
   - Root User (default: root)
   - IP Address of target server
   - SSH Port (default: 22)
   - Password
3. **Enter your log server IP** in the "Server IP" field
4. **Connect** to the target server
5. **Click configuration buttons**:
   - "Configure rsyslog" - Basic system logging
   - "Configure MySQL" - Database logging  
   - "Configure Apache" - Web server logging
6. **Monitor progress** in the terminal output area

## Configuration Scripts

The application uses three bash scripts located in `Bash Files/`:

- `configurar_rsyslog.sh` - System logging configuration
- `configurar_apache_logs.sh` - Apache web server logging
- `configurar_mysql_logs.sh` - MySQL database logging

These scripts can be customized for different requirements.

## Development

### Running from Source
```bash
# Clone the repository
git clone https://github.com/ssprata/ssh-auto-config.git
cd ssh-auto-config

# Install dependencies
pip install paramiko

# Run the application
python NewAutoLog.py
```

### Building Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed --add-data "Bash Files;Bash Files" NewAutoLog.py
```

## Technical Details

- **Language**: Python 3.x
- **GUI Framework**: Tkinter
- **SSH Library**: Paramiko
- **Packaging**: PyInstaller
- **Platform**: Windows (executable)

## Screenshots

### Main Interface
<img width="332" height="304" alt="image" src="https://github.com/user-attachments/assets/88f09c89-72f1-4268-8d48-42e6ee8e6960" />


### Configuration in Progress
<img width="324" height="166" alt="image" src="https://github.com/user-attachments/assets/33642d29-0745-4502-abbf-f055925355ad" /> <img width="324" height="166" alt="image" src="https://github.com/user-attachments/assets/42ccd5cc-a6b8-41e5-8ee9-8465bd9ac195" />



## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

If you encounter any issues or have questions:
- 🐛 [Report bugs](https://github.com/ssprata/ssh-auto-config/issues)
- 💡 [Request features](https://github.com/ssprata/ssh-auto-config/issues)

## Changelog

### v1.5.0
- MySql Errors Fix

### v1.0.0
- Initial release
- SSH connection management
- rsyslog, Apache, and MySQL configuration
- Windows executable distribution
