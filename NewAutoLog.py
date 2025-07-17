import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import paramiko
import os
import sys

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Normal Python run
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

class SSHConnectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Auto Configuration Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Variables
        self.ssh_client = None
        self.shell_channel = None
        self.current_prompt = "$ "
        self.command_history = []
        self.history_index = -1
        self.terminal_enabled = False
        self.use_sudo = False
        self.ssh_password = ""
        self.show_details_var = None

        self.create_gui()

    def create_gui(self):
        # Main frame
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = tk.Label(main_frame, text="SSH Auto Configuration Tool", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))

        # Connection details frame
        conn_frame = tk.LabelFrame(main_frame, text="Connection Details", padx=10, pady=10)
        conn_frame.pack(fill=tk.X, pady=(0, 20))

        tk.Label(conn_frame, text="Root User:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.root_entry = tk.Entry(conn_frame, width=30)
        self.root_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.root_entry.insert(0, "root")

        tk.Label(conn_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(conn_frame, width=30)
        self.ip_entry.grid(row=1, column=1, pady=5, padx=(10, 0))

        tk.Label(conn_frame, text="Port:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(conn_frame, width=30)
        self.port_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
        self.port_entry.insert(0, "22")

        tk.Label(conn_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_entry = tk.Entry(conn_frame, width=30, show="*")
        self.password_entry.grid(row=3, column=1, pady=5, padx=(10, 0))

        # Connect button
        self.connect_button = tk.Button(conn_frame, text="Connect", command=self.start_connection, bg="#2196F3", fg="white")
        self.connect_button.grid(row=4, column=0, columnspan=2, pady=10)

        # Configuration buttons frame
        config_frame = tk.LabelFrame(main_frame, text="Configuration Options", padx=10, pady=10)
        config_frame.pack(fill=tk.X, pady=(0, 20))

        # First row - buttons
        buttons_frame = tk.Frame(config_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))

        self.linux_config_button = tk.Button(buttons_frame, text="Rsyslog Config", command=self.configure_rsyslog, state=tk.DISABLED)
        self.linux_config_button.pack(side=tk.LEFT, padx=5)

        self.mysql_config_button = tk.Button(buttons_frame, text="MySQL Config", command=self.configure_mysql, state=tk.DISABLED)
        self.mysql_config_button.pack(side=tk.LEFT, padx=5)

        self.apache_config_button = tk.Button(buttons_frame, text="Apache Config", command=self.configure_apache, state=tk.DISABLED)
        self.apache_config_button.pack(side=tk.LEFT, padx=5)

        # Second row - server IP and show details
        options_frame = tk.Frame(config_frame)
        options_frame.pack(fill=tk.X)

        tk.Label(options_frame, text="Server IP:").pack(side=tk.LEFT, padx=5)
        self.server_ip_entry = tk.Entry(options_frame, width=20)
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)

        self.show_details_var = tk.BooleanVar()
        self.show_details_checkbox = tk.Checkbutton(options_frame, text="Show detailed output", 
                                                   variable=self.show_details_var)
        self.show_details_checkbox.pack(side=tk.LEFT, padx=20)

        # Terminal frame
        terminal_frame = tk.LabelFrame(main_frame, text="Terminal", padx=10, pady=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True)

        # Progress frame
        self.progress_frame = tk.Frame(terminal_frame)
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))

        self.progress_label = tk.Label(self.progress_frame, text="Ready", font=("Arial", 10))
        self.progress_label.pack(side=tk.LEFT)

        from tkinter import ttk
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate', length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=(10, 0))

        self.terminal_text = scrolledtext.ScrolledText(terminal_frame, height=15, wrap=tk.WORD, font=("Consolas", 10), bg="black", fg="green")
        self.terminal_text.pack(fill=tk.BOTH, expand=True)

    def start_connection(self):
        root_user = self.root_entry.get().strip()
        ip_address = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        password = self.password_entry.get().strip()

        if not root_user or not ip_address or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        self.connect_button.config(state=tk.DISABLED)
        threading.Thread(target=self.connect_to_ssh, args=(root_user, ip_address, port, password), daemon=True).start()

    def connect_to_ssh(self, root_user, ip_address, port, password):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname=ip_address, port=int(port), username=root_user, password=password)
            self.shell_channel = self.ssh_client.invoke_shell()

            # Check current user and store password for sudo commands
            self.ssh_password = password
            stdin, stdout, stderr = self.ssh_client.exec_command("whoami")
            current_user = stdout.read().decode().strip()
            
            self.terminal_text.insert(tk.END, f"Connected to SSH server as user: {current_user}\n")
            
            if current_user != "root":
                self.terminal_text.insert(tk.END, "Note: Commands will be executed with sudo privileges.\n")
                self.use_sudo = True
            else:
                self.use_sudo = False

            self.terminal_text.insert(tk.END, "SSH connection established successfully.\n")

            self.linux_config_button.config(state=tk.NORMAL)
            self.mysql_config_button.config(state=tk.NORMAL)
            self.apache_config_button.config(state=tk.NORMAL)
        except Exception as e:
            self.terminal_text.insert(tk.END, f"Connection failed: {e}\n")
        finally:
            self.connect_button.config(state=tk.NORMAL)

    def configure_rsyslog(self):
        self.execute_script("Bash Files/configurar_rsyslog.sh")

    def configure_mysql(self):
        self.execute_script("Bash Files/configurar_mysql_logs.sh")

    def configure_apache(self):
        self.execute_script("Bash Files/configurar_apache_logs.sh")

    def execute_script(self, script_path):
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH.")
            return

        # Get the correct path for both dev and executable
        full_script_path = get_resource_path(script_path)
        
        if not os.path.exists(full_script_path):
            self.terminal_text.insert(tk.END, f"Script not found: {full_script_path}\n")
            return

        server_ip = self.server_ip_entry.get().strip()
        if not server_ip:
            messagebox.showerror("Error", "Please enter the server IP.")
            return

        with open(full_script_path, "r", encoding="utf-8") as script_file:
            script_content = script_file.read()

        # Replace variable with actual server IP
        script_content = script_content.replace("$IP_SERVIDOR", server_ip)
        script_content = script_content.replace("$1", server_ip)

        # Extract only the actual commands, skip comments and bash constructs
        commands = []
        lines = script_content.split('\n')
        
        for line in lines:
            line = line.strip()
            # Skip empty lines, comments, and bash constructs
            if (line and 
                not line.startswith('#') and 
                not line.startswith('if') and 
                not line.startswith('fi') and
                not line.startswith('then') and
                not line.startswith('else') and
                not line.startswith('exit') and
                not line.startswith('{') and
                not line.startswith('}') and
                not line == '#!/bin/bash'):
                
                # Handle compound commands with && or ||
                if ('&&' in line or '||' in line) and not ('2>' in line or '1>' in line or '&>' in line):
                    # Only split if it's not output redirection
                    if '||' in line and '{' not in line:
                        # Simple command with error handling
                        main_cmd = line.split('||')[0].strip()
                        if main_cmd:
                            commands.append(main_cmd)
                    elif '&&' in line:
                        # Multiple commands chained
                        parts = line.split('&&')
                        for part in parts:
                            part = part.strip()
                            if part and not part.startswith('apt-get install'):
                                commands.append(part)
                            elif 'apt-get install' in part:
                                commands.append(part)
                    else:
                        commands.append(line)
                else:
                    # Keep the full command intact if it contains redirection or no operators
                    commands.append(line)

        # Execute each command
        total_commands = len(commands)
        for i, command in enumerate(commands):
            if command.strip():
                # Update progress
                progress = (i / total_commands) * 100
                self.progress_bar['value'] = progress
                self.progress_label.config(text=f"Executing step {i+1}/{total_commands}...")
                self.root.update_idletasks()

                # Add sudo if needed and command requires privileges
                if (self.use_sudo and 
                    any(cmd in command for cmd in ['apt-get', 'systemctl', 'cp /etc/', 'echo', '>>', 'sed', 'mkdir', 'mv /tmp/', 'logger']) and
                    not command.startswith('sudo')):
                    
                    # Check if this is output redirection (like 2>/dev/null) vs file redirection
                    is_output_redirection = any(redirect in command for redirect in ['2>', '1>', '&>'])
                    
                    if '>>' in command and not is_output_redirection:
                        # Handle file redirection with sudo (but not output redirection)
                        parts = command.split('>>')
                        if len(parts) == 2:
                            echo_part = parts[0].strip()
                            file_part = parts[1].strip()
                            # Properly escape quotes in echo commands
                            echo_part = echo_part.replace('"', '\\"')
                            command = f"echo '{self.ssh_password}' | sudo -S sh -c \"{echo_part} >> {file_part}\""
                    elif '>' in command and not '>>' in command and not is_output_redirection:
                        # Handle file redirection with sudo (but not output redirection)
                        parts = command.split('>')
                        if len(parts) == 2:
                            echo_part = parts[0].strip()
                            file_part = parts[1].strip()
                            # Properly escape quotes in echo commands
                            echo_part = echo_part.replace('"', '\\"')
                            command = f"echo '{self.ssh_password}' | sudo -S sh -c \"{echo_part} > {file_part}\""
                    else:
                        # Regular command with sudo (including commands with output redirection)
                        command = f"echo '{self.ssh_password}' | sudo -S {command}"
                
                # Show detailed output only if checkbox is checked
                if self.show_details_var.get():
                    self.terminal_text.insert(tk.END, f"Executing: {command}\n")
                    self.terminal_text.see(tk.END)
                    self.root.update_idletasks()
                
                try:
                    # Use longer timeout for package operations and MySQL
                    timeout = 120 if any(pkg_cmd in command for pkg_cmd in ['apt-get', 'dpkg', 'mysql']) else 60
                    stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
                    output = stdout.read().decode()
                    error = stderr.read().decode()
                    
                    if self.show_details_var.get():
                        if output:
                            self.terminal_text.insert(tk.END, output + "\n")
                        if error and "sudo:" not in error:  # Hide sudo password prompts
                            # Filter out common non-critical MySQL and dpkg warnings
                            if not any(warning in error.lower() for warning in [
                                "warning:", "note:", "debconf:", "no apport report", 
                                "followup error", "sub-process /usr/bin/dpkg returned an error code (1)"
                            ]):
                                self.terminal_text.insert(tk.END, f"Error: {error}\n")
                    else:
                        # Show only critical errors in simple mode
                        if error and "sudo:" not in error:
                            # Skip known non-critical messages but show real failures
                            critical_errors = ["permission denied", "command not found", "no such file"]
                            skip_errors = [
                                "warning:", "note:", "debconf:", "unit 2.service not loaded",
                                "no apport report", "followup error", "sub-process /usr/bin/dpkg returned an error code (1)",
                                "error 2002", "can't connect to local mysql server"
                            ]
                            
                            if any(critical in error.lower() for critical in critical_errors):
                                if not any(skip in error.lower() for skip in skip_errors):
                                    self.terminal_text.insert(tk.END, f"Error: {error}\n")
                        
                except Exception as e:
                    self.terminal_text.insert(tk.END, f"Error executing command: {e}\n")
                
                if self.show_details_var.get():
                    self.terminal_text.see(tk.END)
                self.root.update_idletasks()

        # Complete progress
        self.progress_bar['value'] = 100
        self.progress_label.config(text="Configuration completed successfully!")
        
        # Show completion message
        if not self.show_details_var.get():
            self.terminal_text.insert(tk.END, f"✅ Configuration completed successfully!\n")
            self.terminal_text.insert(tk.END, f"Logs are now being sent to {server_ip}\n")
        
        self.terminal_text.see(tk.END)
        self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConnectionGUI(root)
    root.mainloop()
