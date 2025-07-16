import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import paramiko
import time
import os

class SSHConnectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Auto Configuration Tool")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Variables
        self.ssh_client = None
        self.shell_channel = None
        self.current_prompt = "$ "
        self.command_history = []
        self.history_index = -1
        self.current_command = ""
        self.current_line_start = "1.0"
        self.terminal_enabled = False
        
        self.create_gui()
    
    def create_gui(self):
        # Main frame
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text="SSH Auto Configuration Tool", 
                              font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Connection details frame
        conn_frame = tk.LabelFrame(main_frame, text="Connection Details", padx=10, pady=10)
        conn_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Root user entry
        tk.Label(conn_frame, text="Root User:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.root_entry = tk.Entry(conn_frame, width=30)
        self.root_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.root_entry.insert(0, "root")  # Default value
        
        # IP address entry
        tk.Label(conn_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(conn_frame, width=30)
        self.ip_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        # Port entry (optional)
        tk.Label(conn_frame, text="Port (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(conn_frame, width=30)
        self.port_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
        self.port_entry.insert(0, "22")  # Default SSH port
        
        # Password entry
        tk.Label(conn_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_entry = tk.Entry(conn_frame, width=30, show="*")
        self.password_entry.grid(row=3, column=1, pady=5, padx=(10, 0))
        
        # Connection button frame
        conn_button_frame = tk.Frame(main_frame)
        conn_button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Connect button
        self.connect_button = tk.Button(conn_button_frame, text="Connect to SSH", 
                                      command=self.start_connection, bg="#2196F3", 
                                      fg="white", font=("Arial", 12, "bold"))
        self.connect_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        clear_button = tk.Button(conn_button_frame, text="Clear", 
                               command=self.clear_fields, bg="#f44336", 
                               fg="white", font=("Arial", 12))
        clear_button.pack(side=tk.LEFT)
        
        # Configuration buttons frame
        config_frame = tk.LabelFrame(main_frame, text="Configuration Options", padx=10, pady=10)
        config_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Status label for connection
        self.connection_status = tk.Label(config_frame, text="Not connected", 
                                        fg="red", font=("Arial", 10, "bold"))
        self.connection_status.pack(pady=(0, 10))
        
        # Configuration buttons
        config_buttons_frame = tk.Frame(config_frame)
        config_buttons_frame.pack(fill=tk.X)
        
        # First row of buttons
        first_row = tk.Frame(config_buttons_frame)
        first_row.pack(fill=tk.X, pady=(0, 5))
        
        # Linux config button
        self.linux_config_button = tk.Button(first_row, text="Linux Config", 
                                            command=self.configure_linux_system, 
                                            bg="#4CAF50", fg="white", 
                                            font=("Arial", 11, "bold"), state=tk.DISABLED)
        self.linux_config_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # MySQL config button
        self.mysql_config_button = tk.Button(first_row, text="MySQL Config", 
                                            command=self.configure_mysql_system, 
                                            bg="#FF9800", fg="white", 
                                            font=("Arial", 11, "bold"), state=tk.DISABLED)
        self.mysql_config_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Second row of buttons
        second_row = tk.Frame(config_buttons_frame)
        second_row.pack(fill=tk.X)
        
        # Apache config button
        self.apache_config_button = tk.Button(second_row, text="Apache Config", 
                                             command=self.configure_apache_system, 
                                             bg="#9C27B0", fg="white", 
                                             font=("Arial", 11, "bold"), state=tk.DISABLED)
        self.apache_config_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Rsyslog config button
        self.rsyslog_config_button = tk.Button(second_row, text="Rsyslog Config", 
                                              command=self.configure_rsyslog_system, 
                                              bg="#607D8B", fg="white", 
                                              font=("Arial", 11, "bold"), state=tk.DISABLED)
        self.rsyslog_config_button.pack(side=tk.LEFT)
        
        # Server IP for logs frame (for Apache and Rsyslog configs)
        log_server_frame = tk.Frame(config_frame)
        log_server_frame.pack(fill=tk.X, pady=(10, 0))
        
        tk.Label(log_server_frame, text="Log Server IP (for Apache/Rsyslog):").pack(side=tk.LEFT)
        self.log_server_ip = tk.Entry(log_server_frame, width=20)
        self.log_server_ip.pack(side=tk.LEFT, padx=(10, 0))
        
        # Create notebook for tabbed interface
        from tkinter import ttk
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Output Log Tab (for errors and warnings)
        log_frame = tk.Frame(notebook)
        notebook.add(log_frame, text="Output Log")
        
        # Output log text area
        self.output_text = scrolledtext.ScrolledText(log_frame, height=12, 
                                                   wrap=tk.WORD, font=("Consolas", 10),
                                                   bg="white", fg="black")
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Terminal Tab (interactive terminal)
        terminal_frame = tk.Frame(notebook)
        notebook.add(terminal_frame, text="Interactive Terminal")
        
        # Terminal toolbar
        toolbar_frame = tk.Frame(terminal_frame)
        toolbar_frame.pack(fill=tk.X, pady=(10, 5), padx=10)
        
        # Special key buttons
        tk.Button(toolbar_frame, text="Ctrl+C", command=lambda: self.send_special_key('ctrl_c'), 
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(toolbar_frame, text="Ctrl+Z", command=lambda: self.send_special_key('ctrl_z'), 
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(toolbar_frame, text="Clear Terminal", command=self.clear_terminal, 
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(toolbar_frame, text="Disconnect", command=self.disconnect_ssh, 
                 font=("Arial", 9), bg="#f44336", fg="white").pack(side=tk.RIGHT)
        
        # Terminal text area (writable)
        self.terminal_text = tk.Text(terminal_frame, height=12, 
                                   wrap=tk.WORD, font=("Consolas", 10),
                                   bg="black", fg="green", insertbackground="green")
        self.terminal_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 5))
        
        # Create scrollbar for terminal
        terminal_scrollbar = tk.Scrollbar(self.terminal_text)
        terminal_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.terminal_text.config(yscrollcommand=terminal_scrollbar.set)
        terminal_scrollbar.config(command=self.terminal_text.yview)
        
        # Bind key events for terminal interaction
        self.terminal_text.bind("<KeyPress>", self.on_terminal_key)
        self.terminal_text.bind("<Button-1>", self.on_terminal_click)
        self.terminal_text.bind("<Return>", self.on_terminal_return)
        
        # Terminal status and command line
        terminal_status_frame = tk.Frame(terminal_frame)
        terminal_status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.terminal_status = tk.Label(terminal_status_frame, text="Terminal: Not connected", 
                                       fg="red", font=("Arial", 9))
        self.terminal_status.pack(side=tk.LEFT)
        
        tk.Label(terminal_status_frame, text="Quick Command:").pack(side=tk.RIGHT, padx=(0, 5))
        self.quick_command = tk.Entry(terminal_status_frame, width=30, font=("Consolas", 9))
        self.quick_command.pack(side=tk.RIGHT, padx=(0, 5))
        self.quick_command.bind("<Return>", self.execute_quick_command)
        
        # Initial messages
        self.output_text.insert(tk.END, "SSH Auto Configuration Tool - Output Log\n")
        self.output_text.insert(tk.END, "This tab shows errors, warnings, and configuration status.\n")
        self.output_text.insert(tk.END, "=" * 60 + "\n\n")
        
        self.terminal_text.insert(tk.END, "SSH Auto Configuration Tool - Interactive Terminal\n")
        self.terminal_text.insert(tk.END, "Connect to a server to start using the terminal.\n")
        self.terminal_text.insert(tk.END, "You can type commands directly in this area.\n")
        self.terminal_text.insert(tk.END, "=" * 60 + "\n")
        self.terminal_text.mark_set("command_start", tk.END)
        self.current_line_start = self.terminal_text.index(tk.END)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, 
                            relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def clear_fields(self):
        """Clear all input fields"""
        self.ip_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.log_server_ip.delete(0, tk.END)
        self.terminal_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.quick_command.delete(0, tk.END)
        self.connection_status.config(text="Not connected", fg="red")
        self.terminal_status.config(text="Terminal: Not connected", fg="red")
        
        # Disable configuration buttons
        self.linux_config_button.config(state=tk.DISABLED)
        self.mysql_config_button.config(state=tk.DISABLED)
        self.apache_config_button.config(state=tk.DISABLED)
        self.rsyslog_config_button.config(state=tk.DISABLED)
        
        # Reset terminal
        self.terminal_enabled = False
        
        # Close SSH connection if open
        if self.shell_channel:
            self.shell_channel.close()
            self.shell_channel = None
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
        
    def log_output(self, message):
        """Add message to terminal output"""
        self.terminal_text.insert(tk.END, f"{message}\n")
        self.terminal_text.see(tk.END)
        self.root.update_idletasks()
    
    def terminal_print(self, text, color=None):
        """Print text to terminal with optional color"""
        self.terminal_text.insert(tk.END, text)
        self.terminal_text.see(tk.END)
        self.root.update_idletasks()
    
    def on_terminal_key(self, event):
        """Handle key press in terminal"""
        if not self.terminal_enabled:
            return "break"
        
        # Get current cursor position
        current_pos = self.terminal_text.index(tk.INSERT)
        
        # Special keys
        if event.keysym == "Return":
            return self.on_terminal_return(event)
        elif event.keysym == "BackSpace":
            # Prevent backspace beyond current line start
            line_start = self.terminal_text.index("insert linestart")
            prompt_end = f"{line_start.split('.')[0]}.{len(self.current_prompt)}"
            if self.terminal_text.compare(current_pos, "<=", prompt_end):
                return "break"
        elif event.keysym == "Up":
            self.history_up_terminal()
            return "break"
        elif event.keysym == "Down":
            self.history_down_terminal()
            return "break"
        elif event.keysym in ["Left", "Right", "Home", "End"]:
            # Allow navigation within current line
            pass
        elif event.char and ord(event.char) < 32:
            # Control characters
            if event.char == '\x03':  # Ctrl+C
                self.send_special_key('ctrl_c')
                return "break"
    
    def on_terminal_click(self, event):
        """Handle click in terminal"""
        if not self.terminal_enabled:
            # Move cursor to end if terminal is disabled
            self.terminal_text.mark_set(tk.INSERT, tk.END)
            return "break"
    
    def on_terminal_return(self, event):
        """Handle Enter key in terminal"""
        if not self.terminal_enabled:
            return "break"
        
        # Get current line content
        current_line = self.terminal_text.get("insert linestart", "insert lineend")
        
        # Extract command (remove prompt)
        if current_line.startswith(self.current_prompt):
            command = current_line[len(self.current_prompt):].strip()
        else:
            command = current_line.strip()
        
        # Add newline
        self.terminal_text.insert(tk.END, "\n")
        
        if command:
            # Add to history
            if command not in self.command_history:
                self.command_history.append(command)
            self.history_index = len(self.command_history)
            
            # Execute command
            self.execute_terminal_command(command)
        else:
            # Empty command, just show new prompt
            self.show_terminal_prompt()
        
        return "break"
    
    def execute_terminal_command(self, command):
        """Execute command in terminal"""
        if not self.shell_channel:
            self.terminal_print("Error: Not connected to SSH\n")
            self.show_terminal_prompt()
            return
        
        try:
            # Handle special local commands
            if command.lower() == 'clear':
                self.clear_terminal()
                return
            elif command.lower() == 'exit':
                self.disconnect_ssh()
                return
            
            # Send command to SSH
            self.shell_channel.send(command + '\n')
            
        except Exception as e:
            self.terminal_print(f"Error: {str(e)}\n")
            self.show_terminal_prompt()
    
    def execute_quick_command(self, event=None):
        """Execute command from quick command entry"""
        command = self.quick_command.get().strip()
        if not command:
            return
        
        # Add command to terminal display
        self.terminal_print(f"{self.current_prompt}{command}\n")
        
        # Execute the command
        self.execute_terminal_command(command)
        
        # Clear quick command entry
        self.quick_command.delete(0, tk.END)
    
    def show_terminal_prompt(self):
        """Show command prompt in terminal"""
        self.terminal_print(self.current_prompt)
        self.current_line_start = self.terminal_text.index(tk.END)
        self.terminal_text.mark_set("command_start", tk.END)
    
    def history_up_terminal(self):
        """Navigate command history up in terminal"""
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.replace_current_command(self.command_history[self.history_index])
    
    def history_down_terminal(self):
        """Navigate command history down in terminal"""
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.replace_current_command(self.command_history[self.history_index])
        elif self.history_index >= len(self.command_history) - 1:
            self.history_index = len(self.command_history)
            self.replace_current_command("")
    
    def replace_current_command(self, command):
        """Replace current command line with given command"""
        # Get current line start and end
        line_start = self.terminal_text.index("insert linestart")
        line_end = self.terminal_text.index("insert lineend")
        
        # Calculate prompt end position
        prompt_end = f"{line_start.split('.')[0]}.{len(self.current_prompt)}"
        
        # Replace command part only
        self.terminal_text.delete(prompt_end, line_end)
        self.terminal_text.insert(prompt_end, command)
        self.terminal_text.mark_set(tk.INSERT, tk.END)
    
    def disconnect_ssh(self):
        """Disconnect SSH connection"""
        try:
            if self.shell_channel:
                self.shell_channel.close()
                self.shell_channel = None
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
            
            self.terminal_print("\nSSH connection closed.\n")
            self.log_output("SSH connection disconnected")
            self.connection_status.config(text="Disconnected", fg="red")
            self.terminal_status.config(text="Terminal: Disconnected", fg="red")
            self.status_var.set("Disconnected")
            
            # Disable terminal and buttons
            self.terminal_enabled = False
            self.linux_config_button.config(state=tk.DISABLED)
            self.mysql_config_button.config(state=tk.DISABLED)
            self.apache_config_button.config(state=tk.DISABLED)
            self.rsyslog_config_button.config(state=tk.DISABLED)
            
        except Exception as e:
            self.log_output(f"Error disconnecting: {str(e)}")
            self.rsyslog_config_button.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)
            self.command_entry.config(state=tk.DISABLED)
            
        except Exception as e:
            self.log_output(f"Error disconnecting: {str(e)}")
    
    def send_special_key(self, key):
        """Send special keys like Ctrl+C, Ctrl+Z, etc."""
        if not self.shell_channel:
            return
        
        special_keys = {
            'ctrl_c': '\x03',  # Ctrl+C
            'ctrl_z': '\x1a',  # Ctrl+Z
            'ctrl_d': '\x04',  # Ctrl+D
            'tab': '\t',       # Tab
            'enter': '\n'      # Enter
        }
        
        if key in special_keys:
            self.shell_channel.send(special_keys[key])
    
    def clear_terminal(self):
        """Clear the terminal display"""
        self.terminal_text.delete(1.0, tk.END)
        self.terminal_print("Terminal cleared by user\n")
        if self.terminal_enabled:
            self.terminal_print("Connected to remote server - Type commands below\n")
            self.terminal_print("=" * 50 + "\n")
            self.show_terminal_prompt()
    
    def start_shell_reader(self):
        """Start reading from SSH shell in a separate thread"""
        def read_shell():
            try:
                buffer = ""
                while self.shell_channel and not self.shell_channel.closed:
                    try:
                        if self.shell_channel.recv_ready():
                            data = self.shell_channel.recv(4096).decode('utf-8', errors='ignore')
                            
                            # Print received data directly to terminal
                            self.terminal_print(data)
                            
                            # Update prompt detection for better command line experience
                            lines = data.split('\n')
                            for line in lines:
                                line = line.strip()
                                if line and any(char in line for char in ['$', '#', '>', '%', ':']):
                                    # Look for common prompt patterns
                                    if (line.endswith('$') or line.endswith('#') or 
                                        line.endswith('> ') or ':~' in line or 
                                        '@' in line and any(line.endswith(c) for c in ['$', '#', '>'])):
                                        # Extract just the prompt part
                                        if '@' in line:
                                            # Format: user@host:path$ or similar
                                            self.current_prompt = line + ' '
                                        else:
                                            self.current_prompt = line + ' ' if not line.endswith(' ') else line
                    
                    except Exception:
                        pass  # Ignore timeout exceptions
                    
                    time.sleep(0.05)  # Reduced sleep for better responsiveness
                    
            except Exception as e:
                self.log_output(f"Shell reader error: {str(e)}")
        
        thread = threading.Thread(target=read_shell)
        thread.daemon = True
        thread.start()
    
    def start_connection(self):
        """Start the SSH connection in a separate thread"""
        # Validate inputs
        root_user = self.root_entry.get().strip()
        ip_address = self.ip_entry.get().strip()
        port = self.port_entry.get().strip() or "22"
        password = self.password_entry.get()
        
        if not root_user or not ip_address:
            messagebox.showerror("Error", "Please enter both root user and IP address")
            return
        
        # Disable button during connection
        self.connect_button.config(state=tk.DISABLED)
        self.status_var.set("Connecting...")
        
        # Start connection in separate thread
        thread = threading.Thread(target=self.connect_to_ssh, 
                                args=(root_user, ip_address, port, password))
        thread.daemon = True
        thread.start()
    
    def connect_to_ssh(self, root_user, ip_address, port, password):
        """Connect via SSH and open interactive shell"""
        try:
            self.log_output(f"Attempting to connect to {root_user}@{ip_address}:{port}")
            
            # Create SSH client
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect
            self.ssh_client.connect(
                hostname=ip_address,
                port=int(port),
                username=root_user,
                password=password,
                timeout=10
            )
            
            self.log_output("✓ SSH connection successful!")
            
            # Create interactive shell
            self.shell_channel = self.ssh_client.invoke_shell()
            self.shell_channel.settimeout(0.1)
            
            # Clear terminal and show welcome message
            self.terminal_text.delete(1.0, tk.END)
            self.terminal_print(f"Connected to {root_user}@{ip_address}\n")
            self.terminal_print("Interactive SSH Terminal - You can type commands directly\n")
            self.terminal_print("=" * 60 + "\n")
            
            # Enable terminal
            self.terminal_enabled = True
            
            # Start shell reader thread
            self.start_shell_reader()
            
            # Wait a moment for initial shell output and show prompt
            time.sleep(1.5)
            self.show_terminal_prompt()
            
            self.connection_status.config(text="Connected ✓", fg="green")
            self.terminal_status.config(text="Terminal: Connected ✓", fg="green")
            self.status_var.set("Connected - Terminal ready")
            
            # Enable configuration buttons
            self.linux_config_button.config(state=tk.NORMAL)
            self.mysql_config_button.config(state=tk.NORMAL)
            self.apache_config_button.config(state=tk.NORMAL)
            self.rsyslog_config_button.config(state=tk.NORMAL)
            
            # Focus on terminal
            self.terminal_text.focus_set()
            
            # Detect the operating system
            system_type = self.detect_system_type()
            self.log_output(f"✓ Detected system type: {system_type}")
            
        except paramiko.AuthenticationException:
            self.log_output("✗ Authentication failed - check username/password")
            messagebox.showerror("Error", "Authentication failed")
            self.connection_status.config(text="Authentication failed ✗", fg="red")
        except paramiko.SSHException as e:
            self.log_output(f"✗ SSH connection failed: {str(e)}")
            messagebox.showerror("Error", f"SSH connection failed: {str(e)}")
            self.connection_status.config(text="Connection failed ✗", fg="red")
        except Exception as e:
            self.log_output(f"✗ Error: {str(e)}")
            messagebox.showerror("Error", str(e))
            self.connection_status.config(text="Error ✗", fg="red")
        finally:
            self.connect_button.config(state=tk.NORMAL)
            if self.status_var.get() != "Connected - Terminal ready":
                self.status_var.set("Ready")
    
    def configure_cisco_system(self):
        """Configure Cisco system"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
            
        self.log_output("Starting Cisco configuration...")
        try:
            # Example Cisco commands
            commands = [
                "configure terminal",
                "hostname AutoConfigured-Router",
                "exit"
            ]
            
            for cmd in commands:
                self.log_output(f"Executing: {cmd}")
                stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=10)
                output = stdout.read().decode()
                if output:
                    self.log_output(output)
            
            self.log_output("✓ Cisco configuration completed")
        except Exception as e:
            self.log_output(f"✗ Cisco configuration failed: {str(e)}")
    
    def configure_windows_system(self):
        """Configure Windows system"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
            
        self.log_output("Starting Windows configuration...")
        try:
            # Example Windows commands
            commands = [
                "systeminfo | findstr /B /C:\"OS Name\"",
                "whoami"
            ]
            
            for cmd in commands:
                self.log_output(f"Executing: {cmd}")
                stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=10)
                output = stdout.read().decode()
                if output:
                    self.log_output(output)
            
            self.log_output("✓ Windows configuration completed")
        except Exception as e:
            self.log_output(f"✗ Windows configuration failed: {str(e)}")
    
    def detect_system_type(self):
        """Detect if the system is Cisco, Linux, or Windows"""
        try:
            # Check for Cisco IOS
            stdin, stdout, stderr = self.ssh_client.exec_command("show version", timeout=5)
            output = stdout.read().decode()
            if "cisco" in output.lower() or "ios" in output.lower():
                return "cisco"
        except:
            pass
        
        try:
            # Check for Linux
            stdin, stdout, stderr = self.ssh_client.exec_command("uname -a", timeout=5)
            output = stdout.read().decode()
            if "linux" in output.lower():
                return "linux"
        except:
            pass
        
        try:
            # Check for Windows
            stdin, stdout, stderr = self.ssh_client.exec_command("ver", timeout=5)
            output = stdout.read().decode()
            if "windows" in output.lower() or "microsoft" in output.lower():
                return "windows"
        except:
            pass
        
        # Additional checks
        try:
            # Try cat /etc/os-release for Linux
            stdin, stdout, stderr = self.ssh_client.exec_command("cat /etc/os-release", timeout=5)
            output = stdout.read().decode()
            if output and "linux" in output.lower():
                return "linux"
        except:
            pass
        
        return "unknown"
    
    def configure_linux_system(self):
        """Configure Linux system using the bash script"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
            
        self.log_output("Starting Linux configuration...")
        
        # Disable button during execution
        self.linux_config_button.config(state=tk.DISABLED)
        
        # Start configuration in separate thread
        thread = threading.Thread(target=self._execute_linux_config)
        thread.daemon = True
        thread.start()
    
    def _execute_linux_config(self):
        """Execute Linux configuration in thread"""
        try:
            # Check if linux_config.sh exists locally
            script_path = os.path.join(os.path.dirname(__file__), "linux_config.sh")
            
            if os.path.exists(script_path):
                # Read the local script
                with open(script_path, 'r') as f:
                    script_content = f.read()
                
                # Create the script on remote system
                self.log_output("Uploading configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("cat > /tmp/linux_config.sh", timeout=10)
                stdin.write(script_content)
                stdin.close()
                
                # Make script executable
                stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x /tmp/linux_config.sh", timeout=5)
                
                # Run the script
                self.log_output("Executing configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("bash /tmp/linux_config.sh", timeout=60)
                
                # Show output in real-time
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_output(line.strip())
                
                # Check for errors
                error = stderr.read().decode()
                if error:
                    self.log_output("Script errors:")
                    self.log_output(error)
                
                self.log_output("✓ Linux configuration completed")
            else:
                self.log_output("⚠ linux_config.sh not found - creating sample script")
                self.create_sample_linux_script()
                
        except Exception as e:
            self.log_output(f"✗ Linux configuration failed: {str(e)}")
        finally:
            self.linux_config_button.config(state=tk.NORMAL)
    
    def configure_mysql_system(self):
        """Configure MySQL system using the MySQL bash script"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
            
        self.log_output("Starting MySQL configuration...")
        
        # Disable button during execution
        self.mysql_config_button.config(state=tk.DISABLED)
        
        # Start configuration in separate thread
        thread = threading.Thread(target=self._execute_mysql_config)
        thread.daemon = True
        thread.start()
    
    def _execute_mysql_config(self):
        """Execute MySQL configuration in thread"""
        try:
            # Check if configurar_mysql_logs.sh exists locally
            script_path = os.path.join(os.path.dirname(__file__), "Bash Files", "configurar_mysql_logs.sh")
            
            if os.path.exists(script_path):
                # Read the local script
                with open(script_path, 'r') as f:
                    script_content = f.read()
                
                # Create the script on remote system
                self.log_output("Uploading MySQL configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("cat > /tmp/configurar_mysql_logs.sh", timeout=10)
                stdin.write(script_content)
                stdin.close()
                
                # Make script executable
                stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x /tmp/configurar_mysql_logs.sh", timeout=5)
                
                # Run the script
                self.log_output("Executing MySQL configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("sudo bash /tmp/configurar_mysql_logs.sh", timeout=60)
                
                # Show output in real-time
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_output(line.strip())
                
                # Check for errors
                error = stderr.read().decode()
                if error:
                    self.log_output("Script errors:")
                    self.log_output(error)
                
                self.log_output("✓ MySQL configuration completed")
            else:
                self.log_output(f"⚠ configurar_mysql_logs.sh not found at: {script_path}")
                
        except Exception as e:
            self.log_output(f"✗ MySQL configuration failed: {str(e)}")
        finally:
            self.mysql_config_button.config(state=tk.NORMAL)
    
    def configure_apache_system(self):
        """Configure Apache system using the Apache bash script"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
        
        # Get log server IP
        log_server_ip = self.log_server_ip.get().strip()
        if not log_server_ip:
            messagebox.showerror("Error", "Please enter the Log Server IP for Apache configuration")
            return
            
        self.log_output(f"Starting Apache configuration with log server: {log_server_ip}")
        
        # Disable button during execution
        self.apache_config_button.config(state=tk.DISABLED)
        
        # Start configuration in separate thread
        thread = threading.Thread(target=self._execute_apache_config, args=(log_server_ip,))
        thread.daemon = True
        thread.start()
    
    def _execute_apache_config(self, log_server_ip):
        """Execute Apache configuration in thread"""
        try:
            # Check if configurar_apache_logs.sh exists locally
            script_path = os.path.join(os.path.dirname(__file__), "Bash Files", "configurar_apache_logs.sh")
            
            if os.path.exists(script_path):
                # Read the local script
                with open(script_path, 'r') as f:
                    script_content = f.read()
                
                # Create the script on remote system
                self.log_output("Uploading Apache configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("cat > /tmp/configurar_apache_logs.sh", timeout=10)
                stdin.write(script_content)
                stdin.close()
                
                # Make script executable
                stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x /tmp/configurar_apache_logs.sh", timeout=5)
                
                # Run the script with the log server IP
                self.log_output(f"Executing Apache configuration script with IP: {log_server_ip}")
                stdin, stdout, stderr = self.ssh_client.exec_command(f"sudo bash /tmp/configurar_apache_logs.sh {log_server_ip}", timeout=60)
                
                # Show output in real-time
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_output(line.strip())
                
                # Check for errors
                error = stderr.read().decode()
                if error:
                    self.log_output("Script errors:")
                    self.log_output(error)
                
                self.log_output("✓ Apache configuration completed")
            else:
                self.log_output(f"⚠ configurar_apache_logs.sh not found at: {script_path}")
                
        except Exception as e:
            self.log_output(f"✗ Apache configuration failed: {str(e)}")
        finally:
            self.apache_config_button.config(state=tk.NORMAL)
    
    def configure_rsyslog_system(self):
        """Configure Rsyslog system using the Rsyslog bash script"""
        if not self.ssh_client:
            messagebox.showerror("Error", "Not connected to SSH. Please connect first.")
            return
        
        # Get log server IP
        log_server_ip = self.log_server_ip.get().strip()
        if not log_server_ip:
            messagebox.showerror("Error", "Please enter the Log Server IP for Rsyslog configuration")
            return
            
        self.log_output(f"Starting Rsyslog configuration with log server: {log_server_ip}")
        
        # Disable button during execution
        self.rsyslog_config_button.config(state=tk.DISABLED)
        
        # Start configuration in separate thread
        thread = threading.Thread(target=self._execute_rsyslog_config, args=(log_server_ip,))
        thread.daemon = True
        thread.start()
    
    def _execute_rsyslog_config(self, log_server_ip):
        """Execute Rsyslog configuration in thread"""
        try:
            # Check if configurar_rsyslog.sh exists locally
            script_path = os.path.join(os.path.dirname(__file__), "Bash Files", "configurar_rsyslog.sh")
            
            if os.path.exists(script_path):
                # Read the local script
                with open(script_path, 'r') as f:
                    script_content = f.read()
                
                # Create the script on remote system
                self.log_output("Uploading Rsyslog configuration script...")
                stdin, stdout, stderr = self.ssh_client.exec_command("cat > /tmp/configurar_rsyslog.sh", timeout=10)
                stdin.write(script_content)
                stdin.close()
                
                # Make script executable
                stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x /tmp/configurar_rsyslog.sh", timeout=5)
                
                # Run the script with the log server IP
                self.log_output(f"Executing Rsyslog configuration script with IP: {log_server_ip}")
                stdin, stdout, stderr = self.ssh_client.exec_command(f"sudo bash /tmp/configurar_rsyslog.sh {log_server_ip}", timeout=60)
                
                # Show output in real-time
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_output(line.strip())
                
                # Check for errors
                error = stderr.read().decode()
                if error:
                    self.log_output("Script errors:")
                    self.log_output(error)
                
                self.log_output("✓ Rsyslog configuration completed")
            else:
                self.log_output(f"⚠ configurar_rsyslog.sh not found at: {script_path}")
                
        except Exception as e:
            self.log_output(f"✗ Rsyslog configuration failed: {str(e)}")
        finally:
            self.rsyslog_config_button.config(state=tk.NORMAL)
    
    def create_sample_linux_script(self):
        """Create a sample Linux configuration script"""
        script_content = """#!/bin/bash
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
"""
        
        script_path = os.path.join(os.path.dirname(__file__), "linux_config.sh")
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        self.log_output(f"✓ Created sample Linux script at: {script_path}")
        self.log_output("Please customize the script for your needs and try again.")

def main():
    root = tk.Tk()
    app = SSHConnectionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()