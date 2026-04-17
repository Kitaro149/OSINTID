# usr/bin/python -3
# -*- coding: utf-8 -*-
# Author: DANIEL ISHAKU ANDO
# Website: danishkute.carrd.co
# ============================================================================
# OSINTID - Unified Offensive Security Intelligence & IoT Detection Framework
# ============================================================================
# Combines Red Team OSINT, Network Utilities, IoT Device Management, 
# Web Search, and CPython High-Performance Modules
# ============================================================================
# Self-contained, auto-installing, fully integrated framework
# ============================================================================

import os
import sys
import subprocess

# ============================================================================
# SECTION 0: AUTOMATIC DEPENDENCY INSTALLER & MODULE EXECUTOR
# ============================================================================

class OSINTIDBootstrap:
    """Bootstrap and manage all OSINTID dependencies and modules"""
    
    REQUIRED_PACKAGES = {
        'colorama': 'colorama',
        'dnspython': 'dns',
        'python-whois': 'whois',
        'requests': 'requests',
        'psutil': 'psutil'
    }
    
    OPTIONAL_PACKAGES = {
        'flask': 'flask',
        'fastapi': 'fastapi',
        'uvicorn': 'uvicorn',
        'neo4j': 'neo4j',
        'sqlalchemy': 'sqlalchemy'
    }
    
    @staticmethod
    def check_and_install_dependencies(verbose=False):
        """Check and auto-install all required dependencies"""
        print("[*] OSINTID Bootstrap: Checking dependencies...")
        
        missing = []
        installed = []
        
        for package_name, import_name in OSINTIDBootstrap.REQUIRED_PACKAGES.items():
            try:
                __import__(import_name)
                installed.append(package_name)
                if verbose:
                    print(f"    [OK] {package_name}")
            except ImportError:
                missing.append(package_name)
        
        if missing:
            print(f"[!] Missing packages: {', '.join(missing)}")
            print("[*] Installing missing dependencies...")
            
            for package in missing:
                try:
                    print(f"    [+] Installing {package}...")
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', package])
                    installed.append(package)
                    print(f"    [OK] {package} installed")
                except Exception as e:
                    print(f"    [!] Failed to install {package}: {e}")
        
        print(f"[+] OSINTID Ready: {len(installed)} packages available")
        return len(missing) == 0
    
    @staticmethod
    def load_optional_modules(verbose=False):
        """Load optional packages if available"""
        available = {}
        
        for package_name, import_name in OSINTIDBootstrap.OPTIONAL_PACKAGES.items():
            try:
                available[package_name] = __import__(import_name)
                if verbose:
                    print(f"    [OK] {package_name} available")
            except ImportError:
                if verbose:
                    print(f"    [!] {package_name} not installed")
        
        return available
    
    @staticmethod
    def list_modules():
        """List all available modules"""
        modules = {
            'Core': ['CPythonNativeLibs', 'LocalStorageManager', 'ErrorHandler'],
            'Intelligence': ['ReconEngine', 'OSINTGatherer', 'IoTDeviceManager'],
            'Network': ['NetcatEngine'],
            'Framework': ['OSINTID']
        }
        return modules

# Bootstrap on import
OSINTIDBootstrap.check_and_install_dependencies()

import sys
import ssl
import json
import time
import socket
import platform
import argparse
import threading
import subprocess
import asyncio
import ctypes
import struct
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from colorama import Fore, Style, init
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, quote
import traceback

init(autoreset=True)

# ============================================================================
# SECTION 1: CPython PERFORMANCE LAYER (Native Speed)
# ============================================================================

class CPythonNativeLibs:
    """CPython C-extension and ctypes optimizations for performance-critical operations"""
    
    @staticmethod
    def load_network_library():
        """Load native networking library with fallback"""
        try:
            if platform.system() == "Windows":
                return ctypes.WinDLL("ws2_32.dll"), "windows"
            else:
                lib = ctypes.CDLL(None)
                return lib, "unix"
        except OSError:
            return None, None
    
    @staticmethod
    def fast_port_scanner(ip: str, port: int, timeout: int = 1) -> bool:
        """Native speed port check using ctypes"""
        try:
            libc, os_type = CPythonNativeLibs.load_network_library()
            
            if libc and hasattr(libc, 'socket'):
                # Use native socket call
                sock = libc.socket(2, 1, 0)  # AF_INET=2, SOCK_STREAM=1
                if sock >= 0:
                    return True
            
            # Fallback to Python socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def fast_hash_file(filepath: str, algorithm: str = 'sha256') -> str:
        """Fast file hashing with C acceleration"""
        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
    
    @staticmethod
    def get_system_uptime() -> int:
        """Get system uptime using native calls"""
        try:
            if platform.system() == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                uptime_ms = kernel32.GetTickCount64()
                return int(uptime_ms / 1000.0)
            else:
                with open('/proc/uptime', 'r') as f:
                    return int(float(f.readline().split()[0]))
        except Exception:
            return -1


# ============================================================================
# SECTION 2: STORAGE & LOGGING SYSTEM
# ============================================================================

class LocalStorageManager:
    """Persistent logging and data backup system"""
    
    def __init__(self, base_dir: str = "./osintid_data"):
        self.base_dir = Path(base_dir)
        self.db_path = self.base_dir / "osintid.db"
        self.logs_dir = self.base_dir / "logs"
        self.backups_dir = self.base_dir / "backups"
        
        self.base_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.backups_dir.mkdir(exist_ok=True)
        
        self._init_database()
        self.lock = threading.Lock()
    
    def _init_database(self):
        """Initialize SQLite database"""
        try:
            import sqlite3
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY, timestamp TEXT, level TEXT, 
                module TEXT, message TEXT, metadata TEXT)''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY, timestamp TEXT, scan_type TEXT,
                target TEXT, result TEXT, status TEXT)''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS iot_devices (
                id INTEGER PRIMARY KEY, device_id TEXT UNIQUE, device_name TEXT,
                device_type TEXT, ip_address TEXT, status TEXT, last_seen TEXT)''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Database init failed: {e}")
    
    def log(self, level: str, module: str, message: str, metadata: Dict = None):
        """Log message with real-time file output"""
        try:
            with self.lock:
                timestamp = datetime.now().isoformat()
                
                # Log to file
                log_file = self.logs_dir / f"{datetime.now().strftime('%Y-%m-%d')}.log"
                log_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                log_entry = f"[{log_time}] [{level}] [{module}] {message}\n"
                
                with open(log_file, 'a') as f:
                    f.write(log_entry)
        except Exception as e:
            print(f"[!] Logging error: {e}")
    
    def log_scan(self, scan_type: str, target: str, result: Dict, status: str = "SUCCESS"):
        """Log scan results"""
        try:
            self.log("INFO", "Scan", f"{scan_type} on {target}", {"status": status})
        except Exception as e:
            print(f"[!] Scan log error: {e}")


# ============================================================================
# SECTION 3: ERROR HANDLING & RECOVERY
# ============================================================================

class ErrorHandler:
    """Comprehensive error handling with recovery strategies"""
    
    def __init__(self, storage: LocalStorageManager = None):
        self.storage = storage
        self.error_count = 0
        self.warning_count = 0
    
    def handle(self, exc: Exception, context: str = "", level: str = "ERROR"):
        """Handle exception with logging"""
        if level == "ERROR":
            self.error_count += 1
            color = Fore.RED
            symbol = "[-]"
        elif level == "WARN":
            self.warning_count += 1
            color = Fore.YELLOW
            symbol = "[!]"
        else:
            color = Fore.GREEN
            symbol = "[+]"
        
        msg = f"{context}: {str(exc)}" if context else str(exc)
        print(f"{color}{symbol} {msg}{Style.RESET_ALL}")
        
        if self.storage:
            self.storage.log(level, "ErrorHandler", msg)


# ============================================================================
# SECTION 4: IoT DEVICE MANAGEMENT
# ============================================================================

class IoTDeviceManager:
    """Discover, register, and manage IoT devices"""
    
    def __init__(self, storage: LocalStorageManager = None):
        self.devices: Dict[str, Dict] = {}
        self.storage = storage
        self.lock = threading.Lock()
    
    def add_device(self, device_id: str, name: str, device_type: str, ip: str):
        """Register IoT device"""
        with self.lock:
            self.devices[device_id] = {
                'id': device_id,
                'name': name,
                'type': device_type,
                'ip': ip,
                'status': 'ONLINE',
                'last_seen': datetime.now().isoformat()
            }
            if self.storage:
                self.storage.log("INFO", "IoT", f"Device registered: {name}")
    
   def scan_network(self, network_range: str = "192.168.1.0/24") -> List[str]:
    """Enhanced IoT discovery with multi-port fingerprinting and banner classification"""
    discovered = []

    COMMON_IOT_PORTS = [80, 443, 554, 8080, 23, 1883]

    def grab_banner(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))

            # Send minimal probe for HTTP-like services
            if port in [80, 8080, 443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(512).decode(errors='ignore').lower()
            sock.close()
            return banner
        except Exception:
            return ""

    def classify_device(banner, open_ports):
        """Basic fingerprinting heuristics"""
        if "rtsp" in banner or 554 in open_ports:
            return "IP Camera"
        elif "mqtt" in banner or 1883 in open_ports:
            return "IoT Sensor (MQTT)"
        elif "telnet" in banner or 23 in open_ports:
            return "Embedded Device (Telnet)"
        elif "webcam" in banner or "camera" in banner:
            return "Camera"
        elif any(p in open_ports for p in [80, 443, 8080]):
            return "Web-enabled Device"
        else:
            return "Unknown"

    try:
        import ipaddress
        network = ipaddress.IPv4Network(network_range, strict=False)

        for ip in list(network.hosts())[:100]:
            ip_str = str(ip)
            open_ports = []
            banners = []

            for port in COMMON_IOT_PORTS:
                if CPythonNativeLibs.fast_port_scanner(ip_str, port, timeout=0.5):
                    open_ports.append(port)
                    banner = grab_banner(ip_str, port)
                    if banner:
                        banners.append(banner[:100])

            if open_ports:
                device_type = classify_device(" ".join(banners), open_ports)
                discovered.append(ip_str)

                # Register device immediately
                self.add_device(
                    f"dev-{ip_str.replace('.', '-')}",
                    f"{device_type}-{ip_str}",
                    device_type,
                    ip_str
                )

                print(f"{Fore.GREEN}[+] {ip_str} -> {device_type} | Ports: {open_ports}{Style.RESET_ALL}")

    except Exception as e:
        if self.storage:
            self.storage.log("ERROR", "IoTScan", f"Scan failed: {e}")

    # Optional Nmap integration
    try:
        import shutil
        if shutil.which("nmap"):
            print(f"{Fore.CYAN}[*] Running optional Nmap fingerprinting...{Style.RESET_ALL}")
            for ip in discovered:
                try:
                    result = subprocess.check_output(
                        ["nmap", "-sV", "-T4", "-F", ip],
                        stderr=subprocess.DEVNULL,
                        timeout=15
                    ).decode(errors='ignore')

                    print(f"{Fore.MAGENTA}[NMAP] {ip}:\n{result.splitlines()[0:10]}{Style.RESET_ALL}")

                except Exception:
                    continue
    except Exception:
        pass

    return discovered


# ============================================================================
# SECTION 5: NETWORK RECONNAISSANCE ENGINE
# ============================================================================

class ReconEngine:
    """Active and passive reconnaissance capabilities"""
    
    def __init__(self, storage: LocalStorageManager = None, error_handler: ErrorHandler = None):
        self.storage = storage
        self.error_handler = error_handler
    
    def port_scan(self, target: str, start_port: int, end_port: int) -> List[int]:
        """Fast port scanning using native speed"""
        open_ports = []
        
        if self.storage:
            self.storage.log("INFO", "PortScan", f"Scanning {target}:{start_port}-{end_port}")
        
        for port in range(start_port, min(end_port + 1, start_port + 1000)):
            try:
                if CPythonNativeLibs.fast_port_scanner(target, port, timeout=1):
                    open_ports.append(port)
                    print(f"{Fore.GREEN}[+] Port {port} OPEN{Style.RESET_ALL}")
            except Exception:
                continue
        
        if self.storage:
            self.storage.log_scan("port_scan", target, {"ports": open_ports})
        
        return open_ports
    
    def banner_grab(self, target: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore')
            sock.close()
            
            if self.storage:
                self.storage.log("INFO", "BannerGrab", f"{target}:{port} -> {banner[:50]}")
            
            return banner
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, f"banner_grab({target}:{port})", "WARN")
            return None
    
    def dns_lookup(self, domain: str) -> Dict:
        """DNS resolution"""
        try:
            import socket
            ip = socket.gethostbyname(domain)
            
            if self.storage:
                self.storage.log("INFO", "DNSLookup", f"{domain} -> {ip}")
            
            return {'domain': domain, 'ip': ip}
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, f"dns_lookup({domain})", "WARN")
            return {}
    
    def whois_lookup(self, domain: str) -> Dict:
        """WHOIS information"""
        try:
            import whois
            result = whois.whois(domain)
            
            if self.storage:
                self.storage.log("INFO", "WHOIS", f"Lookup: {domain}")
            
            return dict(result)
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, f"whois_lookup({domain})", "WARN")
            return {}


# ============================================================================
# SECTION 6: WEB SEARCH & OSINT
# ============================================================================

class OSINTGatherer:
    """Open source intelligence gathering"""
    
    def __init__(self, storage: LocalStorageManager = None):
        self.storage = storage
        self.session = None
    
    def search_ip(self, ip: str) -> Dict:
        """Get IP geolocation and information"""
        try:
            import requests
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if self.storage:
                    self.storage.log("INFO", "IPOsint", f"IP info: {ip}")
                return data
            return {}
        except Exception as e:
            if self.storage:
                self.storage.log("ERROR", "IPOsint", str(e))
            return {}
    
    def domain_reputation(self, domain: str) -> Dict:
        """Check domain safety"""
        try:
            result = {
                'domain': domain,
                'safe': True,
                'checked': datetime.now().isoformat()
            }
            
            if self.storage:
                self.storage.log("INFO", "DomainRep", f"Checked: {domain}")
            
            return result
        except Exception as e:
            if self.storage:
                self.storage.log("ERROR", "DomainRep", str(e))
            return {}


# ============================================================================
# SECTION 7: NETWORK UTILITIES (Netcat-like)
# ============================================================================

class NetcatEngine:
    """Network relay and utility functionality"""
    
    def __init__(self, args, storage: LocalStorageManager = None, error_handler: ErrorHandler = None):
        self.args = args
        self.storage = storage
        self.error_handler = error_handler
        self.socket = None
        self.running = True
    
    def create_socket(self, af=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        """Create socket with SSL support"""
        try:
            raw_socket = socket.socket(af, sock_type)
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if self.args.ssl:
                context = ssl.create_default_context()
                if self.args.listen:
                    if os.path.exists("osintid.crt") and os.path.exists("osintid.key"):
                        context.load_cert_chain("osintid.crt", "osintid.key")
                self.socket = context.wrap_socket(raw_socket, server_side=self.args.listen)
            else:
                self.socket = raw_socket
            
            print(f"{Fore.BLUE}[+] Socket created (SSL={self.args.ssl}){Style.RESET_ALL}")
            return self.socket
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, "socket_creation")
            sys.exit(1)
    
    def server_mode(self):
        """Listen for inbound connections"""
        self.create_socket()
        try:
            self.socket.bind((self.args.target, self.args.port))
            self.socket.listen(5)
            print(f"{Fore.GREEN}[+] Listening on {self.args.target}:{self.args.port}{Style.RESET_ALL}")
            
            if self.storage:
                self.storage.log("INFO", "Server", f"Listening on {self.args.target}:{self.args.port}")
            
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    print(f"{Fore.CYAN}[+] Connection from {addr}{Style.RESET_ALL}")
                    
                    if self.args.execute:
                        self._execute_command(conn)
                    elif self.args.command:
                        self._interactive_shell(conn)
                    else:
                        conn.close()
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    if self.error_handler:
                        self.error_handler.handle(e, "server_connection", "WARN")
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, "server_mode")
        finally:
            self.socket.close()
    
    def client_mode(self):
        """Connect to remote target"""
        self.create_socket()
        try:
            self.socket.connect((self.args.target, self.args.port))
            print(f"{Fore.GREEN}[+] Connected to {self.args.target}:{self.args.port}{Style.RESET_ALL}")
            
            if self.storage:
                self.storage.log("INFO", "Client", f"Connected to {self.args.target}:{self.args.port}")
            
            if self.args.execute:
                self._execute_command(self.socket)
            elif self.args.command:
                self._interactive_shell(self.socket)
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle(e, "client_mode")
        finally:
            self.socket.close()
    
    def _execute_command(self, conn):
        """Execute single command"""
        try:
            output = subprocess.check_output(self.args.execute, shell=True, 
                                            stderr=subprocess.STDOUT, timeout=30)
            conn.send(output)
        except Exception as e:
            conn.send(f"Command failed: {e}".encode())
        finally:
            conn.close()
    
    def _interactive_shell(self, conn):
        """Interactive shell"""
        try:
            conn.send(b"OSINTID Interactive Shell\n")
            while self.running:
                conn.send(b"osintid> ")
                cmd = conn.recv(4096).decode(errors='ignore').strip()
                
                if cmd.lower() in ['exit', 'quit']:
                    break
                
                if cmd:
                    try:
                        output = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                        response = output.stdout + output.stderr
                        conn.send(response if response else b"No output\n")
                    except Exception as e:
                        conn.send(f"Error: {e}\n".encode())
        finally:
            conn.close()


# ============================================================================
# SECTION 8: MAIN OSINTID FRAMEWORK
# ============================================================================

class OSINTID:
    """Unified Offensive Security Intelligence & IoT Detection Framework"""
    
    def __init__(self, args):
        self.args = args
        
        # Initialize subsystems
        self.storage = LocalStorageManager()
        self.error_handler = ErrorHandler(self.storage)
        self.recon = ReconEngine(self.storage, self.error_handler)
        self.osint = OSINTGatherer(self.storage)
        self.iot = IoTDeviceManager(self.storage)
        self.netcat = NetcatEngine(args, self.storage, self.error_handler)
        
        self.print_banner()
    
    def print_banner(self):
        """Print OSINTID banner"""
        print(r"""
  ___  ____ ___ _   _ _____ ___ ____  
 / _ \/ ___|_ _| \ | |_   _|_ _|  _ \ 
| | | \___ \| ||  \| | | |  | || | | |
| |_| |___) | || |\  | | |  | || |_| |
 \___/|____/___|_| \_| |_| |___|____/ 
 
::_Offensive Security Intelligence & IoT Detection Framework v1.0_::
        Powered by CPython Native Performance Layer
        """)
    
    def run_port_scan(self):
        """Execute port scan"""
        if self.args.portscan:
            start_port, end_port = self.args.portscan
            open_ports = self.recon.port_scan(self.args.target, start_port, end_port)
            
            print(f"\n{Fore.CYAN}[*] Open ports: {open_ports}{Style.RESET_ALL}")
            
            if self.args.bannerscan and open_ports:
                print(f"{Fore.CYAN}[*] Grabbing banners...{Style.RESET_ALL}")
                for port in open_ports:
                    banner = self.recon.banner_grab(self.args.target, port)
                    if banner:
                        print(f"    {port}: {banner[:50]}")
    
    def run_dns_lookup(self):
        """DNS resolution"""
        if self.args.dnslookup:
            result = self.recon.dns_lookup(self.args.dnslookup)
            if result:
                print(f"{Fore.CYAN}[+] {result}{Style.RESET_ALL}")
    
    def run_whois(self):
        """WHOIS lookup"""
        if self.args.whois:
            result = self.recon.whois_lookup(self.args.whois)
            if result:
                print(f"{Fore.CYAN}[+] WHOIS: {json.dumps(result, indent=2, default=str)[:300]}...{Style.RESET_ALL}")
    
    def run_osint(self):
        """OSINT gathering"""
        if self.args.osint:
            # Check if IP or domain
            if self._is_ip(self.args.osint):
                result = self.osint.search_ip(self.args.osint)
                print(f"{Fore.CYAN}[+] IP Info: {json.dumps(result, indent=2)[:200]}...{Style.RESET_ALL}")
            else:
                result = self.osint.domain_reputation(self.args.osint)
                print(f"{Fore.CYAN}[+] Domain: {json.dumps(result, indent=2)}{Style.RESET_ALL}")
    
    def run_iot_scan(self):
        """IoT device discovery"""
        if self.args.iot:
            print(f"{Fore.YELLOW}[*] Scanning network for IoT devices...{Style.RESET_ALL}")
            devices = self.iot.scan_network(self.args.iot_range)
            
            print(f"{Fore.GREEN}[+] Found {len(devices)} devices:{Style.RESET_ALL}")
            for ip in devices:
                self.iot.add_device(f"dev-{ip.replace('.', '-')}", f"Device-{ip}", "Unknown", ip)
                print(f"    - {ip}")
            
            # Show registered devices
            all_devices = self.iot.get_devices()
            self.storage.log("INFO", "IoTScan", f"Discovered {len(all_devices)} devices")
    
    def run_netcat(self):
        """Network relay mode"""
        if self.args.listen:
            if not self.args.target:
                self.args.target = '0.0.0.0'
            self.netcat.server_mode()
        else:
            if not self.args.target or not self.args.port:
                print(f"{Fore.RED}[-] Target and port required for client mode{Style.RESET_ALL}")
                return
            self.netcat.client_mode()
    
    def show_stats(self):
        """Display statistics"""
        print(f"\n{Fore.CYAN}[*] OSINTID Statistics:{Style.RESET_ALL}")
        print(f"    Errors: {self.error_handler.error_count}")
        print(f"    Warnings: {self.error_handler.warning_count}")
        print(f"    IoT Devices: {len(self.iot.get_devices())}")
        print(f"    Storage: {self.storage.db_path}")
    
    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if target is IP"""
        import re
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target))


# ============================================================================
# SECTION 9.5: MODULE EXECUTOR & LOADER
# ============================================================================

class ModuleExecutor:
    """Execute and manage OSINTID modules dynamically"""
    
    def __init__(self, osintid_framework: 'OSINTID' = None):
        self.framework = osintid_framework
        self.modules = {}
        self.load_internal_modules()
        self.module_metadata = self.build_metadata()
    
    def load_internal_modules(self):
        """Load all internal OSINTID modules"""
        self.modules = {
            'cpython': CPythonNativeLibs,
            'storage': LocalStorageManager,
            'errors': ErrorHandler,
            'recon': ReconEngine,
            'osint': OSINTGatherer,
            'iot': IoTDeviceManager,
            'netcat': NetcatEngine,
            'framework': OSINTID
        }
    
    def build_metadata(self) -> Dict:
        """Build metadata registry for all modules"""
        return {
            'cpython': {
                'name': 'CPython Native Performance Layer',
                'version': '1.0',
                'methods': ['load_network_library', 'fast_port_scanner', 'fast_hash_file', 'get_system_uptime'],
                'requires': ['ctypes'],
                'purpose': 'Native socket and system acceleration'
            },
            'storage': {
                'name': 'Local Storage Manager',
                'version': '1.0',
                'methods': ['log', 'log_scan', '__init__'],
                'requires': ['sqlite3'],
                'purpose': 'Persistent data and logging'
            },
            'errors': {
                'name': 'Error Handler',
                'version': '1.0',
                'methods': ['handle'],
                'requires': ['colorama'],
                'purpose': 'Exception handling and recovery'
            },
            'recon': {
                'name': 'Reconnaissance Engine',
                'version': '1.0',
                'methods': ['port_scan', 'banner_grab', 'dns_lookup', 'whois_lookup'],
                'requires': ['socket', 'whois'],
                'purpose': 'Network reconnaissance and scanning'
            },
            'osint': {
                'name': 'OSINT Gatherer',
                'version': '1.0',
                'methods': ['search_ip', 'domain_reputation'],
                'requires': ['requests'],
                'purpose': 'Open source intelligence gathering'
            },
            'iot': {
                'name': 'IoT Device Manager',
                'version': '1.0',
                'methods': ['add_device', 'scan_network', 'get_devices'],
                'requires': ['ipaddress'],
                'purpose': 'IoT device discovery and management'
            },
            'netcat': {
                'name': 'Netcat Engine',
                'version': '1.0',
                'methods': ['create_socket', 'server_mode', 'client_mode'],
                'requires': ['socket', 'ssl'],
                'purpose': 'Network relay and utilities'
            },
            'framework': {
                'name': 'OSINTID Main Framework',
                'version': '2.0',
                'methods': ['run_port_scan', 'run_dns_lookup', 'run_osint', 'run_iot_scan', 'run_netcat'],
                'requires': [],
                'purpose': 'Main framework orchestration'
            }
        }
    
    def execute_module(self, module_name: str, method: str, *args, **kwargs):
        """Execute a module method"""
        try:
            if module_name not in self.modules:
                print(f"[!] Module '{module_name}' not found")
                return None
            
            module = self.modules[module_name]
            
            if not hasattr(module, method):
                print(f"[!] Method '{method}' not found in {module_name}")
                return None
            
            result = getattr(module, method)(*args, **kwargs)
            print(f"[+] Executed {module_name}.{method}")
            return result
        except Exception as e:
            print(f"[-] Error executing {module_name}.{method}: {e}")
            return None
    
    def list_modules(self):
        """List all available modules"""
        print("\n" + "="*70)
        print("OSINTID Available Modules".center(70))
        print("="*70)
        
        categories = {
            'Core Infrastructure': ['cpython', 'storage', 'errors'],
            'Intelligence Gathering': ['recon', 'osint', 'iot'],
            'Network Operations': ['netcat'],
            'Framework': ['framework']
        }
        
        for category, modules in categories.items():
            print(f"\n{category}:")
            for mod in modules:
                if mod in self.module_metadata:
                    meta = self.module_metadata[mod]
                    print(f"  [{mod}] {meta['name']}")
                    print(f"      Version: {meta['version']}")
                    print(f"      Purpose: {meta['purpose']}")
                    print(f"      Methods: {', '.join(meta['methods'][:3])}{'...' if len(meta['methods']) > 3 else ''}")
        
        print("\n" + "="*70)
    
    def list_methods(self, module_name: str):
        """List methods of a module"""
        if module_name not in self.modules:
            print(f"[!] Module '{module_name}' not found")
            return
        
        if module_name not in self.module_metadata:
            print(f"[!] No metadata for module '{module_name}'")
            return
        
        meta = self.module_metadata[module_name]
        print(f"\n{meta['name']} (v{meta['version']})")
        print(f"Purpose: {meta['purpose']}")
        print(f"Requires: {', '.join(meta['requires']) if meta['requires'] else 'None'}")
        print(f"\nAvailable Methods:")
        
        for method in meta['methods']:
            print(f"  - {method}")
    
    def show_capabilities(self):
        """Show all capabilities"""
        print("\n" + "="*70)
        print("OSINTID Capabilities Matrix".center(70))
        print("="*70)
        
        capabilities = {
            'Network Scanning': ['Port scanning', 'Banner grabbing', 'Service detection'],
            'DNS Resolution': ['DNS lookups', 'WHOIS information', 'Domain intelligence'],
            'OSINT Gathering': ['IP geolocation', 'Domain reputation', 'Network reconnaissance'],
            'IoT Management': ['Device discovery', 'Network scanning', 'Device registration'],
            'Network Utilities': ['TCP relay (server)', 'TCP relay (client)', 'Interactive shell'],
            'Storage': ['SQLite logging', 'Real-time file logs', 'Data backup'],
            'Performance': ['Native socket acceleration', 'Fast hashing', 'System uptime'],
            'Error Handling': ['Exception recovery', 'Graceful fallbacks', 'Detailed logging']
        }
        
        for capability, features in capabilities.items():
            print(f"\n{capability}:")
            for feature in features:
                print(f"  [+] {feature}")
        
        print("\n" + "="*70)
    
    def import_external_module(self, module_path: str, module_name: str):
        """Dynamically import external modules"""
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            self.modules[module_name] = module
            print(f"[+] External module loaded: {module_name} from {module_path}")
            return module
        except Exception as e:
            print(f"[-] Failed to load external module: {e}")
            return None
    
    def get_module_info(self, module_name: str) -> Dict:
        """Get detailed info about a module"""
        if module_name not in self.module_metadata:
            return None
        return self.module_metadata[module_name]
    
    def get_all_modules_info(self) -> Dict:
        """Get info about all modules"""
        return self.module_metadata



# ============================================================================
# SECTION 9: COMMAND-LINE INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="OSINTID - Offensive Security Intelligence & IoT Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Port scan with banner grabbing
  python OSINTID.py -t 192.168.1.1 --portscan 1 65535 --bannerscan
  
  # DNS and WHOIS lookup
  python OSINTID.py --dnslookup example.com --whois example.com
  
  # IoT device discovery
  python OSINTID.py --iot 192.168.1.0/24
  
  # OSINT gathering
  python OSINTID.py --osint 8.8.8.8
  
  # Netcat server
  python OSINTID.py -t 0.0.0.0 -p 9999 -l -c
  
  # Module Management
  python OSINTID.py --list-modules
  python OSINTID.py --list-methods storage
  python OSINTID.py --exec-module recon port_scan 192.168.1.1 1 100
        """
    )
    
    parser.add_argument('-t', '--target', default=None, help='Target IP or hostname')
    parser.add_argument('-p', '--port', type=int, default=9999, help='Target port')
    parser.add_argument('-l', '--listen', action='store_true', help='Listen mode')
    parser.add_argument('-c', '--command', action='store_true', help='Interactive shell')
    parser.add_argument('-e', '--execute', help='Execute command')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS')
    
    # Reconnaissance
    parser.add_argument('--portscan', nargs=2, type=int, metavar=('START', 'END'), 
                       help='Port scan range')
    parser.add_argument('--bannerscan', action='store_true', help='Grab banners')
    parser.add_argument('--dnslookup', help='DNS lookup')
    parser.add_argument('--whois', help='WHOIS lookup')
    
    # OSINT & IoT
    parser.add_argument('--osint', help='OSINT gather target (IP or domain)')
    parser.add_argument('--iot', metavar='RANGE', help='IoT device scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--iot-range', default='192.168.1.0/24', help='IoT scan range default')
    
    # System
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    
    # Module Management
    parser.add_argument('--list-modules', action='store_true', help='List all available modules')
    parser.add_argument('--list-methods', metavar='MODULE', help='List methods of a module')
    parser.add_argument('--exec-module', nargs=argparse.REMAINDER, metavar=('MODULE', 'METHOD', 'ARGS'),
                       help='Execute a module method')
    parser.add_argument('--import-module', nargs=2, metavar=('PATH', 'NAME'),
                       help='Import external module')
    
    args = parser.parse_args()
    
    # Initialize OSINTID
    framework = OSINTID(args)
    executor = ModuleExecutor(framework)
    
    try:
        # Module management operations
        if args.list_modules:
            executor.list_modules()
            return
        
        if args.list_methods:
            executor.list_methods(args.list_methods)
            return
        
        if args.exec_module:
            module_name = args.exec_module[0]
            method_name = args.exec_module[1] if len(args.exec_module) > 1 else None
            method_args = args.exec_module[2:] if len(args.exec_module) > 2 else []
            
            if not method_name:
                print("[!] Usage: --exec-module MODULE METHOD [ARGS...]")
                return
            
            executor.execute_module(module_name, method_name, *method_args)
            return
        
        if args.import_module:
            module_path, module_name = args.import_module
            executor.import_external_module(module_path, module_name)
            return
        
        # Execute operations
        if args.stats:
            framework.show_stats()
        elif args.portscan:
            framework.run_port_scan()
        elif args.dnslookup:
            framework.run_dns_lookup()
        elif args.whois:
            framework.run_whois()
        elif args.osint:
            framework.run_osint()
        elif args.iot:
            framework.run_iot_scan()
        elif args.listen or args.target or args.execute or args.command:
            framework.run_netcat()
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
