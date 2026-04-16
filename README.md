# OSINTID - Offensive Security Intelligence & IoT Detection Framework

**Version 1.0**  
**Author**: DANIEL ISHAKU ANDO  
**Website**: danishkute.carrd.co  

OSINTID is a unified framework combining Red Team OSINT, network utilities, IoT device management, web search, and high-performance CPython modules. It features automatic dependency installation, native speed optimizations, persistent logging, and modular architecture.

## Features

- **Network Reconnaissance**: Port scanning, banner grabbing, DNS/WHOIS lookups
- **OSINT Gathering**: IP geolocation, domain reputation checks
- **IoT Management**: Device discovery, registration, and network scanning
- **Network Utilities**: Netcat-like TCP relay (server/client), interactive shells, SSL support
- **Performance Layer**: CPython native acceleration for sockets, hashing, and system calls
- **Storage & Logging**: SQLite database, real-time file logs, data backup
- **Error Handling**: Comprehensive exception recovery and graceful fallbacks

## Installation

1. **Clone/Download**: Place `OSINTID.py` in your directory.
2. **Run**: Execute `python OSINTID.py` (dependencies install automatically on first run).
3. **Permissions**: Run with admin/sudo for network operations.

No separate installation needed—it's self-contained.

## Usage

OSINTID uses command-line arguments. Run `python OSINTID.py --help` for full options.

### Basic Examples

#### Port Scan with Banner Grabbing
```
python OSINTID.py -t 192.168.1.1 --portscan 1 65535 --bannerscan
```
Scans ports 1-65535 on the target and grabs service banners.

#### DNS and WHOIS Lookup
```
python OSINTID.py --dnslookup example.com --whois example.com
```
Resolves DNS and fetches WHOIS data.

#### IoT Device Discovery
```
python OSINTID.py --iot 192.168.1.0/24
```
Scans the network range for IoT devices.

#### OSINT Gathering
```
python OSINTID.py --osint 8.8.8.8
```
Gathers IP geolocation or domain reputation (auto-detects IP vs. domain).

#### Netcat Server Mode
```
python OSINTID.py -t 0.0.0.0 -p 9999 -l -c
```
Listens on port 9999 for connections with an interactive shell.

#### Netcat Client Mode
```
python OSINTID.py -t 192.168.1.100 -p 9999 -c
```
Connects to the target and opens an interactive shell.

#### Execute Command Remotely
```
python OSINTID.py -t 192.168.1.100 -p 9999 -e "whoami"
```
Executes a command on the remote host.

### Module Management

OSINTID supports dynamic module execution:

#### List All Modules
```
python OSINTID.py --list-modules
```
Displays available modules (Core, Intelligence, Network, Framework).

#### List Methods of a Module
```
python OSINTID.py --list-methods recon
```
Shows methods for the Reconnaissance Engine (e.g., port_scan, banner_grab).

#### Execute a Module Method
```
python OSINTID.py --exec-module recon port_scan 192.168.1.1 1 100
```
Runs the port_scan method on the specified target and ports.

#### Import External Module
```
python OSINTID.py --import-module /path/to/module.py mymodule
```
Loads a custom module dynamically.

### Statistics and Logging

- Run with `--stats` to view error counts, IoT devices, and storage info.
- Logs are stored in `./osintid_data/logs/` (daily files) and SQLite database (`./osintid_data/osintid.db`).
- Backups in `./osintid_data/backups/`.

## Security Notes

- **Offensive Use**: Designed for red teaming and security research. Use responsibly and legally.
- **Network Scanning**: May trigger security alerts or firewalls.
- **SSL**: Use `--ssl` for encrypted connections (requires certs for server mode).
- **Permissions**: Avoid running as root unless necessary.

## Troubleshooting

- **Import Errors**: Ensure Python 3.x and pip are installed. Re-run to auto-install dependencies.
- **Network Issues**: Check firewall/antivirus. Use `--iot-range` to customize scan ranges.
- **Performance**: Native CPython optimizations reduce scan times, but large ranges may take time.
- **Errors**: Check logs in `./osintid_data/logs/` for details.

## Contributing

Extend modules via `ModuleExecutor.import_external_module()`. Follow the modular structure for new features.

## License

This project is provided for educational and authorized security research purposes only. The author assumes no responsibility for any misuse, damage, or illegal activity arising from its use. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before conducting any testing or network interaction. By using this software, you agree that it is used at your own risk and in accordance with ethical and legal standards.
