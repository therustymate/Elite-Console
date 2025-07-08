# Elite Console
Elite Console - Advanced Network Penetration Utility

## Disclaimer
This software and all related documents, code, and materials (hereinafter referred to as the "Program") are provided solely for educational, research, and security enhancement purposes.
Users strictly agree not to use this Program for any illegal activities, unauthorized access, or malicious purposes.

The author and distributor disclaim any and all liability for any direct or indirect damages, losses, or legal consequences resulting from the use of this Program.
All risks and outcomes arising from the use of this Program are the sole responsibility of the user, who must comply with all applicable laws and regulations.

This Program does not support or promote any malicious attacks, illegal acts, or infringement of others' rights. All usage must be ethical and within legal boundaries.
The user bears full responsibility for any legal disputes resulting from improper use of this Program.

By downloading, installing, or executing this Program, the user is deemed to have agreed to this disclaimer.

## Overview

**Elite** is a powerful console-based network security toolkit designed for network management, penetration testing, security diagnostics, and educational purposes.  
It provides a wide range of features, including ARP spoofing, packet relay, port scanning, packet sniffing, and plugin-based extensibility.

> ⚠️ **Warning:**  
> This program is intended strictly for legal security auditing, research, and educational use only.  
> Unauthorized or malicious use may be subject to criminal or civil liability.

---

## Features

- **ARP Attacks & Defense**
  - ARP MITM (Man-in-the-Middle), ARP Deauth (disconnect), ARP Jammer (network disruption), ARP Scan (active host discovery)
- **Network Packet Capture/Relay/Recording**
  - Relaying packets on specified interfaces, recording to PCAP files, real-time sniffing
- **TCP/HTTP Analysis**
  - Port scanning, HTTP cookie and POST data interception
- **ICMP Utilities**
  - Ping, traceroute, and network-wide active host discovery
- **DNS Lookups**
  - nslookup functionality
- **OUI (MAC Manufacturer) Database Loader and Analyzer**
- **Plugin (Module) System**
  - Auto-loads external DLL-based modules for easy extensibility

---

## Build & Run

1. **Install Dependencies**
   - [.NET 6.0 or higher](https://dotnet.microsoft.com/download)
   - [SharpPcap](https://github.com/chmorgan/sharppcap), [PacketDotNet](https://github.com/chmorgan/packetnet) (install via NuGet)

2. **Build**
   ```
   dotnet build
   ```

3. **Run Examples**
   ```
   ./Elite -- -help
   ./Elite -- arp.mitm "InterfaceName" "TargetIP" "GatewayIP" true
   ./Elite -- tcp.portscan 192.168.0.10 3000 1~1000
   ```

   > You can list available network interfaces with the command: `sys.dev.print all`

---

## Example Commands

| Example Command                                      | Description                                   |
| ---------------------------------------------------- | --------------------------------------------- |
| `-help`                                              | Show all commands and usage                   |
| `sys.dev.print all`                                  | List available network interfaces             |
| `arp.scan InterfaceName 192.168.0.0/24`              | ARP scan for a subnet                         |
| `arp.mitm InterfaceName TargetIP GatewayIP true`     | Start ARP spoofing (MITM) attack              |
| `tcp.portscan TargetIP 3000 1~65535`                 | Port scan for a given IP                      |
| `tcp.httpcookie InterfaceName`                       | Intercept HTTP cookies                        |
| `icmp.scan 192.168.0.0/24`                           | ICMP scan for active hosts in subnet          |
| `dns.nslookup example.com`                           | Lookup IP addresses for a given domain        |
| `sys.oui.print all`                                  | Print OUI (manufacturer) database             |
| `sys.mod.print all`                                  | List loaded external modules                  |

---

## Plugin (Module) Extensibility

- Place a subfolder for each module in the `mods` directory and put a `main.dll` file inside.  
- All public/static methods in the module will be recognized as commands automatically.

---