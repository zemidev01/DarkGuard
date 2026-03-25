<img width="1200" height="951" alt="image" src="https://github.com/user-attachments/assets/7c3227e8-42d5-4533-8058-e4ce6bf72877" />

# DarkGuard

A lightweight, open-source dark-mode GUI for WireGuard on Windows, written in Rust.

## Overview

DarkGuard is a native Windows graphical frontend for managing WireGuard tunnels.
It provides a cleaner alternative to the official WireGuard UI while relying on
the official WireGuard backend.

DarkGuard does not implement its own VPN stack and does not modify WireGuard
internals.

## Features

- Native dark-mode user interface
- Start, stop, and monitor WireGuard tunnels
- Live RX/TX traffic statistics
- Detailed tunnel information (endpoint, DNS, MTU, allowed IPs)
- Uses official WireGuard binaries and Windows services
- Automatically installs WireGuard if not present
- Portable distribution (no forced installer)

## How it works

DarkGuard acts as a graphical wrapper around WireGuard for Windows. It manages
tunnels by:

- Installing WireGuard for Windows if it is not already installed
- Installing and controlling WireGuard tunnel Windows services
- Invoking the official `wireguard.exe` command-line tool
- Reading tunnel status and statistics from the system

This approach ensures full compatibility with WireGuard while keeping the
application lightweight and transparent.

## Antivirus false positives

DarkGuard manages WireGuard tunnels by installing and controlling Windows services
and invoking `wireguard.exe`. This behavior is similar to how malware loaders
operate and may cause false positives in heuristic antivirus scanners or sandbox
environments.

DarkGuard is fully open-source and:
- Does not use obfuscation or packers
- Does not hide or persist beyond WireGuard services
- Does not perform any malicious actions

All functionality can be verified by inspecting the source code.

## Installation

### Portable build

1. Download the latest release from the Releases page
2. Extract the archive
3. Run `darkguard.exe`
4. Grant administrator privileges when prompted

If WireGuard for Windows is not installed, DarkGuard will download and install the
official WireGuard package automatically.

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Administrator privileges (required for managing WireGuard)

## Development status

DarkGuard is in early development. APIs, configuration handling, and the user
interface may change between versions.

Bug reports and contributions are welcome.

## License

This project is licensed under the GNU General Public License v3.0.  
See the LICENSE file for details.

## Disclaimer

WireGuard is a registered trademark of its respective owners.  
This project is not affiliated with or endorsed by WireGuard.

## Sandbox analysis

For transparency, a public Any.Run sandbox analysis of DarkGuard is available.

The report flags the application as "loader" due to its use of elevated
privileges, Windows service management, and WireGuard process invocation.
This behavior is expected and required for managing WireGuard tunnels on Windows.

The analysis does not indicate malicious payloads, persistence mechanisms,
or hidden network activity.

Public Any.Run report:
https://any.run/report/230b91dd4ecb22ca7333c3ed76032a392ac3ee1ce07813a12dd04665d58db24d/e21215e3-ed9c-48a9-9afe-785a95dde82e

## Copyright

Copyright (c) 2026 zemidev01
