# NetScan

<div align="center">

### A lightweight network discovery tool for your home network

Discover devices responding on your local IPv4 network. View IP addresses, available hostnames, MAC addresses and manufacturer information in a clean desktop interface.

**Python · Nmap · Tkinter · Zeroconf**

[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Troubleshooting](#troubleshooting)

</div>

---

## Overview

NetScan is a Python desktop application that helps you discover and review devices visible on a local network you own or are authorised to manage.

It automatically detects your computer's active IPv4 interface and subnet, performs an Nmap host-discovery scan, and displays the results in an organised table. You can export the discovered information to CSV for your own records.

NetScan is designed to be lightweight, straightforward and useful for understanding what's visible on your home network.

## Features

- **Automatic network detection** — identifies the active network interface, local IPv4 address and subnet.
- **Live host discovery** — uses Nmap to discover responding devices on the selected local subnet.
- **Hostname discovery** — retrieves hostnames where available and attempts to identify names advertised through compatible local network services.
- **MAC address detection** — displays MAC addresses when reported by the network scan.
- **Manufacturer identification** — shows available MAC-address vendor information from Nmap.
- **CSV export** — save scan results for later reference.
- **Simple desktop interface** — built with Python and Tkinter.
- **Host discovery only** — the default scan uses Nmap's `-sn` option rather than scanning device ports.

## Preview

<div align="center">

<!-- Add your screenshot to docs/netscan-screenshot.png and uncomment the next line. -->

<!-- ![NetScan desktop application](docs/netscan-screenshot.png) -->

*NetScan desktop interface — screenshot coming soon.*

</div>

## Requirements

- Python 3.10 or newer
- Nmap
- `netifaces`
- `zeroconf`
- Tkinter

Tkinter is included with many Python installations. On some Linux distributions, it must be installed separately.

## Installation

### 1. Clone the repository

Open Terminal and run:

```bash
git clone https://github.com/SzymonRomaszewski/NetScan.git
cd NetScan
```

Alternatively, download the repository as a ZIP file from GitHub and extract it.

### 2. Install Nmap

**macOS — Homebrew**

```bash
brew install nmap
```

**Debian / Ubuntu**

```bash
sudo apt update
sudo apt install nmap python3-tk python3-venv
```

**Windows**

Download and install Nmap from the official website:

https://nmap.org/download.html

Make sure Nmap is available from your terminal.

### 3. Create a Python virtual environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 4. Install Python dependencies

Ensure the repository contains a `requirements.txt` file with:

```text
netifaces
zeroconf
```

Then install the dependencies.

**macOS / Linux**

```bash
python3 -m pip install -r requirements.txt
```

**Windows**

```powershell
py -m pip install -r requirements.txt
```

### 5. Launch NetScan

Run the following from the repository directory with your virtual environment activated.

**macOS**

```bash
sudo -v
python3 netscan.py
```

The `sudo -v` command authorises privileged commands for a limited period. Launch the graphical application normally; do not run the entire application as root.

The current scanner attempts a privileged Nmap scan and falls back to an unprivileged scan if the privileged command cannot run. The unprivileged scan may return less MAC-address and manufacturer information.

**Linux**

```bash
python3 netscan.py
```

Depending on your system's permissions and network configuration, additional privileges may be needed for complete MAC-address discovery.

**Windows**

```powershell
py netscan.py
```

Windows support depends on the current code handling Windows-specific command and permission differences. The macOS scan instructions should not be assumed to work unchanged on Windows.

## Usage

1. Connect your computer to the local network you own or have permission to inspect.
2. Launch NetScan.
3. Check the detected network interface, local IP address and subnet.
4. Select **Scan home Wi-Fi**.
5. Wait for the scan to complete.
6. Review the discovered devices in the results table.
7. Select **Export CSV** to save the results if required.

NetScan scans the detected subnet. For example, `192.168.0.0/24` represents the local IPv4 range, while `192.168.0.77` is one individual IP address within that subnet.

## Understanding the results

| Field | Description |
|---|---|
| **IP address** | The local IPv4 address reported for a responding device. |
| **Device / hostname** | A hostname or locally advertised service name, when discoverable. |
| **MAC address** | The MAC address reported by Nmap, when available. |
| **Manufacturer** | The vendor associated with the MAC address, when identifiable. |

### Why are some details missing?

NetScan relies on information made available by devices and the local network. Not every device advertises a hostname or friendly name.

Manufacturer identification also has limitations:

- MAC vendor information may be unavailable for some addresses.
- Private or randomised MAC addresses may not identify a device manufacturer.
- MAC addresses may be unavailable when the scan lacks sufficient privileges or the device is beyond the local network segment.
- Routers, guest networks, firewalls, VLANs and wireless client isolation can affect discovery.
- Sleeping devices or devices that do not respond to discovery probes may not appear.

A manufacturer name identifies a network-address vendor, not necessarily the exact product or device model. An unfamiliar device name or missing manufacturer does not by itself indicate unauthorised access.

## Troubleshooting

### Nmap is not found

Check that Nmap is installed and available on your system's `PATH`.

```bash
nmap --version
```

If the command is unavailable, install Nmap using the instructions above.

### Missing Python dependencies

Activate your virtual environment and run:

```bash
python3 -m pip install -r requirements.txt
```

On Windows, use:

```powershell
py -m pip install -r requirements.txt
```

### MAC addresses or manufacturers are missing

On macOS, try authorising the privileged scan immediately before starting NetScan:

```bash
sudo -v
python3 netscan.py
```

If details are still missing, check whether the devices and their MAC addresses appear in your router's connected-device list. Manufacturer information cannot be guaranteed for every device.

### Fewer devices are found than expected

Check that the displayed interface and subnet match your intended local network. Some devices may be asleep, isolated from other wireless clients or configured not to respond to discovery probes.

Compare the results with your router's connected-device list.

### The application reports an error

Run NetScan from Terminal or PowerShell so the error is visible. Verify that Python, Nmap and the dependencies are installed in the environment used to launch the application.

## Privacy and safety

- Use NetScan only on networks you own or have explicit permission to inspect.
- NetScan's default scan performs host discovery rather than port scanning.
- CSV exports can contain information about your home network. Keep them private and do not commit them to a public repository.
- Do not share router credentials, authentication tokens or private network exports in issues or pull requests.

## Contributing

Contributions, bug reports and suggestions are welcome.

1. Fork the repository.
2. Create a branch for your changes.
3. Test your changes on your operating system.
4. Submit a pull request describing the changes and how they were tested.

When reporting a bug, include your operating system, Python version and relevant error messages. Remove private network information before sharing logs.

## Roadmap

Potential future improvements include:

- Improved hostname resolution and clearer identification confidence.
- Better identification of duplicate MAC addresses.
- A device-details view.
- Optional scan history.
- Improved Windows support and cross-platform testing.
- Packaging for easier installation.
- Automated tests and continuous integration.

These are potential improvements, not features currently guaranteed by the application.

## Licence

NetScan is distributed under the MIT License. See the [`LICENSE`](LICENSE) file for details.

---

<div align="center">

**NetScan**  
Built with Python.

</div>
