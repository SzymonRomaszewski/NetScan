<div align="center">

# NetScan

### A simple desktop scanner for your home network

Discover devices responding on your local IPv4 network and review their IP addresses, hostnames, MAC addresses and manufacturer details when available.

**Python · Nmap · Tkinter · macOS / Windows / Linux**

</div>

---

## Overview

NetScan is a lightweight desktop application for building a quick inventory of devices visible on a local network you own or are authorised to manage. It detects your computer's active IPv4 interface and subnet, runs an Nmap host-discovery scan, and presents the results in a table.

NetScan is designed to be straightforward: open the app, scan your local network, review the results and optionally export them to CSV.

## Features

- **Local network detection** — displays the selected network interface, your computer's IPv4 address and detected subnet.
- **Host discovery** — uses Nmap's host-discovery mode to find devices that respond to discovery probes.
- **Device details** — displays IP address, hostname (if discoverable), MAC address and manufacturer/vendor (if reported by Nmap).
- **CSV export** — save discovered results for your own records.
- **Cross-platform codebase** — Python desktop UI intended for macOS, Windows and Linux.
- **No port scanning** — the default scan uses Nmap `-sn` host discovery.

## What it looks like

> **Screenshot:** Add a screenshot of the running application here. In GitHub, you can upload an image to the repository (for example, `docs/netscan-screenshot.png`) and then replace this note with:
>
> `![NetScan application screenshot](docs/netscan-screenshot.png)`

## Requirements

- Python 3.10 or newer
- Nmap installed and available on your system's `PATH`
- Python dependency: `netifaces`

## Installation

### macOS

1. Install [Homebrew](https://brew.sh/) if it is not already installed.
2. Open Terminal and install Nmap:

   ```bash
   brew install nmap
   ```

3. Download or clone this repository, then enter the project folder:

   ```bash
   git clone https://github.com/SzymonRomaszewski/NetScan.git
   cd NetScan
   ```

4. Create a virtual environment and install the Python dependency:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python3 -m pip install -r requirements.txt
   ```

5. Start NetScan:

   ```bash
   python3 netscan.py
   ```

### Windows

1. Install Python 3.10+ and [Nmap](https://nmap.org/download.html). During setup, ensure Python and Nmap can be run from PowerShell.
2. Clone the repository:

   ```powershell
   git clone https://github.com/SzymonRomaszewski/NetScan.git
   cd NetScan
   ```

3. Create and activate a virtual environment, then install dependencies:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   py -m pip install -r requirements.txt
   ```

4. Run the app:

   ```powershell
   py netscan.py
   ```

### Linux (Debian / Ubuntu)

Install Nmap and Tkinter support:

```bash
sudo apt update
sudo apt install nmap python3-tk python3-venv
```

Clone the repository and set up the environment:

```bash
git clone https://github.com/SzymonRomaszewski/NetScan.git
cd NetScan
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 netscan.py
```

## How to use it

1. Connect your computer to the home network you own or have permission to manage.
2. Launch NetScan.
3. Check the detected interface, local IP address and subnet shown near the top of the window.
4. Select **Scan home Wi-Fi** and wait for discovery to finish.
5. Review the results table.
6. Select **Export CSV** if you want to save the discovered device list.

## Understanding the results

| Field | Meaning |
| --- | --- |
| **IP address** | The IPv4 address reported for a responding host. |
| **Device / hostname** | A name resolved through Nmap or reverse DNS, when available. Otherwise, the app displays `Unknown`. |
| **MAC address** | The hardware address reported by Nmap when available. |
| **Manufacturer** | Vendor information Nmap can associate with a MAC address, when available. |

### Why might a device show as unknown?

Not every device provides a hostname, and MAC addresses are generally visible only on the same local network segment. Nmap may not receive a MAC address for every host. Guest Wi-Fi isolation, VLANs, firewalls, sleeping devices, VPNs and router configuration can also affect discovery.

NetScan does not guarantee that every connected device will be found or identified. A missing hostname or manufacturer does not necessarily mean a device is suspicious.

## Troubleshooting

### `nmap` not found

Install Nmap for your operating system and confirm that the `nmap` command is available in a new Terminal or PowerShell session.

- macOS with Homebrew: `brew install nmap`
- Debian / Ubuntu: `sudo apt install nmap`
- Windows: use the installer at [nmap.org/download.html](https://nmap.org/download.html)

### `Missing dependency netifaces`

Make sure you are in the project directory and your virtual environment is activated, then run:

```bash
python3 -m pip install -r requirements.txt
```

On Windows, use `py -m pip install -r requirements.txt` if that is the Python launcher configured on your system.

### No devices found or fewer devices than expected

Verify that the displayed interface and subnet correspond to your intended local network. Some networks isolate wireless clients or block discovery traffic. Try checking the router's connected-device list as a comparison.

### The app opens, then immediately shows an error

Run it from Terminal or PowerShell so you can read the error message. Check that Python, Nmap and the requirements are installed in the environment used to launch the application.

## Privacy and safety

- Use NetScan only on networks you own or have explicit permission to assess.
- NetScan performs local host discovery; it does not attempt to bypass Wi-Fi security.
- CSV exports can contain details about your home network. Keep them private and do not commit scan results to a public repository.
- Do not include router credentials, tokens, private network exports or other personal information in issues or pull requests.

## Contributing

Contributions, bug reports and suggestions are welcome.

1. Fork the repository.
2. Create a branch for your change.
3. Test your change on your operating system.
4. Open a pull request describing what changed and how you tested it.

When reporting a bug, include your operating system, Python version and the relevant error message. Remove private network details before posting logs.

## Roadmap ideas

Potential future improvements include:

- Better device-name resolution and clearer identification confidence
- Optional router/gateway information
- A device-details view and improved scan history
- Packaging for easier installation without manually launching Python
- Automated tests and continuous integration

These are ideas for future work, not features currently guaranteed by the app.

## Licence

NetScan is distributed under the [MIT License](LICENSE).

---

<div align="center">

**NetScan** · Built with Python

</div>
