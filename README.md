# Home Wi-Fi NetScan

A small Python desktop app for discovering devices that respond on **your own home Wi-Fi/LAN**. It displays:

- Your computer's local IP address, network interface, and detected subnet
- Discovered device IP addresses
- Hostnames (when available)
- MAC addresses and manufacturer/vendor (when reported by Nmap)
- CSV export of the scan results

It uses Nmap host discovery (`nmap -sn`) and does **not** perform a port scan.

## Requirements

- Python 3.10+
- Nmap installed on your computer
- Python dependency: `netifaces`

### macOS

1. Install Nmap if needed: `brew install nmap`
2. In Terminal, open this project folder.
3. Create a virtual environment and install the Python dependency:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python3 -m pip install -r requirements.txt
   ```

4. Launch the app:

   ```bash
   python3 netscan.py
   ```

### Windows

1. Install Nmap from https://nmap.org/download.html and make sure `nmap` is available on PATH.
2. Install Python 3.10+.
3. In PowerShell, from this project folder:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   py -m pip install -r requirements.txt
   py netscan.py
   ```

### Linux (Debian/Ubuntu example)

```bash
sudo apt install nmap python3-tk
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python netscan.py
```

## Use

1. Connect the computer to the home Wi-Fi you own or are authorised to manage.
2. Start the app and click **Scan home Wi-Fi**.
3. Wait for the scan to finish. Select **Export CSV** to save the results.

## Important limitations

- A scan can only show devices visible from the computer's current local network. Guest Wi-Fi isolation, VLANs, firewalls, sleeping devices, and router settings can hide devices.
- Some devices do not publish a hostname or MAC address; those fields may show `Unknown` or `Not reported`.
- MAC addresses are normally visible only for devices on the same local network segment. They are not the same as an IP address.
- The app uses the active interface's configured subnet mask rather than assuming every network is `/24`. On unusual systems, verify the displayed interface/subnet before scanning.
- This is a local network inventory tool, not a way to reveal devices on other networks or bypass Wi-Fi security.

## GitHub

Create a repository (for example, `home-wifi-netscan`) and add `netscan.py`, `requirements.txt`, and this `README.md`. Do not commit private scan results or your home network details.
