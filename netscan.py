#!/usr/bin/env python3
"""Home Wi-Fi NetScan: discover devices on the currently selected local subnet."""
from __future__ import annotations

import csv
import ipaddress
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import tempfile
import tkinter as tk
import xml.etree.ElementTree as ET
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import netifaces
except ImportError:
    netifaces = None

APP_TITLE = "Home Wi-Fi NetScan"


def get_local_network():
    """Return (interface, local_ip, subnet) for the default IPv4 interface."""
    if netifaces is None:
        raise RuntimeError("Missing dependency netifaces. Run: python3 -m pip install -r requirements.txt")

    gateways = netifaces.gateways()
    default = gateways.get("default", {}).get(netifaces.AF_INET)
    preferred_iface = default[1] if default else None
    candidates = []

    for iface in netifaces.interfaces():
        if preferred_iface and iface != preferred_iface:
            continue
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            ip, mask = addr.get("addr"), addr.get("netmask")
            if not ip or not mask or ip.startswith(("127.", "169.254.")):
                continue
            try:
                network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            candidates.append((iface, ip, network))

    if not candidates:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip, mask = addr.get("addr"), addr.get("netmask")
                if not ip or not mask or ip.startswith(("127.", "169.254.")):
                    continue
                try:
                    candidates.append((iface, ip, ipaddress.ip_network(f"{ip}/{mask}", strict=False)))
                except ValueError:
                    pass
    if not candidates:
        raise RuntimeError("No active IPv4 network found. Connect to your home Wi-Fi and try again.")
    return candidates[0]


def run_command(args, timeout=180):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def _parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = hostname = ""
        for address in host.findall("address"):
            kind = address.get("addrtype")
            if kind == "ipv4":
                ip = address.get("addr", "")
            elif kind == "mac":
                mac = address.get("addr", "").upper()
                vendor = (address.get("vendor") or "").strip()
        hostnames = host.find("hostnames")
        if hostnames is not None:
            names = sorted(hostnames.findall("hostname"), key=lambda x: x.get("type") != "PTR")
            for entry in names:
                candidate = (entry.get("name") or "").strip().rstrip(".")
                if candidate and not candidate.lower().endswith(".in-addr.arpa"):
                    hostname = candidate
                    break
        if ip:
            devices.append({"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor})
    return devices


def nmap_xml_scan(network, interface):
    """Try an administrator-authorised ARP scan first, then a regular Nmap scan."""
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("Nmap is not installed. On macOS, run: brew install nmap")

    # Explicitly select the interface detected for this subnet. On macOS, MAC/vendor
    # details usually require Nmap to run with administrator privileges.
    base = [nmap, "-sn", "-PR", "-R", "--reason", "-e", interface, "-oX", "-", str(network)]
    errors = []

    # First try an already-authorised sudo session (e.g. after running `sudo -v`).
    if shutil.which("sudo"):
        result = run_command(["sudo", "-n", *base], timeout=180)
        if result and result.returncode == 0:
            try:
                return _parse_nmap_xml(result.stdout), "administrator"
            except ET.ParseError:
                errors.append("Administrator scan returned invalid XML.")
        elif result:
            errors.append((result.stderr or result.stdout).strip() or "Administrator permission was not available.")

        # If sudo's cached authorisation has expired, request it with the macOS
        # administrator dialog. Nmap writes XML to a private temporary file so
        # AppleScript doesn't have to transport large XML through its output.
        if os.name == "posix" and shutil.which("osascript") and shutil.which("sudo"):
            temp_dir = tempfile.mkdtemp(prefix="netscan-")
            xml_path = os.path.join(temp_dir, "scan.xml")
            shell_command = " ".join(shlex.quote(part) for part in [*base[:-2], xml_path, str(network)])
            # base ends with ['-oX', '-', network]; replace '-' with private file path.
            shell_command = " ".join(shlex.quote(part) for part in [*base[:-2], xml_path, str(network)])
            applescript_command = 'do shell script "' + shell_command.replace('\\', '\\\\').replace('"', '\\"') + '" with administrator privileges'
            auth = run_command(["osascript", "-e", applescript_command], timeout=240)
            try:
                if auth and auth.returncode == 0 and os.path.isfile(xml_path):
                    xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
                    return _parse_nmap_xml(xml_text), "administrator (prompted)"
                if auth:
                    errors.append((auth.stderr or auth.stdout).strip() or "Administrator scan was cancelled or failed.")
            except (OSError, ET.ParseError) as exc:
                errors.append(str(exc))
            finally:
                try:
                    if os.path.exists(xml_path):
                        os.remove(xml_path)
                    os.rmdir(temp_dir)
                except OSError:
                    pass

    # Fallback: useful for discovery, but often cannot report MAC/vendor data.
    result = run_command(base, timeout=180)
    if result and result.returncode == 0:
        try:
            return _parse_nmap_xml(result.stdout), "standard (limited MAC/vendor data)"
        except ET.ParseError:
            errors.append("Standard scan returned invalid XML.")
    elif result:
        errors.append((result.stderr or result.stdout).strip() or "Standard Nmap scan failed.")
    else:
        errors.append("Nmap timed out or could not be started.")
    raise RuntimeError("Nmap could not scan the network.\n\n" + "\n".join(e for e in errors if e))


def arp_table():
    """Read macOS's ARP cache, which can contain MACs missed by Nmap output."""
    result = run_command(["arp", "-an"], timeout=10)
    found = {}
    if not result or result.returncode != 0:
        return found
    for line in result.stdout.splitlines():
        # Example: ? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-fA-F:]{17})", line)
        if match and match.group(2).lower() != "ff:ff:ff:ff:ff:ff":
            found[match.group(1)] = match.group(2).upper()
    return found


def vendor_from_nmap_database(mac):
    """Look up the MAC's OUI in the Nmap vendor database when present."""
    if not mac:
        return ""
    prefix = mac.replace(":", "").upper()[:6]
    candidates = [
        Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
        Path("/usr/local/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/nmap/nmap-mac-prefixes"),
    ]
    # Also check common Homebrew cellar locations.
    for root in (Path("/opt/homebrew/Cellar/nmap"), Path("/usr/local/Cellar/nmap")):
        if root.exists():
            candidates.extend(root.glob("*/share/nmap/nmap-mac-prefixes"))
    for database in candidates:
        try:
            with database.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    fields = line.rstrip("\n").split(None, 1)
                    if len(fields) == 2 and fields[0].upper() == prefix:
                        return fields[1].strip()
        except OSError:
            continue
    return ""


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0].strip().rstrip(".")
        if name and name != ip:
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    return ""


def scan_devices(network):
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is not installed. On macOS, run: brew install nmap")

    devices, scan_mode = nmap_xml_scan(network, get_local_network()[0])
    # Enrich Nmap results with MACs learned by the operating system's ARP cache.
    arp = arp_table()
    by_ip = {d["ip"]: d for d in devices}
    for ip, mac in arp.items():
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue
        if ip not in by_ip:
            by_ip[ip] = {"ip": ip, "hostname": "", "mac": mac, "vendor": ""}
        elif not by_ip[ip]["mac"]:
            by_ip[ip]["mac"] = mac

    # Resolve names and vendors after discovery; never invent a device name.
    for device in by_ip.values():
        if not device["hostname"]:
            device["hostname"] = reverse_dns(device["ip"]) or "Name unavailable"
        if not device["vendor"] and device["mac"]:
            device["vendor"] = vendor_from_nmap_database(device["mac"])
        if not device["vendor"]:
            device["vendor"] = "Manufacturer unavailable"
        if not device["mac"]:
            device["mac"] = ""
    return list(by_ip.values()), scan_mode


class NetScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1000x600")
        self.root.minsize(760, 440)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Home Wi-Fi NetScan", font=("Arial", 22, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="Find responding devices on your local network. Names and manufacturers depend on information the network makes available.",
            wraplength=930,
        ).pack(anchor="w", pady=(5, 14))

        info = ttk.Frame(outer)
        info.pack(fill="x", pady=(0, 12))
        self.network_var = tk.StringVar(value="Network: detecting…")
        ttk.Label(info, textvariable=self.network_var).pack(side="left", fill="x", expand=True)
        self.scan_button = ttk.Button(info, text="Scan home Wi-Fi", command=self.start_scan)
        self.scan_button.pack(side="right")

        columns = ("ip", "hostname", "mac", "vendor")
        self.table = ttk.Treeview(outer, columns=columns, show="headings", height=16)
        for col, label, width in [
            ("ip", "IP address", 140),
            ("hostname", "Device name / hostname", 260),
            ("mac", "MAC address", 190),
            ("vendor", "Manufacturer (if known)", 300),
        ]:
            self.table.heading(col, text=label)
            self.table.column(col, width=width, minwidth=90, anchor="w")
        self.table.pack(fill="both", expand=True)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))
        self.status_var = tk.StringVar(value="Ready. Scan only networks you own or have permission to inspect.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left", fill="x", expand=True)
        ttk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="right")
        self.devices = []
        self.network = None
        self.refresh_network_label()

    def refresh_network_label(self):
        try:
            iface, ip, network = get_local_network()
            self.network = network
            self.network_var.set(f"Interface: {iface}  •  Your IP: {ip}  •  Subnet: {network}")
        except Exception as exc:
            self.network_var.set("Network details unavailable")
            self.status_var.set(str(exc))

    def start_scan(self):
        if self.network is None:
            self.refresh_network_label()
        if self.network is None:
            messagebox.showerror("Network unavailable", self.status_var.get())
            return
        self.scan_button.configure(state="disabled")
        self.status_var.set(f"Scanning {self.network}…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            devices, mode = scan_devices(self.network)
            self.root.after(0, lambda: self.show_results(devices, mode))
        except Exception as exc:
            self.root.after(0, lambda err=str(exc): self.scan_failed(err))

    def show_results(self, devices, mode):
        self.devices = sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))
        for item in self.table.get_children():
            self.table.delete(item)
        for device in self.devices:
            self.table.insert("", "end", values=(
                device["ip"], device["hostname"], device["mac"] or "MAC unavailable", device["vendor"]
            ))
        self.scan_button.configure(state="normal")
        self.status_var.set(
            f"Scan complete: {len(self.devices)} device(s). Nmap mode: {mode}. "
            "If a name is unavailable, check your router's connected-device list."
        )

    def scan_failed(self, error):
        self.scan_button.configure(state="normal")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Scan failed", error)

    def export_csv(self):
        if not self.devices:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save scan results", defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")], initialfile="home-wifi-devices.csv"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ip", "hostname", "mac", "vendor"])
                writer.writeheader()
                writer.writerows(self.devices)
            self.status_var.set(f"Exported {len(self.devices)} device(s) to CSV.")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


def main():
    root = tk.Tk()
    NetScanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
