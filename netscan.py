#!/usr/bin/env python3
"""Home Wi-Fi device scanner. Scans only the local network interface's subnet."""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import subprocess
import xml.etree.ElementTree as ET


def scan_devices(subnet):
    """Discover devices and their available identification details."""
    result = subprocess.run(
        ["nmap", "-sn", "-R", "-oX", "-", subnet],
        capture_output=True,
        text=True,
        timeout=120,
        check=True
    )

    root = ET.fromstring(result.stdout)
    devices = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        manufacturer = "Unknown"
        hostname = "Unknown"

        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr")
                manufacturer = (
                    address.get("vendor") or "Unknown"
                )

        names = host.find("hostnames")
        if names is not None:
            for entry in names.findall("hostname"):
                name = entry.get("name")
                if name:
                    hostname = name
                    break

        if ip:
            devices.append({
                "ip": ip,
                "hostname": hostname,
                "mac": mac or "Not reported",
                "manufacturer": manufacturer
            })

    return devices

try:
    import netifaces
except ImportError:
    netifaces = None


APP_TITLE = "Home Wi-Fi NetScan"


def get_local_network():
    """Return (interface, local_ip, subnet) using the OS interface configuration."""
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
            ip = addr.get("addr")
            mask = addr.get("netmask")
            if not ip or not mask or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            candidates.append((iface, ip, network))

    if not candidates and preferred_iface:
        # Fall back to another active IPv4 interface if the default route has no usable address.
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip, mask = addr.get("addr"), addr.get("netmask")
                if ip and mask and not ip.startswith(("127.", "169.254.")):
                    try:
                        candidates.append((iface, ip, ipaddress.ip_network(f"{ip}/{mask}", strict=False)))
                    except ValueError:
                        pass
    if not candidates:
        raise RuntimeError("Could not detect an active IPv4 network. Connect to your home Wi-Fi and try again.")
    return candidates[0]


def scan_with_nmap(network):
    """Run a host-discovery scan and parse nmap's normal output."""
    if not shutil.which("nmap"):
        raise RuntimeError(
            "Nmap is not installed.\n\nmacOS: brew install nmap\nWindows: install Nmap from nmap.org\nLinux: use your package manager (for example, sudo apt install nmap)"
        )

    # -sn performs host discovery only; it does not run a port scan.
    # -R requests reverse-DNS resolution; --reason is omitted to keep parsing simple.
    cmd = ["nmap", "-sn", "-PR", "-R", str(network)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if result.returncode not in (0,):
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Nmap scan failed.\n{detail or 'No error details were returned.'}")

    devices = []
    current = None
    for line in result.stdout.splitlines():
        host_match = re.match(r"Nmap scan report for (.+)$", line.strip())
        if host_match:
            if current and current.get("ip"):
                devices.append(current)
            host_text = host_match.group(1).strip()
            ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)$", host_text)
            if ip_match:
                hostname, ip = host_text[:ip_match.start()].strip(), ip_match.group(1)
            else:
                hostname, ip = "", host_text
            current = {"ip": ip, "hostname": hostname, "mac": "", "vendor": ""}
            continue

        if current:
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?", line)
            if mac_match:
                current["mac"] = mac_match.group(1).upper()
                current["vendor"] = mac_match.group(2) or ""

    if current and current.get("ip"):
        devices.append(current)

    # Add a friendly name if Nmap has no reverse-DNS hostname.
    for device in devices:
        if not device["hostname"]:
            try:
                device["hostname"] = socket.gethostbyaddr(device["ip"])[0]
            except (socket.herror, socket.gaierror, OSError):
                device["hostname"] = "Unknown"
    return devices


class NetScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("920x570")
        self.root.minsize(720, 420)

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
            text="Discover devices on your own local network. Hostnames and device manufacturers may not be available for every device.",
            wraplength=850,
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
            ("hostname", "Device / hostname", 220),
            ("mac", "MAC address", 180),
            ("vendor", "Manufacturer (if known)", 260),
        ]:
            self.table.heading(col, text=label)
            self.table.column(col, width=width, minwidth=90, anchor="w")
        self.table.pack(fill="both", expand=True)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))
        self.status_var = tk.StringVar(value="Ready. Connect to your home Wi-Fi, then scan.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left", fill="x", expand=True)
        ttk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="right")

        self.devices = []
        self.network = None
        self.refresh_network_label()

    def refresh_network_label(self):
        try:
            iface, ip, network = get_local_network()
            self.network = network
            self.network_var.set(f"Wi-Fi/network interface: {iface}  •  Your IP: {ip}  •  Subnet: {network}")
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
        self.status_var.set(f"Scanning {self.network} for responding devices…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            devices = scan_with_nmap(self.network)
            self.root.after(0, lambda: self.show_results(devices))
        except Exception as exc:
            self.root.after(0, lambda err=str(exc): self.scan_failed(err))

    def show_results(self, devices):
        self.devices = devices
        for item in self.table.get_children():
            self.table.delete(item)
        for device in sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"])):
            self.table.insert("", "end", values=(
                device["ip"], device["hostname"], device["mac"] or "Not reported",
                device["vendor"] or "Not reported"
            ))
        self.scan_button.configure(state="normal")
        self.status_var.set(f"Scan complete: {len(devices)} responding device(s) found. Some devices may not identify themselves.")

    def scan_failed(self, error):
        self.scan_button.configure(state="normal")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Scan failed", error)

    def export_csv(self):
        if not self.devices:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        from tkinter import filedialog
        import csv
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
