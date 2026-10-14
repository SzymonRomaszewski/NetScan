
#!/usr/bin/env python3
"""Home Wi-Fi device scanner for your local network."""

from __future__ import annotations

import csv
import ipaddress
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from tkinter import messagebox, ttk, filedialog

try:
    import netifaces
except ImportError:
    netifaces = None

APP_TITLE = "Home Wi-Fi NetScan"


def get_local_network():
    """Return the active interface, local IPv4 address and subnet."""
    if netifaces is None:
        raise RuntimeError(
            "Missing dependency. Run:\n"
            "python3 -m pip install netifaces zeroconf"
        )

    gateways = netifaces.gateways()
    default = gateways.get("default", {}).get(netifaces.AF_INET)
    preferred_iface = default[1] if default else None

    candidates = []

    for iface in netifaces.interfaces():
        if preferred_iface and iface != preferred_iface:
            continue

        for addr in netifaces.ifaddresses(iface).get(
            netifaces.AF_INET, []
        ):
            ip = addr.get("addr")
            mask = addr.get("netmask")

            if (
                not ip
                or not mask
                or ip.startswith(("127.", "169.254."))
            ):
                continue

            try:
                network = ipaddress.ip_network(
                    f"{ip}/{mask}", strict=False
                )
                candidates.append((iface, ip, network))
            except ValueError:
                continue

    if not candidates and preferred_iface:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(
                netifaces.AF_INET, []
            ):
                ip = addr.get("addr")
                mask = addr.get("netmask")

                if (
                    not ip
                    or not mask
                    or ip.startswith(("127.", "169.254."))
                ):
                    continue

                try:
                    network = ipaddress.ip_network(
                        f"{ip}/{mask}", strict=False
                    )
                    candidates.append((iface, ip, network))
                except ValueError:
                    continue

    if not candidates:
        raise RuntimeError(
            "Could not detect an active IPv4 network. "
            "Connect to your home Wi-Fi and try again."
        )

    return candidates[0]


def discover_bonjour_names():
    """Discover device/service names advertised using Bonjour or mDNS."""
    names = {}

    try:
        from zeroconf import Zeroconf, ServiceBrowser

        class Listener:
            def add_service(self, zc, service_type, name):
                try:
                    info = zc.get_service_info(
                        service_type, name, timeout=1500
                    )
                    if info is None:
                        return

                    service_name = name.split(".")[0].strip()
                    if not service_name:
                        return

                    for address in info.parsed_addresses():
                        if ":" not in address:
                            names.setdefault(address, service_name)

                except Exception:
                    pass

            def update_service(self, zc, service_type, name):
                self.add_service(zc, service_type, name)

            def remove_service(self, zc, service_type, name):
                pass

        service_types = [
            "_device-info._tcp.local.",
            "_companion-link._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_googlecast._tcp.local.",
            "_workstation._tcp.local.",
            "_smb._tcp.local.",
            "_ipp._tcp.local.",
            "_http._tcp.local.",
            "_ssh._tcp.local.",
        ]

        zeroconf = Zeroconf()
        browsers = []

        try:
            listener = Listener()

            for service_type in service_types:
                try:
                    browsers.append(
                        ServiceBrowser(
                            zeroconf, service_type, listener
                        )
                    )
                except Exception:
                    continue

            # Allow a short time for local services to respond.
            time.sleep(3)

        finally:
            zeroconf.close()

    except ImportError:
        pass
    except Exception:
        pass

    return names


def scan_with_nmap(network):
    """Discover responding devices and their available identifying details."""
    if not shutil.which("nmap"):
        raise RuntimeError(
            "Nmap is not installed.\n\n"
            "macOS: brew install nmap\n"
            "Windows: install Nmap from nmap.org\n"
            "Linux: install Nmap using your package manager."
        )

    # Host discovery only: this does not scan device ports.
    # XML output makes host, IP and MAC parsing more reliable.
    command = [
        "nmap",
        "-sn",
        "-PR",
        "-R",
        "-oX",
        "-",
        str(network),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "The scan timed out. Check your Wi-Fi and try again."
        )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"Nmap scan failed:\n"
            f"{detail or 'No error details were returned.'}"
        )

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        raise RuntimeError(
            "Could not read Nmap's scan results."
        )

    devices = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        device = {
            "ip": "",
            "hostname": "Unknown",
            "mac": "",
            "vendor": "",
        }

        # Read IP addresses and MAC/vendor details from Nmap XML.
        for address in host.findall("address"):
            address_type = address.get("addrtype")
            value = address.get("addr", "")

            if address_type == "ipv4":
                device["ip"] = value

            elif address_type == "mac":
                device["mac"] = value.upper()
                device["vendor"] = address.get("vendor", "")

        # Use the hostname Nmap discovers through DNS.
        hostnames = host.find("hostnames")

        if hostnames is not None:
            for entry in hostnames.findall("hostname"):
                name = entry.get("name", "").strip()

                if name:
                    device["hostname"] = name
                    break

        # Try a reverse-DNS lookup if Nmap didn't supply a name.
        if device["ip"] and device["hostname"] == "Unknown":
            try:
                hostname = socket.gethostbyaddr(
                    device["ip"]
                )[0]

                if hostname:
                    device["hostname"] = hostname

            except (socket.herror, socket.gaierror, OSError):
                pass

        if device["ip"]:
            devices.append(device)

    # Discover additional names advertised on the local network.
    bonjour_names = discover_bonjour_names()

    for device in devices:
        if device["hostname"] == "Unknown":
            name = bonjour_names.get(device["ip"])

            if name:
                device["hostname"] = name

    return devices


class NetScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1000x600")
        self.root.minsize(760, 420)

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="Home Wi-Fi NetScan",
            font=("Arial", 22, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            outer,
            text=(
                "Discover devices on your local network. "
                "Names and manufacturers depend on the information "
                "each device and your network make available."
            ),
            wraplength=920,
        ).pack(anchor="w", pady=(5, 14))

        info = ttk.Frame(outer)
        info.pack(fill="x", pady=(0, 12))

        self.network_var = tk.StringVar(
            value="Network: detecting..."
        )

        ttk.Label(
            info,
            textvariable=self.network_var,
        ).pack(side="left", fill="x", expand=True)

        self.scan_button = ttk.Button(
            info,
            text="Scan home Wi-Fi",
            command=self.start_scan,
        )
        self.scan_button.pack(side="right")

        columns = ("ip", "hostname", "mac", "vendor")

        self.table = ttk.Treeview(
            outer,
            columns=columns,
            show="headings",
            height=16,
        )

        for column, label, width in [
            ("ip", "IP address", 140),
            ("hostname", "Device / hostname", 250),
            ("mac", "MAC address", 190),
            ("vendor", "Manufacturer (if known)", 300),
        ]:
            self.table.heading(column, text=label)
            self.table.column(
                column,
                width=width,
                minwidth=90,
                anchor="w",
            )

        self.table.pack(fill="both", expand=True)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))

        self.status_var = tk.StringVar(
            value="Ready. Connect to your home Wi-Fi, then scan."
        )

        ttk.Label(
            bottom,
            textvariable=self.status_var,
        ).pack(side="left", fill="x", expand=True)

        ttk.Button(
            bottom,
            text="Export CSV",
            command=self.export_csv,
        ).pack(side="right")

        self.devices = []
        self.network = None

        self.refresh_network_label()

    def refresh_network_label(self):
        try:
            iface, ip, network = get_local_network()
            self.network = network

            self.network_var.set(
                f"Interface: {iface}  •  Your IP: {ip}  "
                f"•  Subnet: {network}"
            )

        except Exception as exc:
            self.network = None
            self.network_var.set("Network details unavailable")
            self.status_var.set(str(exc))

    def start_scan(self):
        if self.network is None:
            self.refresh_network_label()

        if self.network is None:
            messagebox.showerror(
                "Network unavailable",
                self.status_var.get(),
            )
            return

        self.scan_button.configure(state="disabled")
        self.status_var.set(
            f"Scanning {self.network} for responding devices..."
        )

        threading.Thread(
            target=self._scan_worker,
            daemon=True,
        ).start()

    def _scan_worker(self):
        try:
            devices = scan_with_nmap(self.network)

            self.root.after(
                0,
                lambda results=devices: self.show_results(results),
            )

        except Exception as exc:
            error = str(exc)

            self.root.after(
                0,
                lambda err=error: self.scan_failed(err),
            )

    def show_results(self, devices):
        self.devices = devices

        for item in self.table.get_children():
            self.table.delete(item)

        for device in sorted(
            devices,
            key=lambda item: ipaddress.ip_address(item["ip"]),
        ):
            self.table.insert(
                "",
                "end",
                values=(
                    device["ip"],
                    device["hostname"],
                    device["mac"] or "Not reported",
                    device["vendor"] or "Not reported",
                ),
            )

        self.scan_button.configure(state="normal")

        self.status_var.set(
            f"Scan complete: {len(devices)} responding device(s) found. "
            "Some devices may not disclose identifying information."
        )

    def scan_failed(self, error):
        self.scan_button.configure(state="normal")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Scan failed", error)

    def export_csv(self):
        if not self.devices:
            messagebox.showinfo(
                "Nothing to export",
                "Run a scan first.",
            )
            return

        path = filedialog.asksaveasfilename(
            title="Save scan results",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="home-wifi-devices.csv",
        )

        if not path:
            return

        try:
            with open(
                path,
                "w",
                newline="",
                encoding="utf-8",
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "ip",
                        "hostname",
                        "mac",
                        "vendor",
                    ],
                )

                writer.writeheader()
                writer.writerows(self.devices)

            self.status_var.set(
                f"Exported {len(self.devices)} device(s) to CSV."
            )

        except OSError as exc:
            messagebox.showerror(
                "Export failed",
                str(exc),
            )


def main():
    root = tk.Tk()
    NetScanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
