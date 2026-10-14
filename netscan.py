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
