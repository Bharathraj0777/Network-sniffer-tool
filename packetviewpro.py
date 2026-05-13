

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import queue
import time
import csv
from collections import Counter
from PIL import Image, ImageTk

try:
    import psutil
    from PIL import Image, ImageTk
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, wrpcap
except Exception:
    raise SystemExit("Install modules:\npip install scapy psutil pillow")


class PacketViewPro:
    def __init__(self, root):
        self.root = root
        self.root.title("PacketView Pro - Final Professional Edition")
        self.root.geometry("1550x900")
        self.root.configure(bg="#f4f6f8")

        self.packet_queue = queue.Queue()
        self.running = False

        self.ids_enabled = tk.BooleanVar(value=True)
        self.protocol_filter = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar()
        self.interface_var = tk.StringVar()

        self.rows = []
        self.filtered_rows = []
        self.raw_packets = []
        self.stats = Counter()
        self.interface_map = {}

        self.logo_img = None
        try:
            img = Image.open("logo.png")
            img = img.resize((180, 110))
            self.logo_img = ImageTk.PhotoImage(img)
        except:
            pass

        self.setup_style()
        self.build_ui()
        self.load_interfaces()

        self.root.after(150, self.process_packets)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background="#f4f6f8", foreground="black")
        style.configure("Treeview", rowheight=25)
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 10, "bold"),
            background="#dbeafe"
        )
        style.configure(
            "Big.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=8
        )

    def build_ui(self):

        if self.logo_img:
            tk.Label(
                self.root,
                image=self.logo_img,
                bg="#f4f6f8"
            ).pack(pady=(8, 2))

        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Interface").pack(side="left")

        self.interface_combo = ttk.Combobox(
            top,
            textvariable=self.interface_var,
            width=22,
            state="readonly"
        )
        self.interface_combo.pack(side="left", padx=5)

        ttk.Button(
            top,
            text="▶ Start Capture",
            style="Big.TButton",
            command=self.start_capture
        ).pack(side="left", padx=4)

        ttk.Button(
            top,
            text="■ Stop Capture",
            style="Big.TButton",
            command=self.stop_capture
        ).pack(side="left", padx=4)

        ttk.Button(
            top,
            text="💾 Export CSV",
            style="Big.TButton",
            command=self.export_csv
        ).pack(side="left", padx=4)

        ttk.Button(
            top,
            text="💾 Export PCAP",
            style="Big.TButton",
            command=self.export_pcap
        ).pack(side="left", padx=4)

        ttk.Button(
            top,
            text="ℹ Project Info",
            style="Big.TButton",
            command=self.show_project_info
        ).pack(side="left", padx=4)

        ttk.Checkbutton(
            top,
            text="IDS ON / OFF",
            variable=self.ids_enabled
        ).pack(side="left", padx=12)

        ttk.Label(top, text="Protocol").pack(side="left", padx=(10, 4))

        self.protocol_combo = ttk.Combobox(
            top,
            textvariable=self.protocol_filter,
            width=12,
            state="readonly",
            values=[
                "ALL", "TCP", "UDP", "ICMP",
                "DNS", "ARP", "HTTP", "HTTPS"
            ]
        )
        self.protocol_combo.current(0)
        self.protocol_combo.pack(side="left")

        ttk.Button(
            top,
            text="Apply Filter",
            command=self.apply_filters
        ).pack(side="left", padx=5)

        ttk.Label(top, text="Search").pack(side="right", padx=(8, 0))

        self.search_entry = ttk.Entry(
            top,
            textvariable=self.search_var,
            width=28
        )
        self.search_entry.pack(side="right")

        self.stats_label = tk.StringVar()
        self.stats_label.set("Packets: 0")

        ttk.Label(
            self.root,
            textvariable=self.stats_label,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=10)

        columns = (
            "time", "src", "dst", "proto",
            "sport", "dport", "size", "alert"
        )

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=8)

        self.tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=140)

        self.tree.column("alert", width=220)

        self.tree.tag_configure("TCP", background="#e0f2fe")
        self.tree.tag_configure("UDP", background="#dcfce7")
        self.tree.tag_configure("ICMP", background="#fef9c3")
        self.tree.tag_configure("DNS", background="#ede9fe")
        self.tree.tag_configure("ARP", background="#ffe4e6")
        self.tree.tag_configure("ALERT", background="#fecaca")

        self.tree.bind("<<TreeviewSelect>>", self.show_payload)

        self.payload = ScrolledText(
            self.root,
            height=10,
            font=("Consolas", 10)
        )
        self.payload.pack(fill="x", padx=10, pady=(0, 10))

    def load_interfaces(self):
        names = psutil.net_if_addrs().keys()
        labels = []

        for name in names:
            low = name.lower()

            if "wifi" in low or "wi-fi" in low or "wlan" in low:
                label = "Wi-Fi"
            elif "ethernet" in low:
                label = "Ethernet"
            elif "loopback" in low:
                label = "Loopback"
            else:
                label = name

            self.interface_map[label] = name
            labels.append(label)

        if not labels:
            labels = ["Default"]

        self.interface_combo["values"] = labels
        self.interface_combo.current(0)

    def start_capture(self):
        if self.running:
            return

        self.running = True

        threading.Thread(
            target=self.capture_packets,
            daemon=True
        ).start()

    def stop_capture(self):
        self.running = False

    def capture_packets(self):
        iface = self.interface_map.get(
            self.interface_var.get(),
            None
        )

        try:
            sniff(
                iface=iface,
                store=False,
                prn=lambda p: self.packet_queue.put(p),
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.running = False
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Capture Error",
                    str(e)
                )
            )

    def process_packets(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            self.handle_packet(pkt)

        self.root.after(150, self.process_packets)

    def handle_packet(self, pkt):
        row = self.extract_packet(pkt)

        if row is None:
            return

        self.rows.append(row)
        self.raw_packets.append(pkt)

        self.apply_filters()

    def extract_packet(self, pkt):
        now = time.strftime("%H:%M:%S")

        src = ""
        dst = ""
        sport = ""
        dport = ""
        proto = "OTHER"
        alert = ""
        size = len(pkt)

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            if dport == 80 or sport == 80:
                proto = "HTTP"
            elif dport == 443 or sport == 443:
                proto = "HTTPS"

        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        elif ICMP in pkt:
            proto = "ICMP"

        elif ARP in pkt:
            proto = "ARP"
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst

        if DNS in pkt:
            proto = "DNS"

        if self.ids_enabled.get():
            risky = {21, 22, 23, 3389, 4444, 5555}

            if str(dport).isdigit() and int(dport) in risky:
                alert = "Sensitive Port Access"
            elif size > 1400:
                alert = "Large Packet Burst"

        self.stats[proto] += 1

        return (
            now, src, dst, proto,
            sport, dport, size, alert
        )

    def apply_filters(self):
        self.tree.delete(*self.tree.get_children())

        selected_proto = self.protocol_filter.get()
        search = self.search_var.get().strip().lower()

        self.filtered_rows = []

        for row in self.rows:
            proto = row[3]

            if selected_proto != "ALL" and proto != selected_proto:
                continue

            text = " ".join(map(str, row)).lower()

            if search and search not in text:
                continue

            self.filtered_rows.append(row)

        for row in reversed(self.filtered_rows):
            tag = "ALERT" if row[7] else row[3]

            self.tree.insert(
                "",
                "end",
                values=row,
                tags=(tag,)
            )

        alerts = sum(1 for r in self.rows if r[7])

        self.stats_label.set(
            f"Packets: {len(self.rows)} | "
            f"Showing: {len(self.filtered_rows)} | "
            f"Alerts: {alerts}"
        )

    def export_csv(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )

        if not file:
            return

        with open(file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            writer.writerow([
                "Time", "Source", "Destination",
                "Protocol", "Src Port", "Dst Port",
                "Size", "Alert"
            ])

            for row in self.filtered_rows:
                writer.writerow(row)

        messagebox.showinfo("Export", "CSV exported successfully")

    def export_pcap(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap")]
        )

        if not file:
            return

        wrpcap(file, self.raw_packets)
        messagebox.showinfo("Export", "PCAP exported successfully")

    def show_project_info(self):
        win = tk.Toplevel(self.root)
        win.title("Project Info")
        win.geometry("700x520")
        win.configure(bg="white")
        win.resizable(False, False)

        tk.Label(
            win,
            text="SUPRAJA TECHNOLOGIES INTERN PROJECT",
            font=("Segoe UI", 15, "bold"),
            bg="white",
            fg="#003366"
        ).pack(pady=15)

        tk.Label(
            win,
            text="Project Name:\nPacketView Pro (Network Packet Sniffer Tool)",
            font=("Segoe UI", 11, "bold"),
            bg="white",
            justify="left"
        ).pack(anchor="w", padx=25, pady=8)

        info = """
Developed By:

1. Bharathu Raj R
   EMP ID : ST#IS#8807
   Email  : bharathuraj.r@gmail.com

2. Mohammad Anish B
   EMP ID : ST#IS#8806
   Email  : mohammedanish718@gmail.com

3. Sujey Priyan S
   EMP ID : ST#IS#8805
   Email  : chikkiboy05@gmail.com
"""

        tk.Label(
            win,
            text=info,
            font=("Segoe UI", 11),
            bg="white",
            justify="left"
        ).pack(anchor="w", padx=25, pady=10)

        ttk.Button(
            win,
            text="Close",
            command=win.destroy
        ).pack(pady=18)

    def show_payload(self, event=None):
        selected = self.tree.selection()

        if not selected:
            return

        values = self.tree.item(selected[0], "values")

        self.payload.delete("1.0", "end")
        self.payload.insert("end", str(values) + "\n\n")


if __name__ == "__main__":
    root = tk.Tk()

    import os
    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")

    img = Image.open(logo_path)
    icon = ImageTk.PhotoImage(img)
    root.iconphoto(True, icon)

    app = PacketViewPro(root)
    root.mainloop()