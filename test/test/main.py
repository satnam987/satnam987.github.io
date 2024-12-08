# main.py

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk
from scanner import scan_file
import threading
import os
import sys
import socket
import time
import logging
import queue

def resource_path(relative_path):
    """Bepaalt het absolute pad naar de resource, ongeacht of de app wordt gebundeld of niet."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class AntisecApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antisec")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        self.root.configure(bg="#1E1E1E")  # Donkergrijze achtergrond

        # Voeg applicatie icoon toe
        try:
            icon_path = resource_path("icon.ico")
            self.root.iconbitmap(icon_path)
        except Exception as e:
            logging.error(f"Icon niet gevonden: {e}")

        # Stijl configuratie
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Aangepaste stijl voor de Progressbar
        self.style.configure("Blue.Horizontal.TProgressbar",
                             troughcolor="#333333",
                             background="#00FFFF",
                             thickness=20)
        self.style.layout("Blue.Horizontal.TProgressbar",
                          [('Horizontal.Progressbar.trough',
                            {'children': [('Horizontal.Progressbar.pbar',
                                           {'side': 'left', 'sticky': 'ns'})],
                             'sticky': 'nswe'})])

        # Stijl voor knoppen
        self.style.configure("Accent.TButton",
                             foreground="#1E1E1E",
                             background="#00FFFF",
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0,
                             padding=10)
        self.style.map("Accent.TButton",
                       foreground=[('pressed', '#1E1E1E'), ('active', '#1E1E1E')],
                       background=[('pressed', '!disabled', '#00CCCC'),
                                   ('active', '#00CCCC')])

        # Stijl voor secundaire knoppen
        self.style.configure("Secondary.TButton",
                             foreground="#FFFFFF",
                             background="#FF4500",
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0,
                             padding=10)
        self.style.map("Secondary.TButton",
                       foreground=[('pressed', '#FFFFFF'), ('active', '#FFFFFF')],
                       background=[('pressed', '!disabled', '#E03E00'),
                                   ('active', '#E03E00')])

        # Stijl voor labels
        self.style.configure("TLabel",
                             foreground="#FFFFFF",  # Witte tekst
                             background="#1E1E1E",  # Donkergrijze achtergrond
                             font=("Segoe UI", 12))
        self.style.configure("Title.TLabel",
                             foreground="#00FFFF",  # Blauwe tekst voor titels
                             background="#1E1E1E",
                             font=("Segoe UI", 24, "bold"))

        # Nieuwe stijl voor hover-effecten
        self.style.configure("Hover.Accent.TButton",
                             foreground="#1E1E1E",
                             background="#00CCCC",
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0,
                             padding=10)
        self.style.map("Hover.Accent.TButton",
                       foreground=[('pressed', '#1E1E1E'), ('active', '#1E1E1E')],
                       background=[('pressed', '!disabled', '#009999'),
                                   ('active', '#009999')])

        self.style.configure("Hover.Secondary.TButton",
                             foreground="#FFFFFF",
                             background="#E03E00",
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0,
                             padding=10)
        self.style.map("Hover.Secondary.TButton",
                       foreground=[('pressed', '#FFFFFF'), ('active', '#FFFFFF')],
                       background=[('pressed', '!disabled', '#CC3300'),
                                   ('active', '#CC3300')])

        # **Toevoeging: Stijl voor Treeview met zwarte achtergrond**
        self.style.configure("Custom.Treeview",
                             background="#000000",
                             fieldbackground="#000000",
                             foreground="#FFFFFF",
                             font=("Segoe UI", 12))
        self.style.configure("Custom.Treeview.Heading",
                             background="#000000",
                             foreground="#FFFFFF",
                             font=("Segoe UI", 12, "bold"))

        self.create_menu()
        self.create_widgets()

        self.detailed_info_window = None
        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)

    def create_menu(self):
        menubar = tk.Menu(self.root, bg="#1E1E1E", fg="#FFFFFF")
        self.root.config(menu=menubar)

        help_menu = tk.Menu(menubar, tearoff=0, bg="#1E1E1E", fg="#FFFFFF")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Over Antisec", command=self.show_about)

    def show_about(self):
        messagebox.showinfo("Over Antisec",
                            "Antisec\nVersie 1.0\n© 2024 Antisec Inc.\n\nEen eenvoudig antivirusprogramma gemaakt met Python.")

    def create_widgets(self):
        # Hoofd Frame
        main_frame = tk.Frame(self.root, bg="#1E1E1E")
        main_frame.pack(fill='both', expand=True)

        # Zijbalk Frame
        sidebar_frame = tk.Frame(main_frame, bg="#2C2C2C", width=200)
        sidebar_frame.pack(side='left', fill='y')

        # Logo in zijbalk
        try:
            sidebar_logo_path = resource_path("sidebar_icon.png")
            sidebar_logo_image = Image.open(sidebar_logo_path)
            sidebar_logo_image = sidebar_logo_image.resize((60, 60), Image.LANCZOS)
            self.sidebar_logo = ImageTk.PhotoImage(sidebar_logo_image)
            sidebar_logo_label = ttk.Label(sidebar_frame, image=self.sidebar_logo, style="TLabel")
            sidebar_logo_label.pack(pady=(20, 5))  # Bovenaan met iets marge
        except FileNotFoundError:
            # Als het zijbalkicoon niet gevonden wordt, doen we niets
            pass

        # Toevoegen van het "Antisec" label op de zijbalk
        antisec_label = ttk.Label(sidebar_frame, text="Antisec", style="TLabel", font=("Segoe UI", 16, "bold"))
        antisec_label.pack(pady=(0, 20))  # Onder het logo met marge

        # Navigatie Knoppen in zijbalk
        nav_buttons = [
            {"text": "Bestand Selecteren", "command": self.browse_file, "style": "Accent.TButton"},
            {"text": "Scan Bestand", "command": self.scan_file_thread, "state": tk.DISABLED, "style": "Accent.TButton"},
            {"text": "Meer Info", "command": self.show_detailed_info, "state": tk.DISABLED, "style": "Secondary.TButton"}
        ]

        self.nav_buttons = {}
        for i, btn in enumerate(nav_buttons):
            button = ttk.Button(sidebar_frame, text=btn["text"], command=btn["command"], style=btn.get("style", "Accent.TButton"), state=btn.get("state", tk.NORMAL))
            button.pack(pady=10, padx=20, fill='x')
            button.bind("<Enter>", self.on_enter)
            button.bind("<Leave>", self.on_leave)
            self.nav_buttons[btn["text"]] = button

        # Content Frame
        content_frame = tk.Frame(main_frame, bg="#1E1E1E")
        content_frame.pack(side='left', fill='both', expand=True, padx=20, pady=20)

        # Verwijderen van het logo uit de hoofdinhoud
        # We hebben de volgende code uitgeschakeld om het logo niet meer in de hoofdinhoud te tonen

        # Header met gecentreerd logo
        header_frame = tk.Frame(content_frame, bg="#1E1E1E")
        header_frame.pack(pady=10)

        try:
            logo_path = resource_path("logo.png")
            logo_image = Image.open(logo_path)
            logo_image = logo_image.resize((250, 150), Image.LANCZOS)
            self.logo = ImageTk.PhotoImage(logo_image)
            logo_label = ttk.Label(header_frame, image=self.logo, style="Title.TLabel")
            logo_label.pack(pady=10)
        except FileNotFoundError:
            logo_label = ttk.Label(header_frame, text="Antisec", style="Title.TLabel")
            logo_label.pack(pady=10)

        # Bestandsselectie Frame
        file_frame = tk.LabelFrame(content_frame, text="Bestandsselectie", bg="#1E1E1E", fg="#00FFFF", font=("Segoe UI", 14, "bold"))
        file_frame.pack(fill='x', padx=10, pady=10)

        self.file_label = ttk.Label(file_frame, text="Geen bestand geselecteerd", wraplength=800, anchor="center", font=("Segoe UI", 12))
        self.file_label.pack(padx=10, pady=10)

        # Bestand selecteren knop met icoon
        browse_icon_path = resource_path("browse_icon.png")
        try:
            browse_icon_image = Image.open(browse_icon_path)
            browse_icon_image = browse_icon_image.resize((20, 20), Image.LANCZOS)
            self.browse_icon = ImageTk.PhotoImage(browse_icon_image)
            browse_button = ttk.Button(file_frame, text=" Bestand Selecteren", image=self.browse_icon, compound='left', command=self.browse_file, style="Accent.TButton")
        except FileNotFoundError:
            browse_button = ttk.Button(file_frame, text="Bestand Selecteren", command=self.browse_file, style="Accent.TButton")
        browse_button.pack(pady=10)
        browse_button.bind("<Enter>", self.on_enter)
        browse_button.bind("<Leave>", self.on_leave)

        # Scan knop met icoon (behouden in content_frame)
        scan_icon_path = resource_path("scan_icon.png")
        try:
            scan_icon_image = Image.open(scan_icon_path)
            scan_icon_image = scan_icon_image.resize((20, 20), Image.LANCZOS)
            self.scan_icon = ImageTk.PhotoImage(scan_icon_image)
            scan_button = ttk.Button(content_frame, text=" Scan Bestand", image=self.scan_icon, compound='left', command=self.scan_file_thread, state=tk.DISABLED, style="Accent.TButton")
        except FileNotFoundError:
            scan_button = ttk.Button(content_frame, text="Scan Bestand", command=self.scan_file_thread, state=tk.DISABLED, style="Accent.TButton")
        scan_button.pack(pady=10)
        scan_button.bind("<Enter>", self.on_enter)
        scan_button.bind("<Leave>", self.on_leave)
        self.nav_buttons["Scan Bestand"] = scan_button  # Update navigatie knop

        # Progress Bar met Label
        progress_frame = tk.Frame(content_frame, bg="#1E1E1E")
        progress_frame.pack(pady=10)

        self.progress_label = ttk.Label(progress_frame, text="", font=("Segoe UI", 10), foreground="#00FFFF", background="#1E1E1E")
        self.progress_label.pack(pady=5)

        self.progress = ttk.Progressbar(progress_frame, style="Blue.Horizontal.TProgressbar", orient='horizontal', mode='indeterminate', length=1000)
        self.progress.pack(pady=5)

        # Samenvatting van Resultaten
        summary_frame = tk.LabelFrame(content_frame, text="Samenvatting van Resultaten", bg="#1E1E1E", fg="#FF4500", font=("Segoe UI", 14, "bold"))
        summary_frame.pack(fill='x', padx=10, pady=10)

        # Gebruik grid voor betere positionering
        self.malicious_label = ttk.Label(summary_frame, text="Malicious: N/A", font=("Segoe UI", 12, "bold"), foreground="#FF0000")
        self.malicious_label.grid(row=0, column=0, sticky='w', padx=30, pady=5)

        self.suspicious_label = ttk.Label(summary_frame, text="Suspicious: N/A", font=("Segoe UI", 12, "bold"), foreground="#FFA500")
        self.suspicious_label.grid(row=0, column=1, sticky='w', padx=30, pady=5)

        self.harmless_label = ttk.Label(summary_frame, text="Harmless: N/A", font=("Segoe UI", 12, "bold"), foreground="#00FFFF")
        self.harmless_label.grid(row=1, column=0, sticky='w', padx=30, pady=5)

        self.undetected_label = ttk.Label(summary_frame, text="Undetected: N/A", font=("Segoe UI", 12, "bold"), foreground="#FFFFFF")
        self.undetected_label.grid(row=1, column=1, sticky='w', padx=30, pady=5)

    def on_enter(self, event):
        if "Accent" in event.widget['style']:
            event.widget.configure(style="Hover.Accent.TButton")
        elif "Secondary" in event.widget['style']:
            event.widget.configure(style="Hover.Secondary.TButton")

    def on_leave(self, event):
        if "Accent" in event.widget['style']:
            event.widget.configure(style="Accent.TButton")
        elif "Secondary" in event.widget['style']:
            event.widget.configure(style="Secondary.TButton")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            display_path = file_path if len(file_path) < 60 else "..." + file_path[-57:]
            self.file_label.config(text=display_path)
            self.nav_buttons["Scan Bestand"].config(state=tk.NORMAL)

    def scan_file_thread(self):
        # Gebruik threading om de GUI niet te blokkeren tijdens het scannen
        thread = threading.Thread(target=self.perform_scan, daemon=True)
        thread.start()

    def perform_scan(self):
        logging.info("Start scan voor bestand: " + self.selected_file)
        self.queue.put({'action': 'disable_scan_button'})
        self.queue.put({'action': 'start_progress'})  # Start de voortgangsbalk

        result = scan_file(self.selected_file)
        self.queue.put({'action': 'update_summary', 'data': result})

        if "detailed" in result and result["detailed"].get("security_vendors"):
            self.queue.put({'action': 'enable_more_info'})
        self.queue.put({'action': 'enable_scan_button'})
        self.queue.put({'action': 'stop_progress'})  # Stop de voortgangsbalk
        logging.info("Scan voltooid voor bestand: " + self.selected_file)

    def process_queue(self):
        try:
            while True:
                task = self.queue.get_nowait()
                action = task.get('action')

                if action == 'disable_scan_button':
                    self.nav_buttons["Scan Bestand"].config(state=tk.DISABLED)
                elif action == 'start_progress':
                    self.progress.start(10)  # Start animatie met interval van 10 ms
                    self.progress_label.config(text="Scan bezig...")
                elif action == 'stop_progress':
                    self.progress.stop()  # Stop animatie
                    self.progress_label.config(text="Scan voltooid.")
                elif action == 'update_summary':
                    self.update_summary(task.get('data'))
                elif action == 'enable_more_info':
                    self.nav_buttons["Meer Info"].config(state=tk.NORMAL)
                elif action == 'enable_scan_button':
                    self.nav_buttons["Scan Bestand"].config(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def update_summary(self, result):
        if "error" in result:
            self.malicious_label.config(text=f"Fout: {result['error']}", foreground="#FF0000")
            self.suspicious_label.config(text="")
            self.harmless_label.config(text="")
            self.undetected_label.config(text="")
        elif "info" in result:
            self.malicious_label.config(text=f"Info: {result['info']}", foreground="#00FFFF")
            self.suspicious_label.config(text="")
            self.harmless_label.config(text="")
            self.undetected_label.config(text="")
        else:
            self.malicious_label.config(text=f"Malicious: {result.get('malicious', 0)}", foreground="#FF0000")
            self.suspicious_label.config(text=f"Suspicious: {result.get('suspicious', 0)}", foreground="#FFA500")
            self.harmless_label.config(text=f"Harmless: {result.get('harmless', 0)}", foreground="#00FFFF")
            self.undetected_label.config(text=f"Undetected: {result.get('undetected', 0)}", foreground="#FFFFFF")
            self.last_scan_results = result.get('detailed', {})

    def show_detailed_info(self):
        if not hasattr(self, 'last_scan_results'):
            messagebox.showinfo("Meer Info", "Geen gedetailleerde informatie beschikbaar.")
            return

        if self.detailed_info_window and tk.Toplevel.winfo_exists(self.detailed_info_window):
            self.detailed_info_window.focus()
            return

        self.detailed_info_window = tk.Toplevel(self.root)
        self.detailed_info_window.title("Gedetailleerde Scan Informatie")
        self.detailed_info_window.geometry("900x700")
        self.detailed_info_window.configure(bg="#000000")  # **Zwarte achtergrond**

        # Gebruik Notebook voor tabbladen
        notebook = ttk.Notebook(self.detailed_info_window)
        notebook.pack(expand=True, fill='both')

        # Tab: Security Vendors' Analysis
        vendors_frame = ttk.Frame(notebook)
        notebook.add(vendors_frame, text="Security Vendors' Analysis")

        # Gebruik Treeview voor een tabelachtige weergave
        vendors_tree = ttk.Treeview(vendors_frame, columns=("Vendor", "Resultaat"), show='headings', selectmode='none', style="Custom.Treeview")
        vendors_tree.heading("Vendor", text="Beveiligingsleverancier")
        vendors_tree.heading("Resultaat", text="Resultaat")
        vendors_tree.column("Vendor", width=250, anchor='center')
        vendors_tree.column("Resultaat", width=600, anchor='w')
        vendors_tree.pack(expand=True, fill='both', padx=10, pady=10)

        # Voeg een Scrollbar toe aan de Treeview
        scrollbar = ttk.Scrollbar(vendors_frame, orient="vertical", command=vendors_tree.yview)
        vendors_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Voeg gegevens toe aan de Treeview
        vendors_analysis = self.extract_vendors_analysis()
        if vendors_analysis:
            for vendor, analysis in vendors_analysis.items():
                vendors_tree.insert('', 'end', values=(vendor, analysis))
        else:
            vendors_tree.insert('', 'end', values=("Geen beveiligingsleveranciers gevonden.", "N/A"))

        # Definieer tags voor kleurcodering
        for item in vendors_tree.get_children():
            resultaat = vendors_tree.item(item, 'values')[1].lower()
            if "virus" in resultaat or "malware" in resultaat:
                vendors_tree.item(item, tags=('malicious',))
            elif "test" in resultaat:
                vendors_tree.item(item, tags=('test',))
            else:
                vendors_tree.item(item, tags=('neutral',))

        vendors_tree.tag_configure('malicious', foreground='#FF0000')  # Rood voor malware
        vendors_tree.tag_configure('test', foreground='#FFA500')       # Oranje voor test
        vendors_tree.tag_configure('neutral', foreground='#00FFFF')    # Blauw voor neutraal

        # Voeg zoekfunctionaliteit toe
        search_frame = tk.Frame(vendors_frame, bg="#000000")  # **Zwarte achtergrond**
        search_frame.pack(pady=5, padx=10, fill='x')

        search_label = ttk.Label(search_frame, text="Zoeken:", foreground="#FFFFFF", background="#000000", font=("Segoe UI", 10))
        search_label.pack(side='left', padx=(0, 5))

        search_entry = ttk.Entry(search_frame, font=("Segoe UI", 10))
        search_entry.pack(side='left', fill='x', expand=True)

        def search_vendors(event=None):
            query = search_entry.get().lower()
            found = False
            for item in vendors_tree.get_children():
                vendor = vendors_tree.item(item, 'values')[0].lower()
                if query in vendor:
                    vendors_tree.selection_set(item)
                    vendors_tree.focus(item)
                    vendors_tree.see(item)
                    found = True
                    break
            if not found:
                messagebox.showinfo("Zoeken", "Geen resultaten gevonden.")

        search_entry.bind("<Return>", search_vendors)

        search_button = ttk.Button(search_frame, text="Zoeken", command=search_vendors, style="Secondary.TButton")
        search_button.pack(side='left', padx=(5, 0))
        search_button.bind("<Enter>", lambda e: search_button.configure(style="Hover.Secondary.TButton"))
        search_button.bind("<Leave>", lambda e: search_button.configure(style="Secondary.TButton"))

        # Sorteerfunctie voor Treeview
        def treeview_sort_column(tv, col, reverse):
            l = [(tv.set(k, col), k) for k in tv.get_children('')]
            try:
                l.sort(key=lambda x: int(x[0].split(':')[0]), reverse=reverse)
            except ValueError:
                l.sort(reverse=reverse)
            for index, (val, k) in enumerate(l):
                tv.move(k, '', index)
            tv.heading(col, command=lambda: treeview_sort_column(tv, col, not reverse))

        vendors_tree.heading("Vendor", text="Beveiligingsleverancier", command=lambda: treeview_sort_column(vendors_tree, "Vendor", False))
        vendors_tree.heading("Resultaat", text="Resultaat", command=lambda: treeview_sort_column(vendors_tree, "Resultaat", False))

    def extract_vendors_analysis(self):
        """
        Extract security vendors' analysis from the detailed scan results.
        """
        vendors_analysis = {}
        analysis = self.last_scan_results.get('security_vendors', {})
        for vendor, result in analysis.items():
            vendors_analysis[vendor] = result
        logging.debug(f"Extracted Security Vendors Analysis: {vendors_analysis}")
        return vendors_analysis

    @staticmethod
    def check_single_instance():
        # Gebruik een socket om te controleren of er al een instantie draait
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("localhost", 9999))
        except socket.error:
            return False
        return True

if __name__ == "__main__":
    # Logging configuratie
    logging.basicConfig(filename='main.log', level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    if not AntisecApp.check_single_instance():
        temp_root = tk.Tk()
        temp_root.withdraw()
        messagebox.showerror("Antisec", "Er draait al een instantie van Antisec.")
        temp_root.destroy()
        sys.exit(0)

    root = tk.Tk()
    app = AntisecApp(root)
    root.mainloop()
