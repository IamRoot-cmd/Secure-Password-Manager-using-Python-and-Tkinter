import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import os
import json
import csv
from cryptography.fernet import Fernet

CRED_FILE = "credentials.enc"
KEY_FILE = "vault.key"
MASTER_PASSWORD = "admin123"  # You can modify this

# Encryption Key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    return open(KEY_FILE, "rb").read()

# Save/Load Encrypted Credentials
def save_credentials(data):
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(CRED_FILE, "wb") as f:
        f.write(encrypted)

def load_credentials():
    if not os.path.exists(CRED_FILE):
        return {}
    key = load_key()
    fernet = Fernet(key)
    with open(CRED_FILE, "rb") as f:
        try:
            decrypted = fernet.decrypt(f.read()).decode()
            return json.loads(decrypted)
        except:
            messagebox.showerror("Error", "Invalid key or corrupted data.")
            return {}

# Password Manager App
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.root.geometry("700x550")
        self.root.configure(bg="#1e1e1e")

        self.data = load_credentials()
        self.setup_style()
        self.create_widgets()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TLabel", font=("Segoe UI", 10), background="#1e1e1e", foreground="white")
        style.configure("TEntry", padding=5)
        style.configure("TButton", padding=6)
        style.configure("Treeview", background="#2c2c2c", foreground="white", fieldbackground="#2c2c2c", rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#333", foreground="white")
        style.map("Treeview", background=[('selected', '#4a4a4a')])

    def create_widgets(self):
        form_frame = ttk.Frame(self.root, padding=15)
        form_frame.pack(pady=10)

        ttk.Label(form_frame, text="Site:").grid(row=0, column=0, sticky="w", pady=5)
        self.site_entry = ttk.Entry(form_frame, width=40)
        self.site_entry.grid(row=0, column=1, pady=5)

        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = ttk.Entry(form_frame, width=40)
        self.username_entry.grid(row=1, column=1, pady=5)

        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(form_frame, width=40, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)

        ttk.Button(self.root, text="Save Credential", command=self.save_credential).pack(pady=8)

        # Search Bar
        search_frame = ttk.Frame(self.root, padding=10)
        search_frame.pack()
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.update_table)
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=5)

        # Table View
        self.tree = ttk.Treeview(self.root, columns=("Site", "Username", "Password"), show="headings")
        self.tree.heading("Site", text="Site")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.column("Site", width=200)
        self.tree.column("Username", width=200)
        self.tree.column("Password", width=200)
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        ttk.Button(self.root, text="Export to CSV", command=self.export_to_csv).pack(pady=5)

        self.update_table()

    def save_credential(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not site or not username or not password:
            messagebox.showwarning("Warning", "All fields are required.")
            return

        self.data[site] = {"username": username, "password": password}
        save_credentials(self.data)

        messagebox.showinfo("Success", f"Saved credentials for {site}")
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.update_table()

    def update_table(self, *args):
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())

        for site, creds in self.data.items():
            if search_term in site.lower() or search_term in creds["username"].lower():
                self.tree.insert("", tk.END, values=(site, creds["username"], creds["password"]))

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")],
                                                 title="Save as")
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Site", "Username", "Password"])
                for site, creds in self.data.items():
                    writer.writerow([site, creds["username"], creds["password"]])
            messagebox.showinfo("Exported", f"Data exported to {file_path}")

# Master Password Window
class MasterPasswordWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔐 Login")
        self.window.geometry("300x150")
        self.window.configure(bg="#1e1e1e")

        ttk.Label(self.window, text="Enter Master Password:").pack(pady=10)
        self.password_entry = ttk.Entry(self.window, width=30, show="*")
        self.password_entry.pack(pady=5)
        ttk.Button(self.window, text="Login", command=self.check_password).pack(pady=10)
        self.password_entry.bind("<Return>", lambda event: self.check_password())

        self.window.mainloop()

    def check_password(self):
        if self.password_entry.get() == MASTER_PASSWORD:
            self.window.destroy()
            root = tk.Tk()
            PasswordManagerApp(root)
            root.mainloop()
        else:
            messagebox.showerror("Access Denied", "Incorrect Master Password")

# Run the App
if __name__ == "__main__":
    MasterPasswordWindow()
