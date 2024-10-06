# pylock_gui.py

import os
import random
import string
import datetime
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from ttkbootstrap import Style
from PIL import Image, ImageTk
from cryptography.fernet import Fernet, InvalidToken

from splash_screen import SplashScreen
from utils import resource_path, get_data_path, load_or_generate_salt, load_key
from styles import configure_styles

class PyLockGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyLock Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg="#2C3E50")
        self.root.resizable(True, True)
        self.key = None
        self.credentials_list = []
        self.salt = load_or_generate_salt()
        self.style = Style(theme='cosmo')
        configure_styles(self.style)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Sorting order: 'alphabetical' or 'recent'
        self.sort_order = 'alphabetical'

        # Start with the splash screen
        self.show_splash_screen()

    def show_splash_screen(self):
        self.root.withdraw()  # Hide the main window during splash
        SplashScreen(self.root, self.start_app)

    def start_app(self):
        self.root.deiconify()  # Show the main window after splash
        self.create_login_screen()

    def create_login_screen(self):
        self.clear_frame()
        self.login_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.login_frame.pack(expand=True)

        # Logo Image
        logo_image = Image.open(resource_path("images/lock_icon.gif")).resize((100, 100), Image.LANCZOS)
        self.logo_photo = ImageTk.PhotoImage(logo_image)
        self.logo_label = Label(self.login_frame, image=self.logo_photo, bg="#2C3E50")
        self.logo_label.pack(pady=(30, 10))  # Adjusted padding

        self.master_password_label = ttk.Label(self.login_frame, text="Enter Master Password:", style='Custom.TLabel')
        self.master_password_label.pack(pady=5)
        self.master_password_entry = Entry(self.login_frame, show='*', width=30, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.master_password_entry.pack(pady=5)
        self.master_password_entry.bind('<Return>', lambda event: self.verify_master_password())

        self.login_button = ttk.Button(self.login_frame, text="Login", style='My.TButton')
        self.login_button.pack(pady=20)
        self.add_hover_effect(self.login_button)
        self.login_button.configure(command=self.verify_master_password)

    def verify_master_password(self):
        master_password = self.master_password_entry.get()
        self.key = load_key(master_password, self.salt)

        try:
            credentials_path = get_data_path("credentials.enc")
            if os.path.exists(credentials_path):
                with open(credentials_path, "rb") as file:
                    test_line = file.readline().strip()
                    if test_line:
                        cipher_suite = Fernet(self.key)
                        cipher_suite.decrypt(test_line)
            self.create_main_menu()
        except InvalidToken:
            messagebox.showerror("Error", "Invalid Master Password")
            self.master_password_entry.delete(0, END)

    def create_main_menu(self):
        self.clear_frame()
        self.main_menu_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.main_menu_frame.pack(expand=True)

        # Welcome Label
        welcome_label = ttk.Label(self.main_menu_frame, text="Welcome to PyLock!", font=('Helvetica', 18, 'bold'), style='Custom.TLabel')
        welcome_label.pack(pady=(30, 20))

        # Generate Password Button with Icon
        gen_icon = Image.open(resource_path("images/generate_icon.gif")).resize((30, 30), Image.LANCZOS)
        self.gen_icon_photo = ImageTk.PhotoImage(gen_icon)
        self.generate_password_button = ttk.Button(
            self.main_menu_frame,
            text=" Generate Password",
            image=self.gen_icon_photo,
            compound=LEFT,
            style='My.TButton',
            width=25
        )
        self.generate_password_button.pack(pady=10)
        self.add_hover_effect(self.generate_password_button)
        self.generate_password_button.configure(command=self.generate_password_screen)

        # View Credentials Button with Icon
        view_icon = Image.open(resource_path("images/view_icon.gif")).resize((30, 30), Image.LANCZOS)
        self.view_icon_photo = ImageTk.PhotoImage(view_icon)
        self.view_credentials_button = ttk.Button(
            self.main_menu_frame,
            text=" View Credentials",
            image=self.view_icon_photo,
            compound=LEFT,
            style='My.TButton',
            width=25
        )
        self.view_credentials_button.pack(pady=10)
        self.add_hover_effect(self.view_credentials_button)
        self.view_credentials_button.configure(command=self.view_credentials_screen)

        # Logout Button
        self.logout_button = ttk.Button(self.main_menu_frame, text="Logout", style='My.TButton', width=25)
        self.logout_button.pack(pady=10)
        self.add_hover_effect(self.logout_button)
        self.logout_button.configure(command=self.logout)

    def add_hover_effect(self, widget):
        def on_enter(event):
            widget.configure(cursor="hand2")
        def on_leave(event):
            widget.configure(cursor="")
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def generate_password_screen(self):
        self.clear_frame()
        self.generate_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.generate_frame.pack(expand=True)

        self.length_label = ttk.Label(self.generate_frame, text="Password Length (8-16):", font=('Helvetica', 14), style='Custom.TLabel')
        self.length_label.pack(pady=5)
        self.length_entry = Entry(self.generate_frame, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.length_entry.pack(pady=5)
        self.length_entry.bind('<Return>', lambda event: self.generate_password())

        self.generate_button = ttk.Button(self.generate_frame, text="Generate", style='My.TButton', width=20)
        self.generate_button.pack(pady=20)
        self.add_hover_effect(self.generate_button)
        self.generate_button.configure(command=self.generate_password)

        self.back_button = ttk.Button(self.generate_frame, text="Back", style='My.TButton', width=20)
        self.back_button.pack(pady=5)
        self.add_hover_effect(self.back_button)
        self.back_button.configure(command=self.create_main_menu)

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length < 8 or length > 16:
                raise ValueError("Password length must be between 8 and 16.")
            password = self.generate_password_logic(length)
            save = messagebox.askyesno("Password Generated", f"Generated Password: {password}\nDo you want to save it?")
            if save:
                self.save_password_screen(password)
            else:
                self.generate_password_screen()
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def generate_password_logic(self, length):
        all_characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(random.choice(all_characters) for _ in range(length))
            if (any(c.islower() for c in password) and any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
                return password

    def save_password_screen(self, password):
        self.clear_frame()
        self.save_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.save_frame.pack(expand=True)

        self.website_label = ttk.Label(self.save_frame, text="Website:", font=('Helvetica', 14), style='Custom.TLabel')
        self.website_label.pack(pady=5)
        self.website_entry = Entry(self.save_frame, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.website_entry.pack(pady=5)

        self.username_label = ttk.Label(self.save_frame, text="Username:", font=('Helvetica', 14), style='Custom.TLabel')
        self.username_label.pack(pady=5)
        self.username_entry = Entry(self.save_frame, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.username_entry.pack(pady=5)

        self.password_label = ttk.Label(self.save_frame, text="Password:", font=('Helvetica', 14), style='Custom.TLabel')
        self.password_label.pack(pady=5)
        self.password_entry = Entry(self.save_frame, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.password_entry.insert(0, password)
        self.password_entry.pack(pady=5)

        self.save_button = ttk.Button(self.save_frame, text="Save", style='My.TButton', width=20)
        self.save_button.pack(pady=20)
        self.add_hover_effect(self.save_button)
        self.save_button.configure(command=self.save_credentials)

        self.back_button = ttk.Button(self.save_frame, text="Back", style='My.TButton', width=20)
        self.back_button.pack(pady=5)
        self.add_hover_effect(self.back_button)
        self.back_button.configure(command=self.create_main_menu)

    def save_credentials(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not website or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return
        cipher_suite = Fernet(self.key)
        timestamp = datetime.datetime.now().isoformat()
        credentials = f"Website: {website}\nUsername: {username}\nPassword: {password}\nTimestamp: {timestamp}".encode()
        encrypted_credentials = cipher_suite.encrypt(credentials)
        credentials_path = get_data_path("credentials.enc")
        with open(credentials_path, "ab") as file:
            file.write(encrypted_credentials + b'\n')
        messagebox.showinfo("Success", "Credentials saved successfully!")
        self.create_main_menu()

    def view_credentials_screen(self):
        self.clear_frame()
        self.view_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.view_frame.pack(expand=True, fill=BOTH)

        # Sort Options Frame
        self.sort_frame = ttk.Frame(self.view_frame, style='Custom.TFrame')
        self.sort_frame.pack(pady=10)

        # Sort Button
        self.sort_button = ttk.Button(self.sort_frame, text="Sort by Recent", style='My.TButton')
        self.sort_button.pack(side=LEFT, padx=5)
        self.add_hover_effect(self.sort_button)
        self.sort_button.configure(command=self.toggle_sort_order)

        # Search Bar
        self.search_frame = ttk.Frame(self.view_frame, style='Custom.TFrame')
        self.search_frame.pack(pady=10)

        self.search_label = ttk.Label(self.search_frame, text="Search Website:", font=('Helvetica', 14), style='Custom.TLabel')
        self.search_label.pack(side=LEFT, padx=5)
        self.search_entry = Entry(self.search_frame, font=('Helvetica', 14), bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.search_entry.pack(side=LEFT, padx=5)
        self.search_entry.bind('<Return>', lambda event: self.search_credentials())

        self.search_button = ttk.Button(self.search_frame, text="Search", style='My.TButton')
        self.search_button.pack(side=LEFT, padx=5)
        self.add_hover_effect(self.search_button)
        self.search_button.configure(command=self.search_credentials)

        # Container Frame using Grid
        self.content_frame = ttk.Frame(self.view_frame, style='Custom.TFrame')
        self.content_frame.pack(expand=True, fill=BOTH, pady=10)

        # Configure grid columns and rows
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.columnconfigure(1, weight=1)
        self.content_frame.rowconfigure(0, weight=1)

        # Treeview Frame
        self.tree_frame = ttk.Frame(self.content_frame, style='Custom.TFrame')
        self.tree_frame.grid(row=0, column=0, sticky='nsew', padx=10)

        self.credentials_tree = ttk.Treeview(
            self.tree_frame,
            columns=("Website", "Username"),
            show='headings',
            height=15,
            style='Custom.Treeview'
        )
        self.credentials_tree.heading("Website", text="Website")
        self.credentials_tree.heading("Username", text="Username")
        self.credentials_tree.column("Website", width=200)
        self.credentials_tree.column("Username", width=200)
        self.credentials_tree.pack(fill=BOTH, expand=True)

        # Scrollbar for the Treeview
        scrollbar = ttk.Scrollbar(self.tree_frame, orient=VERTICAL, command=self.credentials_tree.yview)
        self.credentials_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Bind selection event
        self.credentials_tree.bind("<<TreeviewSelect>>", self.on_treeview_select)

        # Details Frame
        self.details_frame = ttk.Frame(self.content_frame, style='Custom.TFrame')
        self.details_frame.grid(row=0, column=1, sticky='nsew', padx=10)

        # Configure details_frame rows and columns
        for i in range(6):
            self.details_frame.rowconfigure(i, weight=1)
        self.details_frame.columnconfigure(0, weight=1)
        self.details_frame.columnconfigure(1, weight=2)

        # Details Widgets
        label_font = ('Helvetica', 14)
        entry_font = ('Helvetica', 14)

        self.website_detail_label = ttk.Label(self.details_frame, text="Website:", font=label_font, style='Custom.TLabel')
        self.website_detail_label.grid(row=0, column=0, padx=5, pady=5, sticky=E)
        self.website_detail_entry = Entry(self.details_frame, width=30, font=entry_font, bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.website_detail_entry.grid(row=0, column=1, padx=5, pady=5, sticky=W)

        self.username_detail_label = ttk.Label(self.details_frame, text="Username:", font=label_font, style='Custom.TLabel')
        self.username_detail_label.grid(row=1, column=0, padx=5, pady=5, sticky=E)
        self.username_detail_entry = Entry(self.details_frame, width=30, font=entry_font, bg='#3B4A60', fg='white', insertbackground='white', relief='flat')
        self.username_detail_entry.grid(row=1, column=1, padx=5, pady=5, sticky=W)

        self.password_detail_label = ttk.Label(self.details_frame, text="Password:", font=label_font, style='Custom.TLabel')
        self.password_detail_label.grid(row=2, column=0, padx=5, pady=5, sticky=E)
        self.password_detail_entry = Entry(self.details_frame, width=30, font=entry_font, bg='#3B4A60', fg='white', insertbackground='white', relief='flat', show='*')
        self.password_detail_entry.grid(row=2, column=1, padx=5, pady=5, sticky=W)

        self.show_password_var = IntVar()
        self.show_password_check = ttk.Checkbutton(
            self.details_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            style='Custom.TCheckbutton'
        )
        self.show_password_check.grid(row=3, column=1, sticky=W, padx=5, pady=5)

        self.copy_button = ttk.Button(self.details_frame, text="Copy Password", style='My.TButton', width=20)
        self.copy_button.grid(row=4, column=1, pady=10, sticky=W)
        self.add_hover_effect(self.copy_button)
        self.copy_button.configure(command=self.copy_password)

        self.delete_button = ttk.Button(self.details_frame, text="Delete Credential", style='My.TButton', width=20)
        self.delete_button.grid(row=5, column=1, pady=5, sticky=W)
        self.add_hover_effect(self.delete_button)
        self.delete_button.configure(command=self.delete_credential)

        self.back_button = ttk.Button(self.view_frame, text="Back", style='My.TButton', width=20)
        self.back_button.pack(pady=10)
        self.add_hover_effect(self.back_button)
        self.back_button.configure(command=self.create_main_menu)

        self.load_credentials()

    def toggle_sort_order(self):
        if self.sort_order == 'alphabetical':
            self.sort_order = 'recent'
            self.sort_button.config(text="Sort Alphabetically")
        else:
            self.sort_order = 'alphabetical'
            self.sort_button.config(text="Sort by Recent")
        self.load_credentials()

    def load_credentials(self):
        self.credentials_list.clear()
        self.credentials_tree.delete(*self.credentials_tree.get_children())
        cipher_suite = Fernet(self.key)
        credentials_path = get_data_path("credentials.enc")
        if not os.path.exists(credentials_path):
            return
        with open(credentials_path, "rb") as file:
            lines = file.readlines()

        for idx, encrypted_line in enumerate(lines):
            encrypted_credentials = encrypted_line.strip()
            try:
                decrypted_credentials = cipher_suite.decrypt(encrypted_credentials).decode()
                lines = decrypted_credentials.split('\n')
                website = lines[0].split(": ", 1)[1]
                username = lines[1].split(": ", 1)[1]
                password = lines[2].split(": ", 1)[1]
                # Handle existing data without a timestamp
                if len(lines) > 3 and lines[3].startswith("Timestamp: "):
                    timestamp = lines[3].split(": ", 1)[1]
                else:
                    timestamp = "2000-01-01T00:00:00"

                credential_dict = {
                    'website': website,
                    'username': username,
                    'password': password,
                    'timestamp': timestamp
                }
                self.credentials_list.append(credential_dict)
            except InvalidToken:
                messagebox.showerror("Error", "Invalid Master Password")
                return

        # Sort credentials based on the selected sort order
        if self.sort_order == 'alphabetical':
            self.credentials_list.sort(key=lambda x: x['website'].lower())
        elif self.sort_order == 'recent':
            self.credentials_list.sort(key=lambda x: x['timestamp'], reverse=True)

        # Display credentials in the Treeview
        for idx, credential in enumerate(self.credentials_list):
            website = credential['website']
            username = credential['username']
            tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            self.credentials_tree.insert('', 'end', iid=str(idx), values=(website, username), tags=(tag,))

        # Configure row tags
        self.credentials_tree.tag_configure('evenrow', background='#2C3E50')
        self.credentials_tree.tag_configure('oddrow', background='#34495E')

    def search_credentials(self):
        search_query = self.search_entry.get().lower()
        filtered_credentials = [
            credential for credential in self.credentials_list
            if search_query in credential['website'].lower() or search_query in credential['username'].lower()
        ]

        # Sort filtered credentials based on the selected sort order
        if self.sort_order == 'alphabetical':
            filtered_credentials.sort(key=lambda x: x['website'].lower())
        elif self.sort_order == 'recent':
            filtered_credentials.sort(key=lambda x: x['timestamp'], reverse=True)

        # Clear and repopulate the Treeview with filtered credentials
        self.credentials_tree.delete(*self.credentials_tree.get_children())
        for idx, credential in enumerate(filtered_credentials):
            website = credential['website']
            username = credential['username']
            tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            self.credentials_tree.insert('', 'end', iid=str(idx), values=(website, username), tags=(tag,))

        # Reconfigure row tags
        self.credentials_tree.tag_configure('evenrow', background='#2C3E50')
        self.credentials_tree.tag_configure('oddrow', background='#34495E')

    def reindex_credentials(self):
        # Reindex the credentials_list
        # No need to re-sort here, as load_credentials handles sorting
        self.load_credentials()

    def on_treeview_select(self, event):
        selected_item = self.credentials_tree.selection()
        if not selected_item:
            return
        item_id = selected_item[0]
        index = int(item_id)
        credential = self.credentials_list[index]

        # Update details panel
        self.website_detail_entry.config(state=NORMAL)
        self.username_detail_entry.config(state=NORMAL)
        self.password_detail_entry.config(state=NORMAL)

        self.website_detail_entry.delete(0, END)
        self.username_detail_entry.delete(0, END)
        self.password_detail_entry.delete(0, END)

        self.website_detail_entry.insert(0, credential['website'])
        self.username_detail_entry.insert(0, credential['username'])
        self.password_detail_entry.insert(0, credential['password'])

        # Mask password if 'Show Password' is not checked
        if not self.show_password_var.get():
            self.password_detail_entry.config(show='*')
        else:
            self.password_detail_entry.config(show='')

        # Disable editing
        self.website_detail_entry.config(state='readonly')
        self.username_detail_entry.config(state='readonly')
        self.password_detail_entry.config(state='readonly')

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_detail_entry.config(show='')
        else:
            self.password_detail_entry.config(show='*')

    def copy_password(self):
        selected_item = self.credentials_tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No item selected.")
            return
        item_id = selected_item[0]
        index = int(item_id)
        credential = self.credentials_list[index]
        password = credential['password']
        # Copy password to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Success", "Password copied to clipboard.")

    def delete_credential(self):
        selected_item = self.credentials_tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No item selected.")
            return
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected credential?")
        if confirm:
            item_id = selected_item[0]
            index = int(item_id)
            # Remove credential from the list
            del self.credentials_list[index]
            # Remove item from Treeview
            self.credentials_tree.delete(item_id)
            # Re-index the Treeview items and credentials list
            self.reindex_credentials()
            # Save all credentials
            self.save_all_credentials()
            # Clear details panel
            self.clear_details_panel()
            messagebox.showinfo("Success", "Credential deleted successfully.")

    def save_all_credentials(self):
        cipher_suite = Fernet(self.key)
        credentials_path = get_data_path("credentials.enc")
        with open(credentials_path, "wb") as file:
            for credential in self.credentials_list:
                credentials_str = f"Website: {credential['website']}\nUsername: {credential['username']}\nPassword: {credential['password']}\nTimestamp: {credential['timestamp']}"
                encrypted_credentials = cipher_suite.encrypt(credentials_str.encode())
                file.write(encrypted_credentials + b'\n')

    def clear_details_panel(self):
        self.website_detail_entry.config(state=NORMAL)
        self.username_detail_entry.config(state=NORMAL)
        self.password_detail_entry.config(state=NORMAL)

        self.website_detail_entry.delete(0, END)
        self.username_detail_entry.delete(0, END)
        self.password_detail_entry.delete(0, END)

        self.website_detail_entry.config(state='readonly')
        self.username_detail_entry.config(state='readonly')
        self.password_detail_entry.config(state='readonly')

    def logout(self):
        self.key = None
        self.credentials_list.clear()
        self.create_login_screen()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
