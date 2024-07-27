import os
from dotenv import load_dotenv
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet

# Load environment variables from .env file
load_dotenv()

# Define paths for key, password file, and master password hash
directory = os.getenv('DIRECTORY_PATH')
password_file_path = os.path.join(directory, "passwords.txt")
key_file_path = os.path.join(directory, "key.key")
master_password_hash_path = os.path.join(directory, "master_password_hash.txt")

# Generate and save a new encryption key
def write_key():
    key = Fernet.generate_key()
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)

# Load the encryption key from file and generate new key if one doesn't exist
def load_key():
    if not os.path.exists(key_file_path):
        write_key()
    with open(key_file_path, "rb") as file:
        key = file.read()
    return key

key = load_key()
fer = Fernet(key)

# Hash (encrypt) the master password
def hash_password(password):
    return fer.encrypt(password.encode()).decode()

# Verify if a given password matches the stored hash
def verify_password(stored_hash, password):
    try:
        return fer.decrypt(stored_hash.encode()).decode() == password
    except:
        return False

# Set and confirm the master password. Clear entries if passwords don't match
def set_master_password():
    def confirm_passwords():
        password1 = entry_password1.get()
        password2 = entry_password2.get()
        if password1 == password2:
            hashed_password = hash_password(password1)
            with open(master_password_hash_path, "w") as file:
                file.write(hashed_password)
            messagebox.showinfo("Success", "Master password set successfully.")
            setup_window.destroy()
            authenticate()
        else:
            messagebox.showerror("Error", "Passwords do not match. Please try again.")
            entry_password1.delete(0, tk.END)
            entry_password2.delete(0, tk.END)

    setup_window = tk.Tk()                                          
    setup_window.title("Set Master Password")

    # Create and place labels and entry fields
    tk.Label(setup_window, text="Set Master Password:").grid(row=0, column=0, padx=10, pady=10)
    tk.Label(setup_window, text="Confirm Master Password:").grid(row=1, column=0, padx=10, pady=10)
    entry_password1 = tk.Entry(setup_window, show="*")
    entry_password1.grid(row=0, column=1, padx=10, pady=10)
    entry_password2 = tk.Entry(setup_window, show="*")
    entry_password2.grid(row=1, column=1, padx=10, pady=10)

    # Button to set password and exit
    tk.Button(setup_window, text="Set Password", command=confirm_passwords).grid(row=2, column=0, columnspan=2, pady=10)
    tk.Button(setup_window, text="Exit", command=setup_window.quit).grid(row=3, column=0, columnspan=2, pady=10)

    setup_window.mainloop()

# Function to authenticate the user with the master password
def authenticate():
    stored_hash = load_master_password_hash()
    if stored_hash is None:
        messagebox.showinfo("Info", "No master password set. Please set a master password first.")
        return False

    # Function to verify login and enter main app
    def verify_login():
        password = entry_login_password.get()
        if verify_password(stored_hash, password):
            messagebox.showinfo("Success", "Login successful.")
            login_window.destroy()
            main_app()
        else:
            nonlocal attempts
            attempts -= 1
            if attempts > 0:
                messagebox.showwarning("Warning", f"Incorrect password. {attempts} tries remaining.")
            else:
                messagebox.showerror("Error", "Authentication failed. Exiting.")
                login_window.destroy()

    login_window = tk.Tk()
    login_window.title("Login")

    # Create and place label and entry field
    tk.Label(login_window, text="Enter Master Password:").grid(row=0, column=0, padx=10, pady=10)
    entry_login_password = tk.Entry(login_window, show="*")
    entry_login_password.grid(row=0, column=1, padx=10, pady=10)

    # Login Attempts
    attempts = 3  
    tk.Button(login_window, text="Login", command=verify_login).grid(row=1, column=0, columnspan=2, pady=10)
    tk.Button(login_window, text="Exit", command=login_window.quit).grid(row=2, column=0, columnspan=2, pady=10)

    login_window.mainloop()

# Function to load the master password hash
def load_master_password_hash():
    if os.path.exists(master_password_hash_path):
        with open(master_password_hash_path, "r") as file:
            return file.read().strip()
    return None 

# Function to view stored passwords
def view_passwords():
    if not os.path.exists(password_file_path):
        messagebox.showinfo("Info", "No passwords stored yet.")
        return
    
    def update_table():
        for row in tree.get_children():
            tree.delete(row)
        
        # Read each line from the password file, decrypt the password, and insert the data into the table
        with open(password_file_path, 'r') as f:
            for idx, line in enumerate(f.readlines(), start=1):
                data = line.rstrip()
                website, user, passw = data.split("|")
                tree.insert("", "end", values=(idx, website, user, fer.decrypt(passw.encode()).decode()))

    view_window = tk.Tk()
    view_window.title("View Passwords")

    # Define columns and create Table
    columns = ("#1", "#2", "#3", "#4")                              
    tree = ttk.Treeview(view_window, columns=columns, show="headings")

    # Define column headers
    tree.heading("#1", text="No.")
    tree.heading("#2", text="Website")
    tree.heading("#3", text="Username")
    tree.heading("#4", text="Password")

    # Adjust column widths
    tree.column("#1", width=50, anchor="center")
    tree.column("#2", width=200, anchor="w")
    tree.column("#3", width=150, anchor="w")
    tree.column("#4", width=200, anchor="w")

    tree.pack(padx=10, pady=10)
    
    update_table()

    # Buttons to refresh and close the window
    tk.Button(view_window, text="Refresh", command=update_table).pack(pady=10)
    tk.Button(view_window, text="Close", command=view_window.destroy).pack(pady=10)

    view_window.mainloop()

# Function to add a new password entry
def add_password():
    website = entry_website.get()
    username = entry_username.get()
    password = entry_password.get()

    # Check for empty fields
    if not website or not username or not password:
        messagebox.showerror("Error", "Please fill out all fields.")
        return

    # Write entry to file
    with open(password_file_path, 'a') as f:
        f.write(f"{website}|{username}|{fer.encrypt(password.encode()).decode()}\n")

    # Clear entries after adding a password
    messagebox.showinfo("Success", "Password added successfully.")
    entry_website.delete(0, tk.END)
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)

# Function to create the main application window
def main_app():
    root = tk.Tk()
    root.title("Password Manager")

    # Create and place labels and entry fields
    tk.Label(root, text="Website:").grid(row=0, column=0, padx=10, pady=10)
    tk.Label(root, text="Username:").grid(row=1, column=0, padx=10, pady=10)
    tk.Label(root, text="Password:").grid(row=2, column=0, padx=10, pady=10)

    # Declare global entries
    global entry_website, entry_username, entry_password                    
    entry_website = tk.Entry(root)
    entry_website.grid(row=0, column=1, padx=10, pady=10) 

    entry_username = tk.Entry(root)
    entry_username.grid(row=1, column=1, padx=10, pady=10)

    entry_password = tk.Entry(root, show="*")
    entry_password.grid(row=2, column=1, padx=10, pady=10)

    # Buttons to add password and view passwords
    tk.Button(root, text="Add Password", command=add_password).grid(row=3, column=0, columnspan=2, pady=10)
    tk.Button(root, text="View Passwords", command=view_passwords).grid(row=4, column=0, columnspan=2, pady=10)
    tk.Button(root, text="Exit", command=root.destroy).grid(row=5, column=0, columnspan=2, pady=10)

    root.mainloop()

# Start the application
if not os.path.exists(master_password_hash_path):
    set_master_password()
else:
    authenticate()
