import os,sys
import tkinter as tk
from tkinter import filedialog
from functools import partial
from enclib import create_vault, extract_vault

def open_folder():
    folder_path = filedialog.askdirectory(initialdir = sys.argv[0])
    if folder_path:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder_path)

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Vault files", "*.vlt")])
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def encrypt_folder():
    folder_path = folder_entry.get()
    password = password_entry.get()
    if folder_path and password:
        create_vault(folder_path, password)
        status_label.config(text="Folder encrypted successfully.")

def decrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()
    if file_path and password:
        extract_vault(file_path, password)
        status_label.config(text="Vault decrypted and files extracted successfully.")

# Create main window
root = tk.Tk()
root.title("Folder Encryption Tool")

# Create widgets
folder_label = tk.Label(root, text="Select Folder:")
folder_entry = tk.Entry(root, width=50)
folder_button = tk.Button(root, text="Open Folder", command=open_folder)

file_label = tk.Label(root, text="Select File:")
file_entry = tk.Entry(root, width=50)
file_button = tk.Button(root, text="Open File", command=open_file)

password_label = tk.Label(root, text="Enter Password:")
password_entry = tk.Entry(root, show="*")

encrypt_button = tk.Button(root, text="Encrypt Folder", command=encrypt_folder)
decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file)

status_label = tk.Label(root, text="")

# Arrange widgets using grid layout
folder_label.grid(row=0, column=0, sticky="e")
folder_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
folder_button.grid(row=0, column=3, padx=5, pady=5)

file_label.grid(row=1, column=0, sticky="e")
file_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
file_button.grid(row=1, column=3, padx=5, pady=5)

password_label.grid(row=2, column=0, sticky="e")
password_entry.grid(row=2, column=1, columnspan=3, padx=5, pady=5)

encrypt_button.grid(row=3, column=1, padx=5, pady=5)
decrypt_button.grid(row=3, column=2, padx=5, pady=5)

status_label.grid(row=4, column=0, columnspan=4)

# Start the Tkinter event loop
root.mainloop()
