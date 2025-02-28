import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import pyperclip  # For copying to clipboard
from tkinter import ttk  # For the progress bar and themed widgets

def check_password_strength(password):
    strength = 0
    remarks = "Weak"
    
    # Check length
    if len(password) >= 8:
        strength += 1
    
    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        strength += 1
    
    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        strength += 1
    
    # Check for digits
    if re.search(r"\d", password):
        strength += 1
    
    # Check for special characters
    if re.search(r"[@$!%*?&#]", password):
        strength += 1
    
    # Determine strength category
    if strength <= 2:
        remarks = "Weak"
    elif strength == 3 or strength == 4:
        remarks = "Medium"
    elif strength == 5:
        remarks = "Strong"
    
    return strength, remarks

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def analyze_password():
    password = entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return
    
    strength, remarks = check_password_strength(password)
    hashed_password = hash_password(password)
    
    # Update strength and hash result
    result_label.config(text=f"Password Strength: {remarks}")
    strength_bar['value'] = strength * 20  # Visualize strength as progress bar
    
    hash_label.config(text=f"SHA-256 Hash: {hashed_password}")

def copy_to_clipboard():
    hashed_password = hash_label.cget("text").replace("SHA-256 Hash: ", "")
    pyperclip.copy(hashed_password)
    messagebox.showinfo("Copied", "Hashed password copied to clipboard!")

def toggle_password_visibility():
    if entry.cget("show") == "*":
        entry.config(show="")
        toggle_btn.config(text="Hide Password")
    else:
        entry.config(show="*")
        toggle_btn.config(text="Show Password")

def toggle_theme():
    current_bg = root.cget("bg")
    if current_bg == "#2b2b2b":  # Dark mode
        root.config(bg="#f5f5f5")
        result_label.config(bg="#f5f5f5", fg="#000000")
        hash_label.config(bg="#f5f5f5", fg="#000000")
        toggle_theme_btn.config(bg="#f5f5f5", fg="#000000")
        toggle_btn.config(bg="#f5f5f5", fg="#000000")
        entry.config(bg="#ffffff", fg="#000000")
        copy_btn.config(bg="#f5f5f5", fg="#000000")
        strength_bar.config(style="TProgressbar")
    else:  # Light mode
        root.config(bg="#2b2b2b")
        result_label.config(bg="#2b2b2b", fg="#ffffff")
        hash_label.config(bg="#2b2b2b", fg="#ffffff")
        toggle_theme_btn.config(bg="#2b2b2b", fg="#ffffff")
        toggle_btn.config(bg="#2b2b2b", fg="#ffffff")
        entry.config(bg="#3b3b3b", fg="#ffffff")
        copy_btn.config(bg="#2b2b2b", fg="#ffffff")
        strength_bar.config(style="TProgressbarDark")

# GUI Setup
root = tk.Tk()
root.title("Password Strength Analyzer")
root.geometry("450x400")
root.config(bg="#f5f5f5")

# Widgets
tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack(pady=5)

toggle_btn = tk.Button(root, text="Show Password", command=toggle_password_visibility, font=("Arial", 12))
toggle_btn.pack(pady=5)

tk.Button(root, text="Analyze", command=analyze_password, font=("Arial", 12), relief="solid").pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12), bg="#f5f5f5")
result_label.pack(pady=5)

# Progress Bar for Strength
style = ttk.Style()
style.configure("TProgressbar",
                thickness=25,
                barcolor="#0C6F35",
                background="#cccccc")
strength_bar = ttk.Progressbar(root, length=200, maximum=100, value=0, style="TProgressbar")
strength_bar.pack(pady=10)

hash_label = tk.Label(root, text="", wraplength=380, font=("Arial", 10), bg="#f5f5f5")
hash_label.pack(pady=10)

copy_btn = tk.Button(root, text="Copy Hash to Clipboard", command=copy_to_clipboard, font=("Arial", 12))
copy_btn.pack(pady=10)

# Theme Toggle Button
toggle_theme_btn = tk.Button(root, text="Switch to Dark Mode", command=toggle_theme, font=("Arial", 12))
toggle_theme_btn.pack(pady=10)

root.mainloop()
