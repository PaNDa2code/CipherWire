import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re

from .caeser_cipher import CaesarCipher
from .playfair import Playfair

class Display:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encryption App")
        self.root.geometry("600x400")

        tk.Label(self.root, text="Enter Text:").pack(pady=5)
        self.input_plantext = tk.Entry(self.root, width=50)
        self.input_plantext.pack(pady=5)

        tk.Label(self.root, text="Enter Key:").pack(pady=5)
        self.input_key = tk.Entry(self.root, width=50)
        self.input_key.pack(pady=5)

        self.methods = {
                "Caesar cipher": CaesarCipher,
                "Playfair": Playfair,
        }

        tk.Label(self.root, text="Select Encryption Method:").pack(pady=5)
        self.method_var = tk.StringVar(value="Caesar cipher")
        self.method_selector = ttk.Combobox(self.root, textvariable=self.method_var, values=list(self.methods.keys()))
        self.method_selector.pack(pady=5)

        tk.Label(self.root, text="Encrypted Text:").pack(pady=5)
        self.output_entry = tk.Entry(self.root, width=50, state="readonly")
        self.output_entry.pack(pady=5)

        tk.Button(self.root, text="Encrypt", command=self.encrypt_text).pack(pady=10)
        tk.Button(self.root, text="Clear", command=self.clear_entries).pack(pady=5)

        self.root.mainloop()

    def encrypt_text(self):
        input_text = self.input_plantext.get()
        input_key = self.input_key.get()
        method_name = self.method_var.get()
        method_class = self.methods[method_name]

        if not input_text:
            messagebox.showerror("Error", "Please enter some text to encrypt.")
            return
        if not input_key:
            messagebox.showerror("Error", "Please enter some key to encrypt.")
            return
        
        try:
            encrypted_text = method_class.encrypt(input_text, input_key)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return


        self.output_entry.config(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encrypted_text)
        self.output_entry.config(state="readonly")


    def clear_entries(self):
        self.input_plantext.delete(0, tk.END)
        self.input_key.delete(0, tk.END)
        self.output_entry.config(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.config(state="readonly")

if __name__ == "__main__":
    Display()
