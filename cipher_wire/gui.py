import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

from .caeser_cipher import CaesarCipher
from .playfair import Playfair

class Display:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cypher Wire")
        self.root.geometry("600x500")

        # Main Frame for centralizing content
        main_frame = tk.Frame(self.root)
        main_frame.pack(padx=20, pady=20, expand=True, fill="both")

        # Title Label
        self.title_label = tk.Label(main_frame, text="Cypher Wire", font=("Arial", 24))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=20)

        # Input Text
        tk.Label(main_frame, text="Enter Text:").grid(row=1, column=0, padx=10, pady=10)
        self.input_plantext = tk.Entry(main_frame, width=40)
        self.input_plantext.grid(row=1, column=1, padx=10, pady=10)

        # Input Key
        tk.Label(main_frame, text="Enter Key:").grid(row=2, column=0, padx=10, pady=10)
        self.input_key = tk.Entry(main_frame, width=40)
        self.input_key.grid(row=2, column=1, padx=10, pady=10)

        # Encryption Method using Combobox
        tk.Label(main_frame, text="Select Encryption Method:").grid(row=3, column=0, padx=10, pady=10)
        self.methods = {
            "Caesar cipher": CaesarCipher,
            "Playfair": Playfair,
        }
        self.method_var = tk.StringVar(value="Caesar cipher")
        self.method_selector = ttk.Combobox(main_frame, textvariable=self.method_var, values=list(self.methods.keys()))
        self.method_selector.grid(row=3, column=1, padx=10, pady=10)

        # Encrypted Text
        tk.Label(main_frame, text="Encrypted Text:").grid(row=4, column=0, padx=10, pady=10)
        self.output_entry = tk.Entry(main_frame, width=40, state="readonly")
        self.output_entry.grid(row=4, column=1, padx=10, pady=10)

        # Buttons
        self.encrypt_button = tk.Button(main_frame, text="Encrypt", command=self.encrypt_text, state="disabled")
        self.encrypt_button.grid(row=5, column=0, padx=10, pady=20)
        tk.Button(main_frame, text="Clear", command=self.clear_entries).grid(row=5, column=1, padx=10, pady=20)

        # Bind the input fields to check if both fields have data
        self.input_plantext.bind("<KeyRelease>", self.check_inputs)
        self.input_key.bind("<KeyRelease>", self.check_inputs)

        self.root.mainloop()

    def check_inputs(self, event=None):
        text = self.input_plantext.get()
        key = self.input_key.get()

        if text and key:
            self.encrypt_button.config(state="normal")
            if not self.encrypt_text(False):
                self.output_entry.config(state="normal")
                self.output_entry.delete(0, tk.END)
                self.output_entry.config(state="readonly")
        else:
            self.encrypt_button.config(state="disabled")

    def encrypt_text(self, show_error=True) -> bool:
        input_text = self.input_plantext.get()
        input_key = self.input_key.get()
        method_name = self.method_var.get()
        method_class = self.methods[method_name]

        if not input_text:
            if show_error:
                messagebox.showerror("Error", "Please enter some text to encrypt.")
            return False
        if not input_key:
            if show_error:
                messagebox.showerror("Error", "Please enter some key to encrypt.")
            return False

        try:
            encrypted_text = method_class.encrypt(input_text, input_key)
        except Exception as e:
            if show_error:
                messagebox.showerror("Error", str(e))
            return False

        self.output_entry.config(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encrypted_text)
        self.output_entry.config(state="readonly")

        return True

    def clear_entries(self):
        self.input_plantext.delete(0, tk.END)
        self.input_key.delete(0, tk.END)
        self.output_entry.config(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.config(state="readonly")


if __name__ == "__main__":
    Display()
