import tkinter as tk
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

        # Input Plaintext
        tk.Label(main_frame, text="Enter Plaintext:").grid(row=1, column=0, padx=10, pady=10)
        self.input_plaintext = tk.Entry(main_frame, width=40)
        self.input_plaintext.grid(row=1, column=1, padx=10, pady=10)

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

        # Encrypted/Ciphertext
        tk.Label(main_frame, text="Ciphertext:").grid(row=4, column=0, padx=10, pady=10)
        self.output_ciphertext = tk.Entry(main_frame, width=40)
        self.output_ciphertext.grid(row=4, column=1, padx=10, pady=10)

        # Error Label
        self.error_label = tk.Label(main_frame, text="", fg="red")
        self.error_label.grid(row=5, column=0, columnspan=2, pady=10)

        # Buttons
        tk.Button(main_frame, text="Clear", command=self.clear_entries).grid(row=6, column=0, padx=10, pady=20)

        # Bind entries for dynamic behavior
        self.input_plaintext.bind("<KeyRelease>", self.update_text)
        self.output_ciphertext.bind("<KeyRelease>", self.update_text)
        self.input_key.bind("<KeyRelease>", self.check_inputs)

        self.last_updated = None
        self.root.mainloop()

    def check_inputs(self, event=None):
        key = self.input_key.get()
        if key:
            self.update_text()

    def display_error(self, message):
        self.error_label.config(text=message)

    def clear_error(self):
        self.error_label.config(text="")

    def update_text(self, event=None):
        input_text = self.input_plaintext.get()
        cipher_text = self.output_ciphertext.get()
        key = self.input_key.get()
        method_name = self.method_var.get()
        method_class = self.methods[method_name]

        if not key:
            self.display_error("Key is required.")
            return

        self.clear_error()

        if event and event.widget == self.input_plaintext:
            self.last_updated = "plaintext"
        elif event and event.widget == self.output_ciphertext:
            self.last_updated = "ciphertext"
        elif event and event.widget == self.input_key:
            self.old_last_update = self.last_updated
            self.last_updated = "key"

        try:
            if self.last_updated == "plaintext" or (self.last_updated == "key" and self.old_last_update == "plaintext"):
                encrypted_text = method_class.encrypt(input_text, key)
                self.output_ciphertext.delete(0, tk.END)
                self.output_ciphertext.insert(0, encrypted_text)
            elif self.last_updated == "ciphertext" or (self.last_updated == "key" and self.old_last_update == "cyphertext"):
                decrypted_text = method_class.decrypt(cipher_text, key)
                self.input_plaintext.delete(0, tk.END)
                self.input_plaintext.insert(0, decrypted_text)
        except Exception as e:
            self.display_error(str(e))

    def clear_entries(self):
        self.input_plaintext.delete(0, tk.END)
        self.input_key.delete(0, tk.END)
        self.output_ciphertext.delete(0, tk.END)
        self.clear_error()
        self.last_updated = None

if __name__ == "__main__":
    Display()
