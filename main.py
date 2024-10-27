import tkinter as tk
from tkinter import filedialog, messagebox
from encryptions.vigener import vigenere_cipher
from encryptions.transposition import columnar_transposition

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Encryption/Decryption Application")

        self.master.geometry("500x400")

        # Encryption method selection
        self.method_label = tk.Label(master, text="Select encryption method:")
        self.method_label.pack()

        self.method_var = tk.StringVar()
        self.method_var.set("vigenere")

        self.vigenere_radio = tk.Radiobutton(master, text="Vigenere", variable=self.method_var, value="vigenere")
        self.vigenere_radio.pack()

        self.columnar_radio = tk.Radiobutton(master, text="Columnar", variable=self.method_var, value="columnar")
        self.columnar_radio.pack()

        # Input method selection
        self.input_label = tk.Label(master, text="Select input method:")
        self.input_label.pack()

        self.input_var = tk.StringVar()
        self.input_var.set("type")

        self.type_radio = tk.Radiobutton(master, text="Type text", variable=self.input_var, value="type",
                                         command=self.show_text_input)
        self.type_radio.pack()

        self.file_radio = tk.Radiobutton(master, text="Load file", variable=self.input_var, value="file",
                                         command=self.hide_text_input)
        self.file_radio.pack()

        # Text input
        self.text_input = tk.Text(master, height=10, width=50)
        self.text_input.pack()

        # File input button
        self.file_button = tk.Button(master, text="Choose File", command=self.load_file)
        self.file_button.pack()
        self.file_button.pack_forget()  # Hide initially

        # Key input
        self.key_label = tk.Label(master, text="Enter encryption key:")
        self.key_label.pack()
        self.key_entry = tk.Entry(master)
        self.key_entry.pack()

        # Process button
        self.process_button = tk.Button(master, text="Encrypt and Decrypt", command=self.process)
        self.process_button.pack()

    def show_text_input(self):
        self.text_input.pack()
        self.file_button.pack_forget()

    def hide_text_input(self):
        self.text_input.pack_forget()
        self.file_button.pack()

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                self.text_input.delete('1.0', tk.END)
                self.text_input.insert(tk.END, file.read())

    def process(self):
        method = self.method_var.get()
        input_method = self.input_var.get()
        key = self.key_entry.get().upper()

        if not key:
            messagebox.showerror("Error", "Please enter an encryption key.")
            return

        if input_method == "type":
            text = self.text_input.get('1.0', tk.END).strip()
        else:
            text = self.text_input.get('1.0', tk.END).strip()

        if not text:
            messagebox.showerror("Error", "Please enter or load some text.")
            return

        # Encrypt
        if method == "vigenere":
            encrypted = vigenere_cipher(text, key, encrypt=True)
        else:
            encrypted = columnar_transposition(text, key, encrypt=True)

        # Write encrypted to file
        with open("ENCRYPTED", 'w') as file:
            file.write(encrypted)

        # Decrypt
        if method == "vigenere":
            decrypted = vigenere_cipher(encrypted, key, encrypt=False)
        else:
            decrypted = columnar_transposition(encrypted, key, encrypt=False)

        # Write decrypted to file
        with open("DECRYPTED", 'w') as file:
            file.write(decrypted)

        messagebox.showinfo("Success", "Encryption and decryption completed. Check ENCRYPTED and DECRYPTED files.")


root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()
