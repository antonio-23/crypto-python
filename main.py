import tkinter as tk
from tkinter import filedialog, messagebox
import string


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

        self.vigenere_radio = tk.Radiobutton(master, text="Vigenère", variable=self.method_var, value="vigenere")
        self.vigenere_radio.pack()

        self.columnar_radio = tk.Radiobutton(master, text="Columnar", variable=self.method_var,
                                             value="columnar")
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
            encrypted = self.vigenere_cipher(text, key, encrypt=True)
        else:
            encrypted = self.columnar_transposition(text, key, encrypt=True)

        # Write encrypted to file
        with open("ENCRYPTED", 'w') as file:
            file.write(encrypted)

        # Decrypt
        if method == "vigenere":
            decrypted = self.vigenere_cipher(encrypted, key, encrypt=False)
        else:
            decrypted = self.columnar_transposition(encrypted, key, encrypt=False)

        # Write decrypted to file
        with open("DECRYPTED", 'w') as file:
            file.write(decrypted)

        messagebox.showinfo("Success", "Encryption and decryption completed. Check ENCRYPTED and DECRYPTED files.")

    def vigenere_cipher(self, text, key, encrypt=True):
        result = []
        key_length = len(key)
        text = ''.join(filter(str.isalpha, text.upper()))

        for i, char in enumerate(text):
            if char in string.ascii_uppercase:
                key_char = key[i % key_length]
                if encrypt:
                    shift = (ord(char) + ord(key_char) - 2 * ord('A')) % 26
                else:
                    shift = (ord(char) - ord(key_char) + 26) % 26
                result.append(chr(shift + ord('A')))
            else:
                result.append(char)

        return ''.join(result)

    def columnar_transposition(self, text, key, encrypt=True):
        key = ''.join(filter(str.isalpha, key.upper()))
        text = ''.join(filter(str.isalpha, text.upper()))
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        num_cols = len(key)
        num_rows = len(text) // num_cols + (len(text) % num_cols > 0)

        if encrypt:
            # Padding the text if necessary
            padding = (num_cols * num_rows) - len(text)
            text += 'X' * padding if padding > 0 else ''

            # Create a grid for columns
            grid = [''] * num_cols
            for i in range(len(text)):
                grid[i % num_cols] += text[i]

            # Read columns in order
            return ''.join(grid[i] for i in key_order)
        else:
            # Create empty grid for decryption
            grid = [''] * num_cols
            for i in range(num_cols):
                grid[key_order[i]] = text[i * num_rows:(i + 1) * num_rows]

            # Read rows
            return ''.join(''.join(grid[j][i] for j in range(num_cols) if i < len(grid[j])) for i in range(num_rows))


root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()
