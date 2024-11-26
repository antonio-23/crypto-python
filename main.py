import os
import tkinter as tk
from random import random
from tkinter import ttk, filedialog, messagebox
import random
from encryptions.aes import aes_encrypt, aes_decrypt, aes_encrypt_file, aes_decrypt_file
from encryptions.des import des_encrypt_file, des_decrypt_file
from encryptions.rsa import rsa_szyfrowanie, rsa_szyfrowanie_plik, rsa_deszyfrowanie_plik, rsa_deszyfrowanie
from encryptions.transposition import columnar_transposition
from encryptions.vigener import vigenere_cipher
from encryptions.dh import *
import time


class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption/Decryption Application")

        # Set window size and make it non-resizable
        self.master.geometry("850x750")
        self.master.resizable(False, False)

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=1, fill='both')

        # Create frames for each tab
        self.encryption_frame = ttk.Frame(self.notebook)
        self.other_frame = ttk.Frame(self.notebook)

        # Add frames to notebook
        self.notebook.add(self.encryption_frame, text='Szyfrowanie/Deszyfrowanie')
        self.notebook.add(self.other_frame, text='Diffie–Hellman')

        # Initialize output directory
        self.output_dir = "encrypted_files"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Style configuration
        self.configure_styles()

        # Create sections in the encryption frame
        self.create_encryption_method_section()
        self.create_key_section()
        self.create_input_section()
        self.create_output_options_section()
        self.create_action_section()
        self.create_output_section()

        # Create other functionalities in the other frame
        self.create_other_functionalities()



    def configure_styles(self):
        style = ttk.Style()
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10))
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))

    def create_encryption_method_section(self):
        # Encryption Method Section
        method_frame = ttk.LabelFrame(self.encryption_frame, text="Metody szyfrowania", padding="10")
        method_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.method_var = tk.StringVar(value="vigenere")
        methods = [
            ("Vigenere", "vigenere"),
            ("Transpozycyjny kolumnowy", "columnar"),
            ("AES", "aes"),
            ("DES", "des"),
            ("RSA", "rsa")
        ]

        for i, (text, value) in enumerate(methods):
            ttk.Radiobutton(
                method_frame,
                text=text,
                value=value,
                variable=self.method_var,
                command=self.on_method_change
            ).grid(row=0, column=i, padx=10)

    def create_key_section(self):
        if hasattr(self, 'key_frame'):
            self.key_frame.destroy()

        self.key_frame = ttk.LabelFrame(self.encryption_frame, text="Klucze szyfrowania", padding="10")
        self.key_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.key_frame, text="Klucz publiczny:").grid(row=0, column=0, padx=5, pady=(5, 0), sticky=tk.W)
        self.public_key_entry = tk.Text(self.key_frame, height=1, width=50, wrap="none")
        self.public_key_entry.grid(row=0, column=1, padx=5, pady=(5, 0))

        method = self.method_var.get()
        if method.lower() == 'rsa':
            ttk.Label(self.key_frame, text="Klucz prywatny:").grid(row=2, column=0, padx=5, pady=(5, 0), sticky=tk.W)
            self.private_key_entry = tk.Text(self.key_frame, height=1, width=50, wrap="none")
            self.private_key_entry.grid(row=2, column=1, padx=5, pady=(5, 0))

        self.key_info = ttk.Label(self.key_frame, text="")
        self.key_info.grid(row=4, column=0, columnspan=2, pady=(10, 0))

    def on_method_change(self):
        self.create_key_section()
        self.update_key_requirements()

    def create_input_section(self):
        input_frame = ttk.LabelFrame(self.encryption_frame, text="Wprowadź", padding="10")
        input_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.input_var = tk.StringVar(value="text")
        ttk.Radiobutton(
            input_frame,
            text="Tekst",
            value="text",
            variable=self.input_var,
            command=self.toggle_input_method
        ).grid(row=0, column=0, padx=5)

        ttk.Radiobutton(
            input_frame,
            text="Plik",
            value="file",
            variable=self.input_var,
            command=self.toggle_input_method
        ).grid(row=0, column=1, padx=5)

        self.text_input = tk.Text(input_frame, height=8, width=70)
        self.text_input.grid(row=1, column=0, columnspan=2, pady=10)

        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, state='readonly', width=50)
        self.file_path_entry.grid(row=0, column=0, padx=5)

        self.browse_button = ttk.Button(self.file_frame, text="Przeglądaj", command=self.load_file)
        self.browse_button.grid(row=0, column=1, padx=5)

        self.file_frame.grid_remove()

    def create_output_options_section(self):
        method = self.method_var.get()
        if method == 'rsa':
            return

        output_options_frame = ttk.LabelFrame(self.encryption_frame, text="Wynik", padding="10")
        output_options_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        naming_frame = ttk.Frame(output_options_frame)
        naming_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(naming_frame, text="Katalog wyjściowy:").grid(row=0, column=0, padx=5)
        self.output_dir_var = tk.StringVar(value=self.output_dir)
        self.output_dir_entry = ttk.Entry(naming_frame, textvariable=self.output_dir_var, width=40)
        self.output_dir_entry.grid(row=0, column=1, padx=5)
        ttk.Button(naming_frame, text="Przeglądaj", command=self.choose_output_dir).grid(row=0, column=2, padx=5)

        format_frame = ttk.Frame(output_options_frame)
        format_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)

        self.timestamp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            format_frame,
            text="Dodaj znacznik czasu do nazwy pliku",
            variable=self.timestamp_var
        ).grid(row=0, column=0, padx=5)

        self.keep_original_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            format_frame,
            text="Zachowaj oryginalną nazwę pliku",
            variable=self.keep_original_var
        ).grid(row=0, column=1, padx=5)

    def create_action_section(self):
        action_frame = ttk.Frame(self.encryption_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(
            action_frame,
            text="Szyfrowanie",
            command=lambda: self.process(encrypt=True)
        ).grid(row=0, column=0, padx=10)

        ttk.Button(
            action_frame,
            text="Deszyfrowanie",
            command=lambda: self.process(encrypt=False)
        ).grid(row=0, column=1, padx=10)

    def create_output_section(self):
        output_frame = ttk.LabelFrame(self.encryption_frame, text="Wynik", padding="10")
        output_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.output_text = tk.Text(output_frame, height=8, width=70, state='disabled')
        self.output_text.grid(row=0, column=0, pady=5)

    def create_other_functionalities(self):
        # Add other functionalities here
        ttk.Label(self.other_frame, text="Other functionalities can be added here.").pack(pady=20)

    def choose_output_dir(self):
        directory = filedialog.askdirectory(initialdir=self.output_dir)
        if directory:
            self.output_dir = directory
            self.output_dir_var.set(directory)

    def generate_output_filename(self, original_filename, operation):
        base_name = os.path.splitext(os.path.basename(original_filename))[0] if original_filename else "output"
        extension = os.path.splitext(original_filename)[1] if self.keep_original_var.get() else ".txt"

        if self.timestamp_var.get():
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{base_name}_{operation}_{timestamp}{extension}"
        else:
            filename = f"{base_name}_{operation}{extension}"

        return os.path.join(self.output_dir, filename)

    def save_output(self, content, operation):
        try:
            input_filename = self.file_path_var.get() if self.input_var.get() == "file" else None
            output_file = self.generate_output_filename(input_filename, operation)

            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(content)

            return output_file
        except Exception as e:
            raise ValueError(f"Error saving file: {str(e)}")

    def process(self, encrypt=True):
        try:
            method = self.method_var.get()
            key = self.public_key_entry.get("1.0", tk.END).strip()
            if not key:
                raise ValueError("Proszę wprowadzić klucz publiczny.")

            private_key = None
            if method.lower() == 'rsa':
                private_key = self.private_key_entry.get("1.0", tk.END).strip()
                if not private_key:
                    raise ValueError("Proszę wprowadzić klucz prywatny.")

            start_time = time.time()  # Start timing

            if self.input_var.get() == "file":
                input_file_path = self.file_path_var.get()
                if not input_file_path:
                    raise ValueError("Proszę wybrać plik do przetworzenia.")
                output_file_path = self.generate_output_filename(input_file_path,
                                                                 "encrypted" if encrypt else "decrypted")

                if method == "aes":
                    if len(key) not in [16, 24, 32]:
                        raise ValueError("AES musi mieć klucz 16, 24 lub 32 znaki.")
                    if encrypt:
                        aes_encrypt_file(input_file_path, output_file_path, key)
                    else:
                        aes_decrypt_file(input_file_path, output_file_path, key)
                elif method == "des":
                    if len(key) != 8:
                        raise ValueError("DES musi mieć klucz 8 znaków.")
                    if encrypt:
                        des_encrypt_file(input_file_path, output_file_path, key)
                    else:
                        des_decrypt_file(input_file_path, output_file_path, key)
                elif method == "rsa":
                    if encrypt:
                        rsa_szyfrowanie_plik(input_file_path, output_file_path, key)
                    else:
                        rsa_deszyfrowanie_plik(input_file_path, output_file_path, private_key)

                messagebox.showinfo("Sukces",
                                    f"Operacja zakończona powodzeniem!\nWynik zapisany do: {output_file_path}")

            else:
                text = self.text_input.get('1.0', tk.END).strip()
                if not text:
                    raise ValueError("Proszę wprowadzić tekst do przetworzenia.")

                if method == "vigenere":
                    result = vigenere_cipher(text, key, encrypt)
                elif method == "columnar":
                    result = columnar_transposition(text, key, encrypt)
                elif method == "aes":
                    if len(key) not in [16, 24, 32]:
                        raise ValueError("AES musi mieć klucz 16, 24 lub 32 znaki.")
                    result = aes_encrypt(text, key) if encrypt else aes_decrypt(text, key)
                elif method == "des":
                    if len(key) != 8:
                        raise ValueError("DES musi mieć klucz 8 znaków.")
                    result = des_encrypt(text, key) if encrypt else des_decrypt(text, key)
                elif method == "rsa":
                    if encrypt:
                        result = rsa_szyfrowanie(text, key)
                    else:
                        result = rsa_deszyfrowanie(text, private_key)

                self.update_output(result)

            end_time = time.time()  # End timing
            elapsed_time = end_time - start_time
            print(f"Czas {('szyfrowania' if encrypt else 'deszyfrowania')}: {elapsed_time:.4f} sekund")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', text)
        self.output_text.config(state='disabled')

    def update_key_requirements(self):
        method = self.method_var.get()
        if method == "aes":
            self.key_info.config(text="Klucz musi mieć długość 16, 24 lub 32 znaków w przypadku AES-128, AES-192 lub AES-256")
        elif method == "des":
            self.key_info.config(text="Klucz musi mieć długość 8 znaków")
        else:
            self.key_info.config(text="")

    def toggle_input_method(self):
        if self.input_var.get() == "file":
            self.text_input.grid_remove()
            self.file_frame.grid()
        else:
            self.text_input.grid()
            self.file_frame.grid_remove()

    def load_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            with open(file_path, 'rb') as file:
                self.file_data = file.read()

    def create_other_functionalities(self):
        # Create a frame to hold all elements
        main_frame = ttk.Frame(self.other_frame)
        main_frame.pack(expand=1, fill='both', padx=10, pady=10)

        # Create frame for generate button at the top
        generate_button_frame = ttk.Frame(main_frame)
        generate_button_frame.pack(fill='x', pady=(0, 10))

        def on_generate_key():
            try:
                private_key_alice = random.randint(1, 10000)
                public_key_alice = 5 ** private_key_alice % 15485857
                private_key_bob = random.randint(1, 10000)
                public_key_bob = 5 ** private_key_bob % 15485857
                data = f'Klucz publiczny Alicji: {public_key_alice}\nKlucz prywatny Alicji: {private_key_alice}\n\nKlucz publiczny Boba: {public_key_bob}\nKlucz prywatny Boba: {private_key_bob}'
                folder = filedialog.askdirectory(title="Wybierz folder do zapisu odszyfrowanego pliku")
                key_file_name = os.path.join(folder, f'klucze Alicji i Boba')
                with open(key_file_name, 'w') as f:
                    f.write(data)
            except ValueError:
                messagebox.showerror("Błąd", "Proszę wprowadzić poprawną liczbę.")

        # Center the generate button
        generate_button_number = ttk.Button(generate_button_frame, text="Generuj", command=on_generate_key)
        generate_button_number.pack(anchor='center')

        # Create a frame to hold the two sections
        split_frame = ttk.Frame(main_frame)
        split_frame.pack(expand=1, fill='both')

        # Create left and right frames with equal weight
        left_frame = ttk.Frame(split_frame)
        right_frame = ttk.Frame(split_frame)

        # Configure grid weights to make columns equal
        split_frame.grid_columnconfigure(0, weight=1)
        split_frame.grid_columnconfigure(1, weight=1)

        # Use grid instead of pack for equal sizing
        left_frame.grid(row=0, column=0, sticky='nsew', padx=5)
        right_frame.grid(row=0, column=1, sticky='nsew', padx=5)

        # Add input and text fields to the left frame
        ttk.Label(left_frame, text="Klucz publiczny:").pack(anchor='w', pady=(0, 5))
        self.input1_left = ttk.Entry(left_frame)
        self.input1_left.pack(fill='x', pady=(0, 10))

        ttk.Label(left_frame, text="Klucz prywatny:").pack(anchor='w', pady=(0, 5))
        self.input2_left = ttk.Entry(left_frame)
        self.input2_left.pack(fill='x', pady=(0, 10))

        # Add start button to the left frame
        start_button_left = ttk.Button(left_frame, text="Rozpocznij", command=self.start_left)
        start_button_left.pack(pady=(10, 0))

        ttk.Label(left_frame, text="Twój tekst:").pack(anchor='w', pady=(0, 5))
        self.text1_left = tk.Text(left_frame, height=5)
        self.text1_left.pack(fill='both', pady=(0, 10))
        self.text1_left.bind('<KeyRelease>', self.update_text2_right)

        ttk.Label(left_frame, text="Tekst drugiej osoby:").pack(anchor='w', pady=(0, 5))
        self.text2_left = tk.Text(left_frame, height=5)
        self.text2_left.pack(fill='both', pady=(0, 10))
        self.text2_left.config(state='disabled')

        # Add input and text fields to the right frame
        ttk.Label(right_frame, text="Klucz publiczny:").pack(anchor='w', pady=(0, 5))
        self.input1_right = ttk.Entry(right_frame)
        self.input1_right.pack(fill='x', pady=(0, 10))

        ttk.Label(right_frame, text="Klucz prywatny:").pack(anchor='w', pady=(0, 5))
        self.input2_right = ttk.Entry(right_frame)
        self.input2_right.pack(fill='x', pady=(0, 10))

        # Add start button to the right frame
        start_button_right = ttk.Button(right_frame, text="Rozpocznij", command=self.start_right)
        start_button_right.pack(pady=(10, 0))

        ttk.Label(right_frame, text="Twój tekst:").pack(anchor='w', pady=(0, 5))
        self.text1_right = tk.Text(right_frame, height=5)
        self.text1_right.pack(fill='both', pady=(0, 10))
        self.text1_right.bind('<KeyRelease>', self.update_text2_left)

        ttk.Label(right_frame, text="Tekst drugiej osoby:").pack(anchor='w', pady=(0, 5))
        self.text2_right = tk.Text(right_frame, height=5)
        self.text2_right.pack(fill='both', pady=(0, 10))
        self.text2_right.config(state='disabled')

    def start_left(self):
        input_public_alice = self.input1_left.get()
        input_private_bob = self.input2_left.get()

        self.secret_key_bob = int(input_public_alice) ** int(input_private_bob) % 15485857

    def start_right(self):
        input_public_bob = self.input1_right.get()
        input_private_alice = self.input2_right.get()

        self.secret_key_alice = int(input_public_bob) ** int(input_private_alice) % 15485857

    def update_text2_right(self, event):
        encrypted_text = dh_szyfrowanie(self.text1_left.get("1.0", tk.END), self.secret_key_bob)
        decrypted_text = dh_deszyfrowanie(encrypted_text, self.secret_key_alice)
        self.text2_right.config(state='normal')
        self.text2_right.delete('1.0', tk.END)
        self.text2_right.insert('1.0', decrypted_text)
        self.text2_right.config(state='disabled')

    def update_text2_left(self, event):
        encrypted_text = dh_szyfrowanie(self.text1_right.get("1.0", tk.END), self.secret_key_alice)
        decrypted_text = dh_deszyfrowanie(encrypted_text, self.secret_key_bob)
        self.text2_left.config(state='normal')
        self.text2_left.delete('1.0', tk.END)
        self.text2_left.insert('1.0', decrypted_text)
        self.text2_left.config(state='disabled')


def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()