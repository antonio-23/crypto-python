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
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes




class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption/Decryption Application")

        # Set window size and make it non-resizable
        self.master.geometry("850x840")
        self.master.resizable(True, True)

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=1, fill='both')

        # Create frames for each tab
        self.encryption_frame = ttk.Frame(self.notebook)
        self.other_frame = ttk.Frame(self.notebook)
        self.digital_signature_frame = ttk.Frame(self.notebook)

        # Add frames to notebook
        self.notebook.add(self.encryption_frame, text='Szyfrowanie/Deszyfrowanie')
        self.notebook.add(self.other_frame, text='Diffie–Hellman')
        self.notebook.add(self.digital_signature_frame, text='Podpis cyfrowy')

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

        # Create digital signature section
        self.create_digital_signature_section()



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

    def create_digital_signature_section(self):

        # Key Generation Section
        key_gen_frame = ttk.LabelFrame(self.digital_signature_frame, text="Generowanie kluczy", padding="10")
        key_gen_frame.pack(expand=1, fill='both', padx=10, pady=10)

        ttk.Label(key_gen_frame, text="Folder:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(key_gen_frame, textvariable=self.folder_var, width=50)
        self.folder_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_gen_frame, text="Przeglądaj", command=self.choose_folder).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(key_gen_frame, text="Imię:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(key_gen_frame, textvariable=self.name_var, width=50)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(key_gen_frame, text="Nazwisko:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.surname_var = tk.StringVar()
        self.surname_entry = ttk.Entry(key_gen_frame, textvariable=self.surname_var, width=50)
        self.surname_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(key_gen_frame, text="PESEL:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.pesel_var = tk.StringVar()
        self.pesel_entry = ttk.Entry(key_gen_frame, textvariable=self.pesel_var, width=50)
        self.pesel_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(key_gen_frame, text="Adres:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.address_var = tk.StringVar()
        self.address_entry = ttk.Entry(key_gen_frame, textvariable=self.address_var, width=50)
        self.address_entry.grid(row=4, column=1, padx=5, pady=5)

        ttk.Button(key_gen_frame, text="Generuj klucze", command=self.generate_x509_certificate).grid(row=5, column=0,
                                                                                                      columnspan=3,
                                                                                                      pady=10)

        # Document Signing Section
        signing_frame = ttk.LabelFrame(self.digital_signature_frame, text="Podpisywanie", padding="10")
        signing_frame.pack(expand=1, fill='both', padx=10, pady=10)

        ttk.Label(signing_frame, text="Dokument:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.document_path_var = tk.StringVar()
        self.document_path_entry = ttk.Entry(signing_frame, textvariable=self.document_path_var, state='readonly',
                                             width=50)
        self.document_path_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(signing_frame, text="Przeglądaj", command=self.load_document).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(signing_frame, text="Klucz prywatny:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.private_key_entry = tk.Text(signing_frame, height=1, width=50, wrap="none")
        self.private_key_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(signing_frame, text="Przeglądaj", command=self.load_private_key).grid(row=1, column=2, padx=5,
                                                                                         pady=5)

        ttk.Button(signing_frame, text="Podpisz dokument", command=self.sign_document).grid(row=2, column=0,
                                                                                            columnspan=3, pady=10)

        # Signature Verification Section
        verification_frame = ttk.LabelFrame(self.digital_signature_frame, text="Weryfikacja", padding="10")
        verification_frame.pack(expand=1, fill='both', padx=10, pady=10)

        ttk.Label(verification_frame, text="Podpisany plik:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.signed_file_path_var = tk.StringVar()
        self.signed_file_path_entry = ttk.Entry(verification_frame, textvariable=self.signed_file_path_var,
                                                state='readonly', width=50)
        self.signed_file_path_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(verification_frame, text="Przeglądaj", command=self.load_signed_file).grid(row=0, column=2, padx=5,
                                                                                              pady=5)

        ttk.Label(verification_frame, text="Certyfikat:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.certificate_path_var = tk.StringVar()
        self.certificate_path_entry = ttk.Entry(verification_frame, textvariable=self.certificate_path_var,
                                                state='readonly', width=50)
        self.certificate_path_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(verification_frame, text="Przeglądaj", command=self.load_certificate).grid(row=1, column=2, padx=5,
                                                                                              pady=5)

        ttk.Label(verification_frame, text="Łańcuch certyfikatu:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.certificate_chain_path_var = tk.StringVar()
        self.certificate_chain_path_entry = ttk.Entry(verification_frame, textvariable=self.certificate_chain_path_var,
                                                      state='readonly', width=50)
        self.certificate_chain_path_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(verification_frame, text="Przeglądaj", command=self.load_certificate_chain).grid(row=2, column=2,
                                                                                                    padx=5, pady=5)

        ttk.Label(verification_frame, text="Plik:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(verification_frame, textvariable=self.file_path_var, state='readonly',
                                         width=50)
        self.file_path_entry.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(verification_frame, text="Przeglądaj", command=self.load_file).grid(row=3, column=2, padx=5, pady=5)

        ttk.Button(verification_frame, text="Zweryfikuj podpis", command=self.verify_signature).grid(row=4, column=0,
                                                                                                     columnspan=3,
                                                                                                     pady=10)

        ttk.Label(verification_frame, text="Wynik:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.verification_result = tk.Text(verification_frame, height=15, width=70, wrap="none", state='disabled')
        self.verification_result.grid(row=5, column=1, padx=5, pady=5)

    def load_certificate(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.certificate_path_var.set(file_path)

    def load_certificate_chain(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.certificate_chain_path_var.set(file_path)

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)

    def load_document(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.document_path_var.set(file_path)

    def load_signed_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.signed_file_path_var.set(file_path)

    def generate_keys(self):
        # Implement key generation logic here
        messagebox.showinfo("Sukces", "Klucze zostały wygenerowane.")

    def sign_document(self):
        # Implement document signing logic here
        messagebox.showinfo("Sukces", "Dokument został podpisany.")

    def verify_signature(self):
        # Implement signature verification logic here
        self.verification_result.config(state='normal')
        self.verification_result.delete('1.0', tk.END)
        self.verification_result.insert('1.0', "Podpis jest prawidłowy.")
        self.verification_result.config(state='disabled')

    def load_private_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                private_key_pem = file.read()
            self.private_key_entry.delete("1.0", tk.END)
            self.private_key_entry.insert("1.0", private_key_pem)


    def generate_x509_certificate(self):
        try:
            # Retrieve user input
            name = self.name_var.get()
            surname = self.surname_var.get()
            pesel = self.pesel_var.get()
            address = self.address_var.get()
            folder = self.folder_var.get()

            if not all([name, surname, pesel, address, folder]):
                raise ValueError("Wszystkie pola muszą być wypełnione.")

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            intermediate_private_key = serialization.load_pem_private_key(
                self.intermediate_key.encode(),
                password=None,
                backend=default_backend()
            )

            intermediate_cert = x509.load_pem_x509_certificate(
                self.intermediate_cert.encode(),
                default_backend()
            )

            # Wczytanie certyfikatu Root CA
            root_cert = x509.load_pem_x509_certificate(
                self.root_cert.encode(),
                default_backend()
            )

            # Create X.509 certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u""),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u""),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u""),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{name} {surname}"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, pesel),
                x509.NameAttribute(NameOID.STREET_ADDRESS, address),
            ])
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                # Certificate valid for 1 year
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            # Save private key and certificate to files
            private_key_path = os.path.join(folder, "private_key.pem")
            certificate_path = os.path.join(folder, "certificate.pem")

            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(certificate_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            cert_chain_path = os.path.join(folder, "certificate_with_chain.pem")
            with open(cert_chain_path, "wb") as chain_file:
                # Zapisz certyfikat podmiotu
                chain_file.write(certificate.public_bytes(serialization.Encoding.PEM))
                # Zapisz certyfikat Intermediate CA
                chain_file.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
                # Zapisz certyfikat Root CA
                chain_file.write(root_cert.public_bytes(serialization.Encoding.PEM))

            messagebox.showinfo("Sukces", f"Klucz i certyfikat zostały wygenerowane i zapisane w {folder}")

        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def sign_document(self):
        try:
            # Retrieve the document path and private key from the input fields
            document_path = self.document_path_var.get()
            private_key_pem = self.private_key_entry.get("1.0", tk.END).strip()

            if not document_path or not private_key_pem:
                raise ValueError("Proszę wybrać dokument i wprowadzić klucz prywatny.")

            # Load the document
            with open(document_path, 'rb') as f:
                document_data = f.read()

            # Load the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
            )

            # Create the signature
            signature = private_key.sign(
                document_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Save the signature to a file
            signature_path = os.path.join(os.path.dirname(document_path), "signature.sig")
            with open(signature_path, 'wb') as f:
                f.write(signature)

            messagebox.showinfo("Sukces", f"Dokument został podpisany. Podpis zapisany w: {signature_path}")

        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def verify_signature(self):
        try:
            # Retrieve the paths from the input fields
            signed_file_path = self.signed_file_path_var.get()
            certificate_path = self.certificate_path_var.get()
            certificate_chain_path = self.certificate_chain_path_var.get()
            original_file_path = self.file_path_var.get()

            if not all([signed_file_path, certificate_path, original_file_path]):
                raise ValueError("Proszę wybrać podpisany plik, certyfikat oraz oryginalny plik.")

            # Load the signed file
            with open(signed_file_path, 'rb') as f:
                signature = f.read()

            # Load the certificate
            with open(certificate_path, 'rb') as f:
                cert_data = f.read()
            certificate = x509.load_pem_x509_certificate(cert_data)

            # Load the original file
            with open(original_file_path, 'rb') as f:
                original_data = f.read()

            # Verify the signature
            public_key = certificate.public_key()
            public_key.verify(
                signature,
                original_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Extract certificate details
            subject = certificate.subject
            cert_details = f"""
            Imię: {subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.split()[0]}
            Nazwisko: {subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.split()[1]}
            Adres: {subject.get_attributes_for_oid(NameOID.STREET_ADDRESS)[0].value}
            PESEL: {subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value}
            Numer Seryjny: {certificate.serial_number}
            Certyfikat: {certificate}
            Od: {certificate.not_valid_after_utc}
            Do: {certificate.not_valid_after_utc}
            """

            self.verification_result.config(state='normal')
            self.verification_result.delete('1.0', tk.END)
            self.verification_result.insert('1.0', "Podpis jest prawidłowy.\n" + cert_details)
            self.verification_result.config(state='disabled')

        except Exception as e:
            self.verification_result.config(state='normal')
            self.verification_result.delete('1.0', tk.END)
            self.verification_result.insert('1.0', f"Błąd weryfikacji: {str(e)}")
            self.verification_result.config(state='disabled')


def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()