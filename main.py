import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from encryptions.aes import aes_encrypt, aes_decrypt, aes_encrypt_file, aes_decrypt_file
from encryptions.des import des_encrypt, des_decrypt, des_encrypt_file, des_decrypt_file
from encryptions.rsa import rsa_szyfrowanie, rsa_szyfrowanie_plik, rsa_deszyfrowanie_plik, rsa_deszyfrowanie
from encryptions.transposition import columnar_transposition
from encryptions.vigener import vigenere_cipher


class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption/Decryption Application")

        # Set window size and make it non-resizable
        self.master.geometry("850x750")
        self.master.resizable(False, False)

        # Create main container with padding
        self.main_frame = ttk.Frame(master, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Initialize output directory
        self.output_dir = "encrypted_files"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Style configuration
        self.configure_styles()

        # Create sections
        self.create_encryption_method_section()
        self.create_key_section()
        self.create_input_section()
        self.create_output_options_section()
        self.create_action_section()
        self.create_output_section()

    def configure_styles(self):
        style = ttk.Style()
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10))
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))

    def create_encryption_method_section(self):
        # Encryption Method Section
        method_frame = ttk.LabelFrame(self.main_frame, text="Encryption Method", padding="10")
        method_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.method_var = tk.StringVar(value="vigenere")
        methods = [
            ("Vigenere Cipher", "vigenere"),
            ("Columnar Transposition", "columnar"),
            ("AES Encryption", "aes"),
            ("DES Encryption", "des"),
            ("RSA Encryption", "rsa")
        ]

        for i, (text, value) in enumerate(methods):
            ttk.Radiobutton(
                method_frame,
                text=text,
                value=value,
                variable=self.method_var,
                command=self.on_method_change  # Zmienione na self.on_method_change
            ).grid(row=0, column=i, padx=10)

    def create_key_section(self):
        # Usuń istniejący key_frame (jeśli istnieje)
        if hasattr(self, 'key_frame'):
            self.key_frame.destroy()

        # Key Input Section
        self.key_frame = ttk.LabelFrame(self.main_frame, text="Klucze szyfrowania", padding="10")
        self.key_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # Public Key
        ttk.Label(self.key_frame, text="Klucz publiczny:").grid(row=0, column=0, padx=5, pady=(5, 0), sticky=tk.W)
        self.public_key_entry = tk.Text(self.key_frame, height=1, width=50, wrap="none")
        self.public_key_entry.grid(row=0, column=1, padx=5, pady=(5, 0))


        # Sprawdź wybraną metodę szyfrowania
        method = self.method_var.get()
        print(f"Selected method: {method}")

        if method.lower() == 'rsa':
            # Private Key
            ttk.Label(self.key_frame, text="Klucz prywatny:").grid(row=2, column=0, padx=5, pady=(5, 0), sticky=tk.W)
            self.private_key_entry = tk.Text(self.key_frame, height=1, width=50, wrap="none")
            self.private_key_entry.grid(row=2, column=1, padx=5, pady=(5, 0))

        # Informacje o kluczach
        self.key_info = ttk.Label(self.key_frame, text="")
        self.key_info.grid(row=4, column=0, columnspan=2, pady=(10, 0))

    def on_method_change(self):
        """Handle method change: refresh key section and update key requirements."""
        self.create_key_section()  # Odśwież sekcję klucza
        self.update_key_requirements()  # Zaktualizuj wskazówki dotyczące klucza


    def setup_method_selection(self):
        self.method_var = tk.StringVar(value='default')  # Domyślna metoda
        rsa_radio = ttk.Radiobutton(self.main_frame, text="RSA", variable=self.method_var, value='rsa',
                                    command=self.on_method_change)
        aes_radio = ttk.Radiobutton(self.main_frame, text="AES", variable=self.method_var, value='aes',
                                    command=self.on_method_change)

        rsa_radio.grid(row=0, column=0, padx=10, pady=10)
        aes_radio.grid(row=0, column=1, padx=10, pady=10)

    def create_input_section(self):
        # Input Section
        input_frame = ttk.LabelFrame(self.main_frame, text="Input", padding="10")
        input_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # Input method selection
        self.input_var = tk.StringVar(value="text")
        ttk.Radiobutton(
            input_frame,
            text="Direct Text Input",
            value="text",
            variable=self.input_var,
            command=self.toggle_input_method
        ).grid(row=0, column=0, padx=5)

        ttk.Radiobutton(
            input_frame,
            text="Load From File",
            value="file",
            variable=self.input_var,
            command=self.toggle_input_method
        ).grid(row=0, column=1, padx=5)

        # Text input
        self.text_input = tk.Text(input_frame, height=8, width=70)
        self.text_input.grid(row=1, column=0, columnspan=2, pady=10)

        # File input
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, state='readonly', width=50)
        self.file_path_entry.grid(row=0, column=0, padx=5)

        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self.load_file)
        self.browse_button.grid(row=0, column=1, padx=5)

        self.file_frame.grid_remove()

    def create_output_options_section(self):
        # Output Options Section
        method = self.method_var.get()
        if method == 'rsa':
            return

        output_options_frame = ttk.LabelFrame(self.main_frame, text="Output Options", padding="10")
        output_options_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # File naming options
        naming_frame = ttk.Frame(output_options_frame)
        naming_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(naming_frame, text="Output Directory:").grid(row=0, column=0, padx=5)
        self.output_dir_var = tk.StringVar(value=self.output_dir)
        self.output_dir_entry = ttk.Entry(naming_frame, textvariable=self.output_dir_var, width=40)
        self.output_dir_entry.grid(row=0, column=1, padx=5)
        ttk.Button(naming_frame, text="Browse", command=self.choose_output_dir).grid(row=0, column=2, padx=5)

        # File format options
        format_frame = ttk.Frame(output_options_frame)
        format_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)

        self.timestamp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            format_frame,
            text="Add timestamp to filename",
            variable=self.timestamp_var
        ).grid(row=0, column=0, padx=5)

        self.keep_original_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            format_frame,
            text="Keep original file extension",
            variable=self.keep_original_var
        ).grid(row=0, column=1, padx=5)

    def create_action_section(self):
        # Action Buttons Section
        action_frame = ttk.Frame(self.main_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(
            action_frame,
            text="Encrypt",
            command=lambda: self.process(encrypt=True)
        ).grid(row=0, column=0, padx=10)

        ttk.Button(
            action_frame,
            text="Decrypt",
            command=lambda: self.process(encrypt=False)
        ).grid(row=0, column=1, padx=10)

    def create_output_section(self):
        # Output Section
        output_frame = ttk.LabelFrame(self.main_frame, text="Output", padding="10")
        output_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.output_text = tk.Text(output_frame, height=8, width=70, state='disabled')
        self.output_text.grid(row=0, column=0, pady=5)

    def choose_output_dir(self):
        directory = filedialog.askdirectory(initialdir=self.output_dir)
        if directory:
            self.output_dir = directory
            self.output_dir_var.set(directory)

    def generate_output_filename(self, original_filename, operation):
        # Get base filename
        base_name = os.path.splitext(os.path.basename(original_filename))[0] if original_filename else "output"
        extension = os.path.splitext(original_filename)[1] if self.keep_original_var.get() else ".txt"

        # Add timestamp if selected
        if self.timestamp_var.get():
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{base_name}_{operation}_{timestamp}{extension}"
        else:
            filename = f"{base_name}_{operation}{extension}"

        return os.path.join(self.output_dir, filename)

    def save_output(self, content, operation):
        try:
            # Generate filename
            input_filename = self.file_path_var.get() if self.input_var.get() == "file" else None
            output_file = self.generate_output_filename(input_filename, operation)

            # Ensure directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            # Save content
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(content)

            return output_file
        except Exception as e:
            raise ValueError(f"Error saving file: {str(e)}")

    def process(self, encrypt=True):
        try:
            method = self.method_var.get()
            # key = self.key_entry.get()
            key = self.public_key_entry.get("1.0", tk.END).strip()
            private_key = self.private_key_entry.get("1.0", tk.END).strip()
            print(key)
            if not key:
                raise ValueError("Please enter an encryption key.")

            if self.input_var.get() == "file":
                input_file_path = self.file_path_var.get()
                if not input_file_path:
                    raise ValueError("Please select a file to process.")
                output_file_path = self.generate_output_filename(input_file_path,
                                                                 "encrypted" if encrypt else "decrypted")

                if method == "aes":
                    if len(key) not in [16, 24, 32]:
                        raise ValueError("AES key must be 16, 24, or 32 characters long.")
                    if encrypt:
                        aes_encrypt_file(input_file_path, output_file_path, key)
                    else:
                        aes_decrypt_file(input_file_path, output_file_path, key)
                elif method == "des":
                    if len(key) != 8:
                        raise ValueError("DES key must be exactly 8 characters long.")
                    if encrypt:
                        des_encrypt_file(input_file_path, output_file_path, key)
                    else:
                        des_decrypt_file(input_file_path, output_file_path, key)
                elif method == "rsa":
                    if encrypt:
                        rsa_szyfrowanie_plik(input_file_path,output_file_path, key)
                    else:
                        rsa_deszyfrowanie_plik(input_file_path, output_file_path, private_key)

                messagebox.showinfo("Success",
                                    f"Operation completed successfully!\nOutput saved to: {output_file_path}")

            else:
                text = self.text_input.get('1.0', tk.END).strip()
                if not text:
                    raise ValueError("Please enter or load some text to process.")

                if method == "vigenere":
                    result = vigenere_cipher(text, key, encrypt)
                elif method == "columnar":
                    result = columnar_transposition(text, key, encrypt)
                elif method == "aes":
                    if len(key) not in [16, 24, 32]:
                        raise ValueError("AES key must be 16, 24, or 32 characters long.")
                    result = aes_encrypt(text, key) if encrypt else aes_decrypt(text, key)
                elif method == "des":
                    if len(key) != 8:
                        raise ValueError("DES key must be exactly 8 characters long.")
                    result = des_encrypt(text, key) if encrypt else des_decrypt(text, key)
                elif method == "rsa":
                    if encrypt:
                        result = rsa_szyfrowanie(text, key)
                    else:
                        result = rsa_deszyfrowanie(text, private_key)

                self.update_output(result)

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
            self.key_info.config(text="Key must be 16, 24, or 32 characters long for AES-128, AES-192, or AES-256")
        elif method == "des":
            self.key_info.config(text="Key must be exactly 8 characters long")
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

    def save_output(self, data, operation):
        output_file_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if output_file_path:
            with open(output_file_path, 'wb') as file:
                file.write(data)
        return output_file_path

    def encrypt_decrypt(self, encrypt=True):
        try:
            method = self.method_var.get()
            key = self.key_var.get()
            if self.input_var.get() == "file":
                data = self.file_data
            else:
                data = self.text_input.get('1.0', tk.END).encode('utf-8')

            if method == "aes":
                if len(key) not in [16, 24, 32]:
                    raise ValueError("AES key must be 16, 24, or 32 characters long.")
                result = aes_encrypt(data, key) if encrypt else aes_decrypt(data, key)
            elif method == "des":
                if len(key) != 8:
                    raise ValueError("DES key must be exactly 8 characters long.")
                result = des_encrypt(data, key) if encrypt else des_decrypt(data, key)

            # Update output display
            self.update_output(result.decode('utf-8') if not self.input_var.get() == "file" else "Binary data")

            # Save to file
            operation = "encrypted" if encrypt else "decrypted"
            output_file = self.save_output(result, operation)

            messagebox.showinfo(
                "Success",
                f"Operation completed successfully!\nOutput saved to: {output_file}"
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))


def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()