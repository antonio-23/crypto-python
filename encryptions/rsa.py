import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Funkcja do szyfrowania tekstu
def rsa_szyfrowanie(text, global_public_key):
    # Załadowanie klucza publicznego RSA
    public_key = RSA.import_key(global_public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Podział tekstu na mniejsze kawałki
    chunk_size = public_key.size_in_bytes() - 42  # Zostawiamy miejsce na padding
    chunks = [text[i:i+chunk_size].encode() for i in range(0, len(text), chunk_size)]

    encrypted_data = b''
    for chunk in chunks:
        encrypted_data += cipher_rsa.encrypt(chunk)

    # Kodowanie w base64, aby łatwiej było przechowywać wynik
    return base64.b64encode(encrypted_data).decode()

def rsa_deszyfrowanie(encrypted_text, global_private_key):
    # Załadowanie klucza prywatnego RSA
    private_key = RSA.import_key(global_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Dekodowanie z base64
    encrypted_data = base64.b64decode(encrypted_text.encode())

    # Odszyfrowanie danych w porcjach
    decrypted_data = b''
    for i in range(0, len(encrypted_data), private_key.size_in_bytes()):
        chunk = encrypted_data[i:i+private_key.size_in_bytes()]
        decrypted_data += cipher_rsa.decrypt(chunk)

    return decrypted_data.decode()
def rsa_szyfrowanie_plik(plik_sciezka, output_file_path, global_public_key):
    print(global_public_key)
    # Załadowanie klucza publicznego RSA
    public_key = RSA.import_key(global_public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Odczytanie pliku
    with open(plik_sciezka, 'rb') as f:
        data = f.read()

    # Odczytanie rozszerzenia pliku
    file_extension = os.path.splitext(plik_sciezka)[1].lstrip('.')

    # Podział pliku na mniejsze kawałki
    chunk_size = public_key.size_in_bytes() - 42  # Zostawiamy miejsce na padding
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    encrypted_data = b''
    for chunk in chunks:
        encrypted_data += cipher_rsa.encrypt(chunk)

    with open(output_file_path, 'wb') as f:
        f.write(encrypted_data)


def rsa_deszyfrowanie_plik(plik_sciezka,output_file_path , global_private_key):
    # Załadowanie klucza prywatnego RSA
    private_key = RSA.import_key(global_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Odczytanie zaszyfrowanego pliku
    with open(plik_sciezka, 'rb') as f:
        encrypted_data = f.read()

    # Podział zaszyfrowanych danych na kawałki
    chunk_size = private_key.size_in_bytes()
    decrypted_data = b''
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i+chunk_size]
        decrypted_data += cipher_rsa.decrypt(chunk)

    # Odczytanie rozszerzenia pliku z nazwy (jeśli zostało zapisane)
    file_extension = os.path.splitext(plik_sciezka)[1].lstrip('.')

    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)
