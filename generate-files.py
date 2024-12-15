import os
import random
import string

def generate_text_file(file_name, size, unit, chunk_size=1024):
    units_multiplier = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }

    file_size_bytes = size * units_multiplier.get(unit, 1)
    bytes_written = 0

    with open(file_name, 'w') as f:
        while bytes_written < file_size_bytes:
            part_size = min(chunk_size, file_size_bytes - bytes_written)
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=part_size))
            f.write(content)
            bytes_written += part_size

    print(f"Plik tekstowy '{file_name}' o rozmiarze {size} {unit} został utworzony.")

def generate_binary_file(file_name, size, unit, chunk_size=1024 * 1024):
    units_multiplier = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }

    file_size_bytes = size * units_multiplier.get(unit, 1)
    bytes_written = 0

    with open(file_name, 'wb') as f:
        while bytes_written < file_size_bytes:
            part_size = min(chunk_size, file_size_bytes - bytes_written)
            f.write(b'\0' * part_size)
            bytes_written += part_size

    print(f"Plik binarny '{file_name}' o rozmiarze {size} {unit} został utworzony.")

def main():
    print("Program do generowania plików tekstowego i binarnego o określonym rozmiarze.")

    # Wybór jednostki
    unit = input("Wybierz jednostkę rozmiaru (B, KB, MB, GB): ").strip().upper()
    if unit not in ['B', 'KB', 'MB', 'GB']:
        print("Nieprawidłowa jednostka. Wybierz B, KB, MB lub GB.")
        return

    # Wybór rozmiaru
    try:
        size = int(input(f"Podaj rozmiar pliku w {unit}: "))
        if size <= 0:
            print("Rozmiar pliku musi być liczbą dodatnią.")
            return
    except ValueError:
        print("Nieprawidłowa wartość. Podaj liczbę całkowitą.")
        return

    # Generowanie plików
    text_file_name = f"{size}{unit}.txt"
    binary_file_name = f"{size}{unit}.bin"

    generate_text_file(text_file_name, size, unit)
    generate_binary_file(binary_file_name, size, unit)

if __name__ == "__main__":
    main()