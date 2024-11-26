import base64

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def des_encrypt(text, key):
    """
    Encrypt text using DES in CBC mode with PKCS7 padding.

    Args:
        text (str): Text to encrypt
        key (str): Encryption key (must be exactly 8 bytes long)

    Returns:
        str: Base64 encoded encrypted text
    """
    try:
        # Convert text and key to bytes
        text_bytes = text.encode('utf-8')
        key_bytes = key.encode('utf-8')

        # Validate key length
        if len(key_bytes) != 8:
            raise ValueError("DES musi mieć klucz 8 znaków.")

        # Create cipher object and generate random IV
        cipher = DES.new(key_bytes, DES.MODE_CBC)

        # Pad the text and encrypt
        padded_text = pad(text_bytes, DES.block_size)
        encrypted_bytes = cipher.encrypt(padded_text)

        # Combine IV and encrypted content
        combined = cipher.iv + encrypted_bytes

        # Encode to base64 for safe storage/transmission
        encoded = base64.b64encode(combined)

        return encoded.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Encryption error: {str(e)}")


def des_decrypt(encrypted_text, key):
    """
    Decrypt DES encrypted text.

    Args:
        encrypted_text (str): Base64 encoded encrypted text
        key (str): Decryption key (must be exactly 8 bytes long)

    Returns:
        str: Decrypted text
    """
    try:
        # Convert key to bytes and decode base64 content
        key_bytes = key.encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_text)

        # Validate key length
        if len(key_bytes) != 8:
            raise ValueError("DES musi mieć klucz 8 znaków.")

        # Extract IV and encrypted content
        iv = encrypted_bytes[:DES.block_size]
        encrypted_content = encrypted_bytes[DES.block_size:]

        # Create cipher object with extracted IV
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)

        # Decrypt and unpad
        decrypted_padded = cipher.decrypt(encrypted_content)
        decrypted = unpad(decrypted_padded, DES.block_size)

        return decrypted.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Decryption error: {str(e)}")

def des_encrypt_file(input_file_path, output_file_path, key):
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 8:
            raise ValueError("DES musi mieć klucz 8 znaków.")

        with open(input_file_path, 'rb') as f:
            file_data = f.read()

        cipher = DES.new(key_bytes, DES.MODE_CBC)
        padded_data = pad(file_data, DES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        combined_data = cipher.iv + encrypted_data

        with open(output_file_path, 'wb') as f:
            f.write(combined_data)

    except Exception as e:
        raise ValueError(f"File encryption error: {str(e)}")

def des_decrypt_file(input_file_path, output_file_path, key):
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 8:
            raise ValueError("DES musi mieć klucz 8 znaków.")

        with open(input_file_path, 'rb') as f:
            combined_data = f.read()

        iv = combined_data[:DES.block_size]
        encrypted_data = combined_data[DES.block_size:]

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, DES.block_size)

        with open(output_file_path, 'wb') as f:
            f.write(decrypted_data)

    except Exception as e:
        raise ValueError(f"File decryption error: {str(e)}")