from encryptions.des import des_encrypt, des_decrypt

def adjust_key_length(key, length=8):
    if len(key) > length:
        return key[:length]
    return key.ljust(length, '0')

def dh_szyfrowanie(tekst, key):
    adjusted_key = adjust_key_length(str(key))
    encrypted_text = des_encrypt(tekst, adjusted_key)
    print(encrypted_text)
    return encrypted_text

def dh_deszyfrowanie(zaszyfrowany_tekst, key):
    adjusted_key = adjust_key_length(str(key))
    decrypted_text = des_decrypt(zaszyfrowany_tekst, adjusted_key)
    return decrypted_text