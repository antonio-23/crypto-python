import string


def vigenere_cipher(text, key, encrypt=True):
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