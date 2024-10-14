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


def columnar_transposition(text, key, encrypt=True):
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
