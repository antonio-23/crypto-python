def columnar_transposition(text, key, encrypt=True):
    # Store original text and formatting
    original_text = text
    non_alpha_positions = [(i, char) for i, char in enumerate(text) if not char.isalpha()]
    case_map = [c.isupper() if c.isalpha() else None for c in text]

    # Process only alphabetic characters
    processed_text = ''.join(c.upper() for c in text if c.isalpha())
    key = ''.join(filter(str.isalpha, key.upper()))
    key_order = sorted(range(len(key)), key=lambda k: key[k])

    num_cols = len(key)
    if len(processed_text) == 0 or num_cols == 0:
        return original_text

    num_rows = len(processed_text) // num_cols + (1 if len(processed_text) % num_cols else 0)

    if encrypt:
        # Create matrix and fill with padding
        matrix = [[''] * num_cols for _ in range(num_rows)]
        for i, char in enumerate(processed_text):
            row = i // num_cols
            col = i % num_cols
            matrix[row][col] = char

        # Read columns according to key order
        encrypted = ''
        for k in key_order:
            for row in range(num_rows):
                if row * num_cols + k < len(processed_text):
                    encrypted += matrix[row][k]

        return encrypted
    else:
        # Calculate dimensions for decryption
        matrix = [[''] * num_cols for _ in range(num_rows)]

        # Fill matrix column by column according to key order
        pos = 0
        for k in key_order:
            for row in range(num_rows):
                if pos < len(processed_text) and row * num_cols + k < len(processed_text):
                    matrix[row][k] = processed_text[pos]
                    pos += 1

        # Read matrix row by row
        decrypted = ''
        for row in range(num_rows):
            for col in range(num_cols):
                if row * num_cols + col < len(processed_text):
                    decrypted += matrix[row][col]

        # Restore original formatting
        result = list(decrypted)

        # Restore case
        for i, is_upper in enumerate(case_map):
            if is_upper is not None:
                if i < len(result):
                    result[i] = result[i].upper() if is_upper else result[i].lower()

        # Reinsert non-alphabetic characters
        for pos, char in non_alpha_positions:
            if pos <= len(result):
                result.insert(pos, char)

        return ''.join(result)