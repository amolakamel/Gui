import tkinter as tk
from Crypto.Cipher import DES
import base64
from Crypto.Util.Padding import pad, unpad

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Algorithm")

        self.algorithm_var = tk.StringVar()
        self.algorithm_var.set("Caesar Cipher")
        
        self.text_labe2 = tk.Label(self.root, text="Enter key:")
        self.text_labe2.pack()
        
        self.key_entry = tk.Entry(self.root,show="*", width=40)  # Entry widget for key
        self.key_entry.pack()

        self.create_widgets()

    def create_widgets(self):
        # Text Input
        self.text_label = tk.Label(self.root, text="Enter Text:")
        self.text_label.pack()
        
        self.text_input = tk.Text(self.root, height=2, width=40)
        self.text_input.pack()

        # Algorithm Selection
        self.algorithm_label = tk.Label(self.root, text="Select Algorithm:")
        self.algorithm_label.pack()

        algorithms = ["Caesar Cipher", "Vigenere Cipher", "Playfair Cipher","DES"]
        self.algorithm_menu = tk.OptionMenu(self.root, self.algorithm_var, *algorithms)
        self.algorithm_menu.pack()

        # Action Selection
        self.action_var = tk.StringVar()
        self.action_var.set("Encrypt")

        self.action_label = tk.Label(self.root, text="Select Action:")
        self.action_label.pack()

        actions = ["Encrypt", "Decrypt"]
        self.action_menu = tk.OptionMenu(self.root, self.action_var, *actions)
        self.action_menu.pack()

        # Process Button
        self.process_button = tk.Button(self.root, text="Process", command=self.process_text)
        self.process_button.pack()

        # Output Label
        self.output_label = tk.Label(self.root, text="Result:")
        self.output_label.pack()

        self.output_text = tk.Text(self.root, height=5, width=40, state="disabled")
        self.output_text.pack()

    def process_text(self):
        text = self.text_input.get("1.0", "end-1c")
        algorithm = self.algorithm_var.get()
        key = self.key_entry.get()
        action = self.action_var.get()

        if action == "Encrypt":
            result = self.encrypt_text(text, algorithm, key)
        elif action == "Decrypt":
            result = self.decrypt_text(text, algorithm, key)
        else:
            result = "Invalid Action"

        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", result)
        self.output_text.config(state="disabled")

    def encrypt_text(self, text, algorithm, key):
        if algorithm == "Caesar Cipher":
            return self.caesar_cipher(text)
        elif algorithm == "Vigenere Cipher":
            return self.vigenere_encrypt(text, key)
        elif algorithm == "Playfair Cipher":
            return self.playfair_encrypt(text, key)
        elif algorithm == "DES":
            return self.des_encrypt(text, key)
        else:
            return "Invalid Algorithm"

    def decrypt_text(self, text, algorithm, key):
        if algorithm == "Caesar Cipher":
            return self.caesar_cipher(text, decrypt=True)
        elif algorithm == "Vigenere Cipher":
            return self.vigenere_decrypt(text, key)
        elif algorithm == "Playfair Cipher":
            return self.playfair_decrypt(text, key)
        elif algorithm == "DES":
            return self.des_decrypt(text, key)
        else:
            return "Invalid Algorithm"

    def caesar_cipher(self, text, decrypt=False):
        shift = 3  # You can adjust the shift value
        result = ""
        for char in text:
            if char.isalpha():
                shift_amount = shift if not decrypt else -shift
                result += chr((ord(char) - ord('A' if char.isupper() else 'a') + shift_amount) % 26 +
                              ord('A' if char.isupper() else 'a'))
            else:
                result += char
        return result




    def generate_playfair_matrix(self,key):
        # Create a 5x5 matrix filled with zeros
        matrix = [['' for _ in range(5)] for _ in range(5)]
        key = key.upper().replace('J', 'I')
        key += 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

        # Populate the matrix with unique characters from the key
        unique_chars = []
        for char in key:
            if char not in unique_chars:
                unique_chars.append(char)

        row, col = 0, 0
        for char in unique_chars:
            matrix[row][col] = char
            col += 1
            if col == 5:
                col = 0
                row += 1

        return matrix

    def find_char_positions(self,matrix, char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return (i, j)

    def playfair_encrypt(self,plain_text, key):
        key = key.upper().replace('J', 'I')
        matrix = self.generate_playfair_matrix(key)
        plain_text = plain_text.upper().replace('J', 'I')
        pairs = []

        # الحروف المتشابهة بضيف'X' بينهم
        i = 0
        while i < len(plain_text):
            if i == len(plain_text) - 1 or plain_text[i] == plain_text[i + 1]:
                pairs.append(plain_text[i] + 'X')
                i += 1
            else:
                pairs.append(plain_text[i] + plain_text[i + 1])
                i += 2

        # Encrypt each pair
        cipher_text = ''
        for pair in pairs:
            char1, char2 = pair[0], pair[1]
            row1, col1 = self.find_char_positions(matrix, char1)
            row2, col2 = self.find_char_positions(matrix, char2)

            if row1 == row2:
                cipher_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:
                cipher_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            else:
                cipher_text += matrix[row1][col2] + matrix[row2][col1]

        return cipher_text

    def playfair_decrypt(self,cipher_text, key):
        key = key.upper().replace('J', 'I')
        matrix = self.generate_playfair_matrix(key)
        pairs = []

        # Decrypt each pair
        for i in range(0, len(cipher_text), 2):
            pair = cipher_text[i:i + 2]
            char1, char2 = pair[0], pair[1]
            row1, col1 = self.find_char_positions(matrix, char1)
            row2, col2 = self.find_char_positions(matrix, char2)

            if row1 == row2:
                pairs.append(matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5])
            elif col1 == col2:
                pairs.append(matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2])
            else:
                pairs.append(matrix[row1][col2] + matrix[row2][col1])

        # Remove added 'X' and reconstruct the original text
        plain_text = ''.join(pairs).replace('X', '')

        return plain_text

    def vigenere_encrypt(self,plain_text, key):
        key = key.upper()
        encrypted_text = ""
        key_index = 0

        for char in plain_text:
            if char.isalpha():
                if char.isupper():
                    encrypted_text += chr((ord(char) + ord(key[key_index]) - 2 * 65) % 26 + 65)
                else:
                    encrypted_text += chr((ord(char) + ord(key[key_index]) - 2 * 97) % 26 + 97)
                key_index = (key_index + 1) % len(key)
            else:
                encrypted_text += char

        return encrypted_text

    def vigenere_decrypt(self,cipher_text, key):
        key = key.upper()
        decrypted_text = ""
        key_index = 0

        for char in cipher_text:
            if char.isalpha():
                if char.isupper():
                    decrypted_text += chr((ord(char) - ord(key[key_index]) + 26) % 26 + 65)
                else:
                    decrypted_text += chr((ord(char) - ord(key[key_index]) + 26) % 26 + 97)
                key_index = (key_index + 1) % len(key)
            else:
                decrypted_text += char

        return decrypted_text

    def des_encrypt(self, text, key):
#key 8 byte
        key = key.ljust(8, '0')[:8]
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        padded_text = self.pad_text(text)
        encrypted_text = cipher.encrypt(padded_text.encode())
        return base64.b64encode(encrypted_text).decode()

    def des_decrypt(self, text, key):

        key = key.ljust(8, '0')[:8]
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        encrypted_text = base64.b64decode(text)
        decrypted_text = cipher.decrypt(encrypted_text).decode()
        return self.unpad_text(decrypted_text)

    def pad_text(self, text):
        block_size = 8
        pad_size = block_size - len(text) % block_size
        padded_text = text + chr(pad_size) * pad_size
        return padded_text

    def unpad_text(self, text):
        pad_size = ord(text[-1])
        return text[:-pad_size]

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

main()
