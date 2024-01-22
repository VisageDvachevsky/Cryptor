import hashlib
import time
import random
import re
import smtplib
import tkinter as tk
from tkinter import ttk, messagebox
from email.mime.text import MIMEText
import json
from datetime import datetime, timedelta
import threading

global error_messages

class EncoderDecoder:
    def __init__(self):
        self.expiration_time = 10
        self.key = self._generate_unique_key()

    def _generate_unique_key(self):
        unique_data = str(time.time()).encode('utf-16')
        hashed_data = hashlib.sha256(unique_data).hexdigest()
        return int(hashed_data, 16)

    def send_key_to_gmail(self, user_email, access_key, language="English"):
        sender_email = "mr.echxo@gmail.com"
        sender_password = "faawfleorzonymsk"

        subject = f'{error_messages[language_var.get()]["subject"]}'
        body = f'{error_messages[language_var.get()]["access_key"]}{access_key}\n{error_messages[language_var.get()]["Expiration"]}{self.expiration_time} {error_messages[language_var.get()]["time_type"]}'

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = user_email

        try:
            smtp_server = smtplib.SMTP("smtp.gmail.com", 587)
            smtp_server.starttls()
            smtp_server.login(sender_email, sender_password)
            smtp_server.sendmail(sender_email, user_email, msg.as_string())
            smtp_server.quit()

            error_message.set(error_messages[language]["access_key_sent"])

        except smtplib.SMTPException as e:  
            error_message.set(error_messages[language]["unknown_error"].format(str(e)))

        except smtplib.SMTPAuthenticationError as e:
            error_message.set(error_messages[language]["unknown_error"].format(str(e)))

        except smtplib.SMTPServerDisconnected as e:
            error_message.set(error_messages[language]["unknown_error"].format(str(e)))

        except Exception as e:
            error_message.set(error_messages[language]["unknown_error"].format(str(e)))

    def _base32encode(self, num):
        charset = "0123456789abcdefghijklmnopqrstuv"
        base32 = ''
        while num > 0:
            num, index = divmod(num, 32)
            base32 = charset[index] + base32
        return base32

    def encode(self, text):
        encoded = [str(len(text))]
        for i, char in enumerate(text):
            num = text.count(char)
            position = f"({bin(i)[2:]})" if num > 1 else ''

            char_code = ord(char)
            char_code_utf16 = char_code.to_bytes(2, byteorder='big').hex()
            char_code_base32 = self._base32encode(int(char_code_utf16, 16))

            encoded_value = f"{num}{char_code_base32}{position}"
            encoded.append(encoded_value)

        sum_of_encoded_numbers = sum(int(encoded_value[0]) for encoded_value in encoded[1:])
        sum_in_hex = hex(sum_of_encoded_numbers ** 5)[2:]
        encoded.append(sum_in_hex)
        return '.'.join(encoded)

    def decode(self, encoded_str):
        def _base32decode(base32):
            charset = "0123456789abcdefghijklmnopqrstuv"
            num = 0
            for char in base32:
                num = num * 32 + charset.index(char)
            return num

        parts = encoded_str.split(".")
        if not parts:
            return ""

        length = int(parts[0])
        decoded_text = ""

        pattern = re.compile(r'(\d)([0-9a-v]+)(\(([01]+)\))?')

        for part in parts[1:-1]:
            match = pattern.match(part)
            if match:
                num = int(match.group(1))
                char_code_base32 = match.group(2)
                position_binary = match.group(4)

                if position_binary is not None:
                    position = int(position_binary, 2)
                else:
                    position = None

                char_code_utf16 = _base32decode(char_code_base32)
                char_code = int.from_bytes(bytes.fromhex(format(char_code_utf16, '04x')), byteorder='big')

                char = chr(char_code)

                if position is not None:
                    decoded_text = decoded_text[:position] + char + decoded_text[position:]
                else:
                    decoded_text += char

        sum_of_encoded_numbers = sum(int(part[0]) for part in parts[1:-1])
        expected_sum = int(parts[-1], 16)

        if sum_of_encoded_numbers ** 5 != expected_sum:
            error_message.set(error_message.set(error_messages[language]["expected_sum"].format(str(e))))
            return

        return decoded_text

    def encrypt(self, number, n=5):
        number_str = str(number)
        encrypted_number_str = ""

        for digit in number_str:
            if digit.isdigit():
                encrypted_digit = (int(digit) + n) % 10
                encrypted_number_str += str(encrypted_digit)

            else:
                encrypted_number_str += digit

        encrypted_number = int(encrypted_number_str)
        return encrypted_number

    def decrypt(self, encrypted_number, n=5):
        encrypted_number_str = str(encrypted_number)
        decrypted_number_str = ""

        for digit in encrypted_number_str:
            if digit.isdigit():
                decrypted_digit = (int(digit) - n) % 10
                decrypted_number_str += str(decrypted_digit)

            else:
                decrypted_number_str += digit

        decrypted_number = int(decrypted_number_str)
        return decrypted_number

    def save_key_to_file(self, key, filename):
        encoded_key = self.encrypt(str(key))

        key_info = {
            "key": encoded_key,
            "creation_time": datetime.now().strftime("%Y:%m:%d:%H:%M"),
            "ExpirationTime": self.expiration_time
        }
        try:
            with open(filename, 'w') as file:
                json.dump(key_info, file)

        except Exception as e:
            error_message.set(f"{error_message.set(error_messages[language]['save_error'])} {str(e)}")

    def is_valid_key(self, user_key, filename):
        try:
            with open(filename, 'r') as file:
                key_info = json.load(file)
                saved_key = key_info.get("key")
                creation_time_str = key_info.get("creation_time")

                saved_key = self.decrypt(saved_key)

                if str(saved_key) == str(user_key): 

                    creation_time = datetime.strptime(creation_time_str, "%Y:%m:%d:%H:%M")
                    expiration_time = creation_time + timedelta(minutes=self.expiration_time)

                    return datetime.now() <= expiration_time

                else:
                    error_message.set(error_message.set(error_messages[language]["old_key"].format(str(e))))

        except FileNotFoundError:
            error_message.set(error_message.set(error_messages[language]["key_file"].format(str(e))))

        except json.JSONDecodeError:
            error_message.set(error_message.set(error_messages[language]['decode_error']))

        except Exception as e:
            error_message.set(error_message.set(error_messages[language]["unknown_error_with_json"]))

        return False

def clear_decoded_text():
    decoded_text.delete("1.0", tk.END)

def generate_key_clicked():
    encoder_decoder = EncoderDecoder()
    secret_key_entry.delete(0, tk.END)
    secret_key_entry.insert(0, str(encoder_decoder.key))
    secret_key_entry.config(state=tk.NORMAL)
    clear_decoded_text()

def encode_text():
    input_text = text_entry.get()
    encoded_str = encoder_decoder.encode(input_text)
    encoded_text.delete("1.0", tk.END)
    encoded_text.insert("1.0", encoded_str)
    clear_decoded_text() 

def decode_text():
    secret_key = secret_key_entry.get()
    try:
        secret_key = int(secret_key)
    except ValueError:
        error_message.set(error_messages[language_var.get()]["invalid_secret_key"])
        clear_decoded_text()
        return

    if not encoder_decoder.is_valid_key(secret_key, 'key_info.json'):
        error_message.set(error_messages[language_var.get()]["invalid_key"])
        clear_decoded_text()
        return 

    encoded_str = encoded_text.get("1.0", tk.END).strip()

    try:
        decoded_word = encoder_decoder.decode(encoded_str)
        decoded_text.delete("1.0", tk.END)
        decoded_text.insert("1.0", decoded_word)
        error_message.set(error_messages[language_var.get()]["decryption_completed"])

    except ValueError as e:
        error_message.set(error_messages[language_var.get()]["invalid_encrypted_text"])
        clear_decoded_text() 

def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email)

def send_access_key():
    user_email = email_entry.get()
    
    if not is_valid_email(user_email):
        error_message.set(error_messages[language_var.get()]['invalid_email'])
        clear_decoded_text() 
        return

    access_key = encoder_decoder.key
    encoder_decoder.save_key_to_file(access_key, 'key_info.json')
    email_result = encoder_decoder.send_key_to_gmail(user_email, access_key)
    error_message.set(email_result)
    secret_key_entry.config(state=tk.NORMAL)
    error_message.set(error_messages[language_var.get()]["email_sent"])
    clear_decoded_text() 

def clear_decoded_text_periodically():
    while True:
        time.sleep(60)  
        clear_decoded_text()

def change_language(event=None):
    selected_language = language_var.get()

    error_messages_translated = error_messages.get(selected_language, {})

    def set_translations(translation):
        try:
            tab_control.tab(0, text=translation["tab1"])
            tab_control.tab(1, text=translation["tab2"])
            text_label.config(text=translation["text_label"])
            encode_button.config(text=translation["encode_button"])
            email_label.config(text=translation["email_label"])
            send_key_button.config(text=translation["send_key_button"])
            secret_key_label.config(text=translation["secret_key_label"])
            decode_button.config(text=translation["decode_button"])
            encoded_text_label.config(text=translation["encoded_text_label"])
            decoded_text_label.config(text=translation["decoded_text_label"])

            result_label.config(text=error_messages_translated.get())

        except:
            pass

    match selected_language:
        case "English":
            set_translations({
                "tab1": "Encrypt",
                "tab2": "Decrypt",
                "text_label": "Enter text to encrypt:",
                "encode_button": "Encrypt",
                "email_label": "Enter your email address to receive the access code:",
                "send_key_button": "Send Access Key",
                "secret_key_label": "Enter the received secret key:",
                "decode_button": "Decrypt",
                "encoded_text_label": "Encrypted text:",
                "decoded_text_label": "Decrypted text:",
            })
        case "Русский":
            set_translations({
                "tab1": "Зашифровать",
                "tab2": "Дешифровать",
                "text_label": "Введите текст для шифрования:",
                "encode_button": "Зашифровать",
                "email_label": "Введите ваш адрес эл.почты для получения кода:",
                "send_key_button": "Отправить ключ доступа",
                "secret_key_label": "Введите полученный секретный ключ:",
                "decode_button": "Дешифровать",
                "encoded_text_label": "Зашифрованный текст:",
                "decoded_text_label": "Расшифрованный текст:",
            })

error_messages = {
    "English": {
        "invalid_email": "Error: Enter a valid email address.",
        "access_key_sent": "Access key successfully sent to the specified address.",
        "invalid_secret_key": "Error: Enter a valid secret key.",
        "invalid_key": "Invalid key or expired key.",
        "decryption_completed": "Decryption completed.",
        "email_sent": "Message with unique code was sent",
        "invalid_encrypted_text": "Error: Enter valid encrypted text.",
        "subject" : "Unique key",
        "access_key" : "Your unique access key:",
        "Expiration" : "It will be valid for: ",
        "time_type" : "minutes",
        "excepted_sum" : "Sum of encrypted numbers do not match excepted sum",
        "save_error" : "Error: with save key in file",
        "old_key" : "Not valid key",
        "key_file" : "File with key not found",
        "decode_error" : "Error: with reading file with key",
        "unknown_error_with_json" : "Unknown error"
    },

    "Русский": {
        "invalid_email": "Ошибка: Введите корректный адрес электронной почты.",
        "access_key_sent": "Ключ доступа успешно отправлен на указанный адрес.",
        "invalid_secret_key": "Ошибка: Введите корректный секретный ключ.",
        "invalid_key": "Неверный ключ или устаревший ключ.",
        "decryption_completed": "Дешифрование завершено.",
        "email_sent": "Сообщение с кодом успешно отправлено",
        "invalid_encrypted_text": "Ошибка: Введите зашифрованный текст.",
        "subject": "Уникальный ключ",
        "access_key" : "Ваш уникальный ключ:",
        "Expiration": "Он будет действителен: ",
        "time_type" : "минут",
        "excepted_sum" : "Сумма зашифрованных чисел не соответствует ожидаемой сумме",
        "save_error" : "Ошибка: при сохранении ключа в файл",
        "old_key" : "Неверный или устаревший ключ",
        "key_file" : "Файл с ключем не найден",
        "decode_error" : "Ошибка: при чтении файла с ключем",
        "unknown_error_with_json" : "Неизвестная ошибка",
    }
}

root = tk.Tk()
root.title("Encoder/Decoder")

error_message = tk.StringVar()
encoder_decoder = EncoderDecoder()

tab_control = ttk.Notebook(root)
encode_tab = ttk.Frame(tab_control)
decode_tab = ttk.Frame(tab_control)
tab_control.add(encode_tab, text="Encrypt")
tab_control.add(decode_tab, text="Decrypt")
tab_control.pack(expand=1, fill="both")

text_label = tk.Label(encode_tab, text="Enter text to encrypt:")
text_label.pack(pady=10)
text_entry = tk.Entry(encode_tab, width=50)
text_entry.pack()

encode_button = tk.Button(encode_tab, text="Encrypt", command=encode_text)
encode_button.pack(pady=10)

email_label = tk.Label(decode_tab, text="Enter your Gmail address to receive the access code:")
email_label.pack(pady=10)
email_entry = tk.Entry(decode_tab, width=50)
email_entry.pack()

send_key_button = tk.Button(decode_tab, text="Send Access Key", command=send_access_key)
send_key_button.pack(pady=10)

secret_key_label = tk.Label(decode_tab, text="Enter the received secret key:")
secret_key_label.pack(pady=10)
secret_key_entry = tk.Entry(decode_tab, width=50, show="*")
secret_key_entry.pack()

decode_button = tk.Button(decode_tab, text="Decrypt", command=decode_text)
decode_button.pack(pady=10)

encoded_text_label = tk.Label(decode_tab, text="Encrypted text:")
encoded_text_label.pack(pady=5)

encoded_text = tk.Text(decode_tab, height=5, width=50)
encoded_text.pack()

decoded_text_label = tk.Label(decode_tab, text="Decrypted text:")
decoded_text_label.pack(pady=5)

decoded_text = tk.Text(decode_tab, height=5, width=50)
decoded_text.pack()

result_label = ttk.Label(decode_tab, textvariable=error_message)
result_label.pack(pady=10)

languages = ["English", "Русский"]

language_var = tk.StringVar()
language_combobox = ttk.Combobox(root, textvariable=language_var, values=languages, state="readonly")
language_combobox.pack()
language_combobox.bind("<<ComboboxSelected>>", change_language)
language_combobox.set("English") 

clear_decoded_text_thread = threading.Thread(target=clear_decoded_text_periodically)
clear_decoded_text_thread.daemon = True  
clear_decoded_text_thread.start()

root.mainloop()