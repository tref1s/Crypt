from flask import Flask, render_template_string, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import base64
import secrets
from pathlib import Path
import io

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

HARDCODED_KEY = b'\xa3\x5e\x1f\x8c\x92\x47\xda\x0b\x34\xe7\x8a\x90\xbc\xfe\x01\x28\x9d\x76\x12\xab\x5c\xcf\x66\x2d\xf0\x11\xb9\x3e\x87\x64\x09\xaa'

class CryptManager:
    
    def __init__(self):
        self.keys_dir = Path("keys")
        self.master_key_file = self.keys_dir / "master_key.json"
        self.user_keys_file = self.keys_dir / "user_keys.json"
        self.keys_dir.mkdir(exist_ok=True)
        self.master_key = None
        self.user_key = None
        self.load_or_generate_master_key()
        self.load_or_generate_user_key()
    
    def encrypt_with_hardcoded_key(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(HARDCODED_KEY), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def decrypt_with_hardcoded_key(self, encrypted_data: bytes) -> bytes:
        try:
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            cipher = Cipher(algorithms.AES(HARDCODED_KEY), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Ошибка при дешифровании мастер-ключа: {str(e)}")
    
    def load_or_generate_master_key(self):
        if not self.master_key_file.exists():
            print("Генерируется новый мастер-ключ...")
            self.master_key = os.urandom(32)
            self.save_master_key()
        else:
            self.load_master_key()
    
    def save_master_key(self):
        encrypted_master_key = self.encrypt_with_hardcoded_key(self.master_key)
        key_data = {
            'master_key': base64.b64encode(encrypted_master_key).decode(),
        }
        with open(self.master_key_file, 'w', encoding='utf-8') as f:
            json.dump(key_data, f, indent=2, ensure_ascii=False)
    
    def load_master_key(self):
        try:
            with open(self.master_key_file, 'r', encoding='utf-8') as f:
                key_data = json.load(f)
            encrypted_master_key = base64.b64decode(key_data['master_key'])
            self.master_key = self.decrypt_with_hardcoded_key(encrypted_master_key)
        except Exception as e:
            print(f"Ошибка при загрузке мастер-ключа: {e}")
            self.master_key = None
    
    def encrypt_with_master_key(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def decrypt_with_master_key(self, encrypted_data: bytes) -> bytes:
        try:
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Ошибка при дешифровании пользовательского ключа: {str(e)}")
    
    def load_or_generate_user_key(self):
        if self.master_key is None:
            raise ValueError("Мастер-ключ не загружен")
        if not self.user_keys_file.exists():
            print("Генерируется новый пользовательский ключ...")
            self.user_key = os.urandom(32)
            self.save_user_key()
        else:
            self.load_user_key()
    
    def save_user_key(self):
        encrypted_user_key = self.encrypt_with_master_key(self.user_key)
        key_data = {
            'user_key': base64.b64encode(encrypted_user_key).decode(),
        }
        with open(self.user_keys_file, 'w', encoding='utf-8') as f:
            json.dump(key_data, f, indent=2, ensure_ascii=False)
    
    def load_user_key(self):
        try:
            with open(self.user_keys_file, 'r', encoding='utf-8') as f:
                key_data = json.load(f)
            encrypted_user_key = base64.b64decode(key_data['user_key'])
            self.user_key = self.decrypt_with_master_key(encrypted_user_key)
        except Exception as e:
            print(f"Ошибка при загрузке пользовательского ключа: {e}")
            self.user_key = None
    
    def encrypt_message(self, message: str) -> str:
        if not message:
            return ""
        try:
            message_bytes = message.encode('utf-8')
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.user_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
            encrypted_data = {
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(encryptor.tag).decode()
            }
            return base64.b64encode(json.dumps(encrypted_data).encode()).decode()
        except Exception as e:
            return f"Ошибка шифрования: {str(e)}"
    
    def decrypt_message(self, encrypted_message: str) -> str:
        if not encrypted_message:
            return ""
        try:
            encrypted_data = json.loads(base64.b64decode(encrypted_message).decode())
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            cipher = Cipher(algorithms.AES(self.user_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            return f"Ошибка дешифрования: {str(e)}"
    
    def delete_master_key(self):
        if self.master_key_file.exists():
            self.master_key_file.unlink()
        if self.user_keys_file.exists():
            self.user_keys_file.unlink()
        self.master_key = None
        self.user_key = None
        self.load_or_generate_master_key()
        self.load_or_generate_user_key()
    
    def delete_user_key(self):
        if self.user_keys_file.exists():
            self.user_keys_file.unlink()
        self.user_key = None
        self.load_or_generate_user_key()
    
    def delete_both_keys(self):
        self.delete_master_key()

crypt_manager = CryptManager()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypt | Современное криптографическое приложение</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-bg: linear-gradient(135deg, #0a0a2a, #1a1a5f, #0d0d33);
            --card-bg: rgba(255, 255, 255, 0.08);
            --card-border: rgba(255, 255, 255, 0.15);
            --text-primary: #ffffff;
            --text-secondary: rgba(255, 255, 255, 0.7);
            --accent-encrypt: #2a5ee0;
            --accent-decrypt: #4287f5;
            --accent-hover: #3a75f0;
            --success: #10b981;
            --error: #ef4444;
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }

        body {
            background: var(--primary-bg);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            padding: 20px;
            overflow-x: hidden;
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
        }

        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .container {
            max-width: 1600px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 30px;
        }

        .header {
            text-align: center;
            padding: 20px 0;
            margin-bottom: 10px;
            animation: fadeIn 0.8s ease-out;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .logo-icon {
            background: linear-gradient(135deg, var(--accent-encrypt), var(--accent-decrypt));
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            box-shadow: var(--shadow);
        }

        .header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(to right, var(--accent-encrypt), var(--accent-decrypt));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 10px;
        }

        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
            max-width: 600px;
            margin: 0 auto;
            line-height: 1.7;
        }

        .key-management {
            display: flex;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
            animation: slideUp 0.6s ease-out;
        }

        .crypto-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(450px, 1fr));
            gap: 25px;
            max-width: 1250px;
            margin: 0 auto;
            width: 100%;
        }

        @media (max-width: 1100px) {
            .crypto-grid {
                grid-template-columns: 1fr;
                max-width: 800px;
            }
        }

        .crypto-section {
            background: var(--card-bg);
            border-radius: 16px;
            padding: 25px;
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            box-shadow: var(--shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            animation: fadeIn 0.8s ease-out;
        }

        .crypto-section:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }

        .crypto-section.encrypt { 
            border-top: 4px solid var(--accent-encrypt);
        }

        .crypto-section.decrypt { 
            border-top: 4px solid var(--accent-decrypt);
        }

        .crypto-section h3 {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .section-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        .encrypt .section-icon {
            background: rgba(42, 94, 224, 0.2);
            color: var(--accent-encrypt);
        }

        .decrypt .section-icon {
            background: rgba(66, 135, 245, 0.2);
            color: var(--accent-decrypt);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9rem;
        }

        textarea {
            width: 100%;
            min-height: 150px;
            padding: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.15);
            color: var(--text-primary);
            font-family: 'Roboto Mono', monospace;
            font-size: 15px;
            resize: vertical;
            transition: all 0.3s ease;
        }

        textarea:focus {
            outline: none;
            border-color: rgba(66, 135, 245, 0.4);
            box-shadow: 0 0 0 3px rgba(66, 135, 245, 0.2);
        }

        .btn-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }

        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 120px;
            justify-content: center;
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .btn:active {
            transform: translateY(1px);
        }

        .btn-encrypt {
            background: var(--accent-encrypt);
            color: white;
        }

        .btn-encrypt:hover {
            background: var(--accent-hover);
            box-shadow: 0 4px 15px rgba(42, 94, 224, 0.4);
        }

        .btn-decrypt {
            background: var(--accent-decrypt);
            color: white;
        }

        .btn-decrypt:hover {
            background: var(--accent-hover);
            box-shadow: 0 4px 15px rgba(66, 135, 245, 0.4);
        }

        .btn-key {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.15);
        }

        .btn-key:hover {
            background: rgba(255, 255, 255, 0.2);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        .btn-icon {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.15);
            min-width: auto;
            padding: 12px 15px;
        }

        .btn-icon:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .status {
            text-align: center;
            padding: 15px;
            border-radius: 12px;
            opacity: 0;
            transition: opacity 0.3s ease;
            margin-top: 20px;
            backdrop-filter: blur(10px);
        }

        .status.show {
            opacity: 1;
        }

        .status.success {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status.error {
            background: rgba(239, 68, 68, 0.15);
            color: #ff0000;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .file-input {
            display: none;
        }

        .info-section {
            background: var(--card-bg);
            border-radius: 16px;
            padding: 25px;
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            margin-top: 10px;
            animation: fadeIn 0.8s ease-out;
            max-width: 1250px;
            margin: 0 auto;
            width: 100%;
        }

        .info-section h3 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1.3rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }

        .feature {
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }

        .feature i {
            background: rgba(66, 135, 245, 0.15);
            color: var(--accent-decrypt);
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            flex-shrink: 0;
        }

        .feature div h4 {
            color: var(--text-primary);
            margin-bottom: 5px;
            font-size: 1rem;
        }

        .feature div p {
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.6;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 768px) {
            .crypto-grid {
                grid-template-columns: 1fr;
                max-width: 100%;
            }
            
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2.2rem;
            }
            
            .btn {
                min-width: 100px;
                padding: 10px 15px;
                font-size: 13px;
            }
            
            .btn-icon {
                padding: 10px;
            }
            
            .key-management {
                gap: 10px;
            }
            
            .logo-icon {
                width: 50px;
                height: 50px;
                font-size: 24px;
            }
        }

        @media (max-width: 480px) {
            .btn-group {
                justify-content: center;
            }
            
            .btn {
                flex-grow: 1;
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
            
            .header p {
                font-size: 0.95rem;
            }
            
            .crypto-section {
                padding: 20px;
            }
            
            .features {
                grid-template-columns: 1fr;
            }
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            z-index: 1000;
            animation: fadeIn 0.3s ease;
        }

        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: linear-gradient(135deg, #141432, #1d1d5a);
            padding: 30px;
            border-radius: 16px;
            border: 1px solid rgba(66, 135, 245, 0.3);
            max-width: 450px;
            width: 90%;
            text-align: center;
            animation: modalAppear 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.5);
        }

        @keyframes modalAppear {
            0% { opacity: 0; transform: translate(-50%, -45%) scale(0.95); }
            100% { opacity: 1; transform: translate(-50%, -50%) scale(1); }
        }

        .modal-title {
            font-size: 1.6rem;
            margin-bottom: 15px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }

        .modal-text {
            color: var(--text-secondary);
            margin-bottom: 25px;
            line-height: 1.6;
            font-size: 1rem;
        }

        .modal-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .modal-btn {
            padding: 12px 25px;
            border: none;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            background: linear-gradient(135deg, var(--accent-encrypt), var(--accent-decrypt));
            color: white;
            box-shadow: 0 4px 15px rgba(42, 94, 224, 0.3);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .modal-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(42, 94, 224, 0.4);
        }

        .modal-btn:active {
            transform: translateY(1px);
        }

        .modal-btn-cancel {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: none;
        }

        .modal-btn-cancel:hover {
            background: rgba(255, 255, 255, 0.2);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        /* Уведомления */
        #notifications {
            position: fixed;
            top: 20px;
            left: 20px;
            z-index: 2000;
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-width: 400px;
            width: calc(100% - 40px);
            pointer-events: none;
        }

        .notification {
            padding: 16px 20px;
            border-radius: 12px;
            font-size: 0.95rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
            background: linear-gradient(135deg, rgba(20, 20, 50, 0.95), rgba(29, 29, 90, 0.95));
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            transform: translateX(-120%);
            animation: slideIn 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55) forwards;
            pointer-events: all;
        }

        .notification.success {
            border-left: 4px solid var(--success);
        }

        .notification.error {
            border-left: 4px solid var(--error);
        }

        .notification i {
            font-size: 1.2rem;
        }

        .notification.success i {
            color: var(--success);
        }

        .notification.error i {
            color: var(--error);
        }

        @keyframes slideIn {
            0% {
                transform: translateX(-120%);
                opacity: 0;
            }
            100% {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes slideOut {
            0% {
                transform: translateX(0);
                opacity: 1;
            }
            100% {
                transform: translateX(-120%);
                opacity: 0;
            }
        }

        .notification.slide-out {
            animation: slideOut 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55) forwards;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-lock"></i>
                </div>
            </div>
            <h1>Crypt</h1>
            <p>Приложение для безопасного шифрования и дешифрования данных с использованием алгоритма AES-256-GCM</p>
        </div>
        
        <div class="key-management">
            <button class="btn btn-key" onclick="showExportModal()">
                <i class="fas fa-file-export"></i> Экспорт ключей
            </button>
            <button class="btn btn-key" onclick="document.getElementById('import-file').click()">
                <i class="fas fa-file-import"></i> Импорт ключей
            </button>
            <button class="btn btn-key" onclick="showDeleteModal()">
                <i class="fas fa-trash-alt"></i> Удалить ключи
            </button>
            <input type="file" id="import-file" class="file-input" accept=".json" onchange="importKeys(this)">
        </div>
        
        <div class="crypto-grid">
            <div class="crypto-section encrypt">
                <h3>
                    <div class="section-icon">
                        <i class="fas fa-lock"></i>
                    </div>
                    Шифрование
                </h3>
                <div class="form-group">
                    <label for="plaintext"><i class="fas fa-font"></i> Исходный текст:</label>
                    <textarea id="plaintext" placeholder="Введите текст для шифрования..."></textarea>
                </div>
                <div class="btn-group">
                    <button class="btn btn-encrypt" onclick="encryptText()">
                        <i class="fas fa-lock"></i> Зашифровать
                    </button>
                    <button class="btn btn-icon" onclick="copyToClipboard('plaintext')" title="Скопировать">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-icon" onclick="pasteFromClipboard('plaintext')" title="Вставить">
                        <i class="fas fa-paste"></i>
                    </button>
                    <button class="btn btn-icon" onclick="downloadText('plaintext', 'plaintext.txt')" title="Скачать">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-icon" onclick="document.getElementById('upload-plaintext').click()" title="Загрузить файл">
                        <i class="fas fa-file-upload"></i>
                    </button>
                    <input type="file" id="upload-plaintext" class="file-input" accept=".txt" onchange="uploadText(this, 'plaintext')">
                </div>
            </div>
            <div class="crypto-section encrypt">
                <h3>
                    <div class="section-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    Результат шифрования
                </h3>
                <div class="form-group">
                    <label for="encrypted_result"><i class="fas fa-file-code"></i> Зашифрованные данные:</label>
                    <textarea id="encrypted_result" readonly placeholder="Здесь появится зашифрованный текст..."></textarea>
                </div>
                <div class="btn-group">
                    <button class="btn btn-icon" onclick="copyToClipboard('encrypted_result')" title="Скопировать">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-icon" onclick="downloadText('encrypted_result', 'encrypted.txt')" title="Скачать">
                        <i class="fas fa-download"></i>
                    </button>
                </div>
            </div>
            <div class="crypto-section decrypt">
                <h3>
                    <div class="section-icon">
                        <i class="fas fa-unlock"></i>
                    </div>
                    Дешифрование
                </h3>
                <div class="form-group">
                    <label for="ciphertext"><i class="fas fa-file-code"></i> Зашифрованный текст:</label>
                    <textarea id="ciphertext" placeholder="Введите зашифрованный текст..."></textarea>
                </div>
                <div class="btn-group">
                    <button class="btn btn-decrypt" onclick="decryptText()">
                        <i class="fas fa-unlock"></i> Расшифровать
                    </button>
                    <button class="btn btn-icon" onclick="copyToClipboard('ciphertext')" title="Скопировать">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-icon" onclick="pasteFromClipboard('ciphertext')" title="Вставить">
                        <i class="fas fa-paste"></i>
                    </button>
                    <button class="btn btn-icon" onclick="downloadText('ciphertext', 'ciphertext.txt')" title="Скачать">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-icon" onclick="document.getElementById('upload-ciphertext').click()" title="Загрузить файл">
                        <i class="fas fa-file-upload"></i>
                    </button>
                    <input type="file" id="upload-ciphertext" class="file-input" accept=".txt" onchange="uploadText(this, 'ciphertext')">
                </div>
            </div>
            <div class="crypto-section decrypt">
                <h3>
                    <div class="section-icon">
                        <i class="fas fa-file-alt"></i>
                    </div>
                    Результат дешифрования
                </h3>
                <div class="form-group">
                    <label for="decrypted_result"><i class="fas fa-font"></i> Расшифрованный текст:</label>
                    <textarea id="decrypted_result" readonly placeholder="Здесь появится расшифрованный текст..."></textarea>
                </div>
                <div class="btn-group">
                    <button class="btn btn-icon" onclick="copyToClipboard('decrypted_result')" title="Скопировать">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-icon" onclick="downloadText('decrypted_result', 'decrypted.txt')" title="Скачать">
                        <i class="fas fa-download"></i>
                    </button>
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3><i class="fas fa-shield-alt"></i> О технологии</h3>
            <p style="color: var(--text-secondary); margin-bottom: 15px; line-height: 1.7;">
                Приложение использует алгоритм AES-256-GCM для обеспечения максимальной безопасности ваших данных. 
                AES-256 (Advanced Encryption Standard) - это симметричный алгоритм шифрования, принятый в качестве стандарта правительством США. 
                Режим GCM (Galois/Counter Mode) обеспечивает не только конфиденциальность, но и аутентификацию данных.
            </p>
            
            <div class="features">
                <div class="feature">
                    <i class="fas fa-user-shield"></i>
                    <div>
                        <h4>Безопасность</h4>
                        <p>256-битное шифрование обеспечивает максимальную защиту ваших данных</p>
                    </div>
                </div>
                <div class="feature">
                    <i class="fas fa-bolt"></i>
                    <div>
                        <h4>Производительность</h4>
                        <p>Оптимизированные алгоритмы для быстрого шифрования и дешифрования</p>
                    </div>
                </div>
                <div class="feature">
                    <i class="fas fa-mobile-alt"></i>
                    <div>
                        <h4>Доступность</h4>
                        <p>Полностью адаптивный интерфейс для любых устройств</p>
                    </div>
                </div>
                <div class="feature">
                    <i class="fas fa-cloud"></i>
                    <div>
                        <h4>Конфиденциальность</h4>
                        <p>Все операции выполняются локально, ваши данные не покидают устройство</p>
                    </div>
                </div>
            </div>
        </div>
        <div id="notifications"></div>
        
        <div id="status" class="status" role="alert"></div>
    </div>
    <div id="exportModal" class="modal">
        <div class="modal-content">
            <h2 class="modal-title"><i class="fas fa-file-export"></i> Экспорт ключей</h2>
            <p class="modal-text">Выберите, какие ключи вы хотите экспортировать. Для максимальной безопасности рекомендуется экспортировать ключи по отдельности.</p>
            <div class="modal-buttons">
                <button class="modal-btn" onclick="exportMasterKey()">
                    <i class="fas fa-key"></i> Мастер-ключ
                </button>
                <button class="modal-btn" onclick="exportUserKey()">
                    <i class="fas fa-user-lock"></i> Пользовательский
                </button>
                <button class="modal-btn" onclick="exportBothKeys()">
                    <i class="fas fa-keyboard"></i> Оба ключа
                </button>
            </div>
            <p class="modal-text" style="color: #ff6b6b; font-size: 0.9rem; margin-top: 15px;">
                <i class="fas fa-exclamation-triangle"></i> Экспорт обоих ключей в одном файле не рекомендуется из-за снижения безопасности.
            </p>
            <button class="modal-btn modal-btn-cancel" onclick="closeExportModal()">
                <i class="fas fa-times"></i> Отмена
            </button>
        </div>
    </div>
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <h2 class="modal-title"><i class="fas fa-trash-alt"></i> Удаление ключей</h2>
            <p class="modal-text">Выберите, какие ключи вы хотите удалить. После удаления ключи будут немедленно перегенерированы.</p>
            <div class="modal-buttons">
                <button class="modal-btn" onclick="deleteMasterKey()" style="background: linear-gradient(135deg, #ef4444, #ff6b6b);">
                    <i class="fas fa-key"></i> Мастер-ключ
                </button>
                <button class="modal-btn" onclick="deleteUserKey()" style="background: linear-gradient(135deg, #f59e0b, #fbbf24);">
                    <i class="fas fa-user-lock"></i> Пользовательский
                </button>
            </div>
            <p class="modal-text" style="color: #ff6b6b; font-size: 0.9rem; margin-top: 15px;">
                <i class="fas fa-exclamation-triangle"></i> Удаление мастер-ключа приведет к перегенерации обоих ключей.
            </p>
            <button class="modal-btn modal-btn-cancel" onclick="closeDeleteModal()">
                <i class="fas fa-times"></i> Отмена
            </button>
        </div>
    </div>

    <script>
        function showNotification(message, type = 'info') {
            const notifications = document.getElementById('notifications');
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            
            const icon = type === 'success' ? 'check-circle' : 
                        type === 'error' ? 'exclamation-circle' : 
                        'info-circle';
            
            notification.innerHTML = `
                <i class="fas fa-${icon}"></i>
                <span>${message}</span>
            `;
            
            notifications.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('slide-out');
                setTimeout(() => {
                    notifications.removeChild(notification);
                }, 500);
            }, 3000);
        }

        function showStatus(message, isError = false) {
            showNotification(message, isError ? 'error' : 'success');
        }

        async function encryptText() {
            const plaintext = document.getElementById('plaintext').value;
            if (!plaintext.trim()) {
                showStatus('Введите текст для шифрования', true);
                return;
            }
            
            const encryptBtn = document.querySelector('.btn-encrypt');
            const originalHtml = encryptBtn.innerHTML;
            encryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Шифрование...';
            encryptBtn.disabled = true;
            
            try {
                const response = await fetch('/encrypt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        message: plaintext
                    })
                });
                
                const result = await response.json();
                
                if (!result.success) {
                    throw new Error(result.error || 'Ошибка шифрования');
                }
                
                document.getElementById('encrypted_result').value = result.encrypted;
                showStatus('Текст успешно зашифрован!');
            } catch (error) {
                showStatus('Ошибка при шифровании: ' + error.message, true);
            } finally {
                encryptBtn.innerHTML = originalHtml;
                encryptBtn.disabled = false;
            }
        }

        async function decryptText() {
            const ciphertext = document.getElementById('ciphertext').value;
            if (!ciphertext.trim()) {
                showStatus('Введите зашифрованный текст', true);
                return;
            }
            
            const decryptBtn = document.querySelector('.btn-decrypt');
            const originalHtml = decryptBtn.innerHTML;
            decryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Дешифрование...';
            decryptBtn.disabled = true;
            
            try {
                const response = await fetch('/decrypt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        encrypted: ciphertext
                    })
                });
                
                const result = await response.json();
                
                if (!result.success) {
                    throw new Error(result.error || 'Ошибка дешифрования');
                }
                
                document.getElementById('decrypted_result').value = result.decrypted;
                showStatus('Текст успешно расшифрован!');
            } catch (error) {
                showStatus('Ошибка при дешифровании: ' + error.message, true);
            } finally {
                decryptBtn.innerHTML = originalHtml;
                decryptBtn.disabled = false;
            }
        }

        function showExportModal() {
            document.getElementById('exportModal').style.display = 'block';
        }

        function closeExportModal() {
            document.getElementById('exportModal').style.display = 'none';
        }

        async function exportMasterKey() {
            closeExportModal();
            try {
                showStatus('Экспорт мастер-ключа...');
                const response = await fetch('/export_master_key');
                if (!response.ok) throw new Error('Ошибка экспорта');
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'master_key.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showStatus('Мастер-ключ экспортирован!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        async function exportUserKey() {
            closeExportModal();
            try {
                showStatus('Экспорт пользовательского ключа...');
                const response = await fetch('/export_user_key');
                if (!response.ok) throw new Error('Ошибка экспорта');
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'user_key.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showStatus('Пользовательский ключ экспортирован!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        async function exportBothKeys() {
            closeExportModal();
            try {
                showStatus('Экспорт обоих ключей...');
                const response = await fetch('/export_both_keys');
                if (!response.ok) throw new Error('Ошибка экспорта');
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'keys.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showStatus('Оба ключа экспортированы!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        async function importKeys(input) {
            const file = input.files[0];
            if (!file) return;
            
            try {
                showStatus('Импорт ключей...');
                const fileContent = await file.text();
                
                const response = await fetch('/import_keys', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ key_data: fileContent })
                });
                
                const result = await response.json();
                
                if (!result.success) {
                    throw new Error(result.error);
                }
                
                showStatus('Ключи успешно импортированы!');
            } catch (error) {
                showStatus('Ошибка при импорте: ' + error.message, true);
            } finally {
                input.value = '';
            }
        }

        function showDeleteModal() {
            document.getElementById('deleteModal').style.display = 'block';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }

        async function deleteMasterKey() {
            closeDeleteModal();
            try {
                showStatus('Удаление мастер-ключа...');
                const response = await fetch('/delete_master_key', { method: 'POST' });
                const result = await response.json();
                if (!result.success) throw new Error(result.error);
                clearAllFields();
                showStatus('Мастер-ключ удален, оба ключа перегенерированы!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        async function deleteUserKey() {
            closeDeleteModal();
            try {
                showStatus('Удаление пользовательского ключа...');
                const response = await fetch('/delete_user_key', { method: 'POST' });
                const result = await response.json();
                if (!result.success) throw new Error(result.error);
                clearAllFields();
                showStatus('Пользовательский ключ удален и перегенерирован!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        async function deleteBothKeys() {
            closeDeleteModal();
            try {
                showStatus('Удаление обоих ключей...');
                const response = await fetch('/delete_both_keys', { method: 'POST' });
                const result = await response.json();
                if (!result.success) throw new Error(result.error);
                clearAllFields();
                showStatus('Оба ключа удалены и перегенерированы!');
            } catch (error) {
                showStatus('Ошибка: ' + error.message, true);
            }
        }

        function clearAllFields() {
            document.getElementById('plaintext').value = '';
            document.getElementById('encrypted_result').value = '';
            document.getElementById('ciphertext').value = '';
            document.getElementById('decrypted_result').value = '';
        }

        window.onclick = function(event) {
            const exportModal = document.getElementById('exportModal');
            const deleteModal = document.getElementById('deleteModal');
            if (event.target === exportModal) closeExportModal();
            if (event.target === deleteModal) closeDeleteModal();
        }

        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeExportModal();
                closeDeleteModal();
            }
        });

        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey) {
                if (e.key === 'e') {
                    e.preventDefault();
                    encryptText();
                } else if (e.key === 'd') {
                    e.preventDefault();
                    decryptText();
                }
            }
        });

        async function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            if (!element.value.trim()) {
                showStatus('Поле пустое, нечего копировать', true);
                return;
            }
            
            try {
                await navigator.clipboard.writeText(element.value);
                
                const copyBtn = document.querySelector(`[onclick="copyToClipboard('${elementId}')"]`);
                const originalHtml = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                
                setTimeout(() => {
                    copyBtn.innerHTML = originalHtml;
                }, 2000);
                
                showStatus('Скопировано в буфер обмена!');
            } catch (error) {
                showStatus('Ошибка при копировании: ' + error.message, true);
            }
        }

        async function pasteFromClipboard(elementId) {
            try {
                const text = await navigator.clipboard.readText();
                if (!text) {
                    throw new Error('Буфер обмена пуст');
                }
                document.getElementById(elementId).value = text;
                showStatus('Текст вставлен из буфера обмена!');
            } catch (error) {
                showStatus('Ошибка при вставке: ' + error.message, true);
            }
        }

        function downloadText(elementId, filename) {
            const text = document.getElementById(elementId).value;
            if (!text.trim()) {
                showStatus('Поле пустое, нечего скачивать', true);
                return;
            }
            
            try {
                const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                showStatus('Файл успешно скачан!');
            } catch (error) {
                showStatus('Ошибка при скачивании: ' + error.message, true);
            }
        }

        async function uploadText(input, elementId) {
            const file = input.files[0];
            if (!file) return;
            
            try {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    try {
                        const text = e.target.result;
                        document.getElementById(elementId).value = text;
                        showStatus('Текст успешно загружен из файла!');
                    } catch (error) {
                        showStatus('Ошибка при чтении файла: ' + error.message, true);
                    }
                };
                
                reader.onerror = function() {
                    showStatus('Ошибка при чтении файла', true);
                };
                
                reader.readAsText(file, 'utf-8');
            } catch (error) {
                showStatus('Ошибка при загрузке файла: ' + error.message, true);
            } finally {
                input.value = '';
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        message = data.get('message', '')
        encrypted = crypt_manager.encrypt_message(message)
        return jsonify({'success': True, 'encrypted': encrypted})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        encrypted = data.get('encrypted', '')
        decrypted = crypt_manager.decrypt_message(encrypted)
        return jsonify({'success': True, 'decrypted': decrypted})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/export_master_key')
def export_master_key():
    try:
        with open(crypt_manager.master_key_file, 'r', encoding='utf-8') as f:
            master_key_data = json.load(f)
        export_data = {'master_key': master_key_data['master_key']};
        key_data = json.dumps(export_data, indent=2, ensure_ascii=False)
        return send_file(
            io.BytesIO(key_data.encode('utf-8')),
            as_attachment=True,
            download_name='master_key.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/export_user_key')
def export_user_key():
    try:
        with open(crypt_manager.user_keys_file, 'r', encoding='utf-8') as f:
            user_key_data = json.load(f)
        export_data = {'user_key': user_key_data['user_key']};
        key_data = json.dumps(export_data, indent=2, ensure_ascii=False)
        return send_file(
            io.BytesIO(key_data.encode('utf-8')),
            as_attachment=True,
            download_name='user_key.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/export_both_keys')
def export_both_keys():
    try:
        with open(crypt_manager.master_key_file, 'r', encoding='utf-8') as f:
            master_key_data = json.load(f)
        with open(crypt_manager.user_keys_file, 'r', encoding='utf-8') as f:
            user_key_data = json.load(f)
        export_data = {
            'master_key': master_key_data['master_key'],
            'user_key': user_key_data['user_key']
        };
        key_data = json.dumps(export_data, indent=2, ensure_ascii=False)
        return send_file(
            io.BytesIO(key_data.encode('utf-8')),
            as_attachment=True,
            download_name='keys.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/import_keys', methods=['POST'])
def import_keys():
    try:
        data = request.json
        key_data = json.loads(data.get('key_data', ''))
        
        if 'master_key' in key_data:
            with open(crypt_manager.master_key_file, 'w', encoding='utf-8') as f:
                json.dump({'master_key': key_data['master_key']}, f, indent=2, ensure_ascii=False)
            crypt_manager.load_master_key()
            if crypt_manager.master_key is None:
                raise ValueError("Ошибка загрузки мастер-ключа")
        
        if 'user_key' in key_data:
            with open(crypt_manager.user_keys_file, 'w', encoding='utf-8') as f:
                json.dump({'user_key': key_data['user_key']}, f, indent=2, ensure_ascii=False)
            crypt_manager.load_user_key()
            if crypt_manager.user_key is None:
                raise ValueError("Ошибка загрузки пользовательского ключа")
        
        if 'master_key' not in key_data and 'user_key' not in key_data:
            raise ValueError("Неверный формат файла ключей")
        
        return jsonify({'success': True, 'message': 'Ключи импортированы'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_master_key', methods=['POST'])
def delete_master_key():
    try:
        crypt_manager.delete_master_key()
        return jsonify({'success': True, 'message': 'Мастер-ключ удален, оба ключа перегенерированы'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_user_key', methods=['POST'])
def delete_user_key():
    try:
        crypt_manager.delete_user_key()
        return jsonify({'success': True, 'message': 'Пользовательский ключ удален и перегенерирован'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_both_keys', methods=['POST'])
def delete_both_keys():
    try:
        crypt_manager.delete_both_keys()
        return jsonify({'success': True, 'message': 'Ключи удалены и перегенерированы'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def main():
    print("="*60)
    print("🔐 Crypt - Криптографическое приложение")
    print("="*60)
    print("Статус: Инициализация...")
    try:
        print("✅ Cryptography library найдена")
        print("✅ Ключи инициализированы")
        print("✅ Веб-сервер готов к запуску")
        print("="*60)
        print("🌐 Приложение доступно по адресу: http://localhost:5000")
        print("📝 Для остановки нажмите Ctrl+C")
        print("="*60)
        app.run(host='0.0.0.0', port=5000, debug=False)
    except ImportError as e:
        print(f"❌ Ошибка: Не найдена библиотека: {e}")
        print("💡 Установите зависимости: pip install flask cryptography")
    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")

if __name__ == '__main__':
    main()