from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password: str) -> bytes:
    hashed_pwd = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed_pwd)

def encrypt_file(file_path: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        original = file.read()
    
    encrypted = fernet.encrypt(original)
    
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(file_path: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    decrypted = fernet.decrypt(encrypted_data)
    
    output_path = file_path[:-4] if file_path.endswith('.enc') else file_path + '.dec'
    
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
