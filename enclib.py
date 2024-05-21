import os
import hashlib
import pickle
import errno
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(data, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + cipher_text

def decrypt(cipher_text, password):
    iv = cipher_text[:AES.block_size]
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return plain_text

def list_filepaths(path="data/"):
    filepaths = []
    for root, dirs, files in os.walk(path):
        for file in files:
            full_path = os.path.normpath(os.path.join(root, file))
            filepaths.append(full_path)
    return filepaths

def del_dir(path="data/"):
    if os.path.exists(path):
        shutil.rmtree(path)
        return True
    return False

def unpack_ref(ref):
    ref = pickle.loads(ref)
    for path, data in ref.items():
        directory = os.path.dirname(path)

        try:
            os.makedirs(directory)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        with open(path, 'wb') as file:
            file.write(data)

def get_ref(path="data/"):
    data = {}
    for file in list_filepaths(path):
        with open(file, "rb") as fg:
            info = fg.read()
            data[file] = info
    return pickle.dumps(data)

def create_vault(path="data/", password="password123?", target="DefaultVault"):
    target = f"{target}.vlt"

    # Calculate password hash
    password_hash = hashlib.sha256(password.encode()).digest()

    # Serialize data
    data = get_ref(path)

    # Encrypt data
    encrypted_data = encrypt(data, password)

    # Include password hash in the beginning of the encrypted data
    final_data = password_hash + encrypted_data

    # Delete original files
    del_dir(path)

    # Write encrypted data to file
    with open(target, "wb") as file:
        file.write(final_data)

def extract_vault(vlt="DefaultVault.vlt", password="password123?"):
    with open(vlt, "rb") as file:
        bindata = file.read()

    # Extract password hash and encrypted data
    password_hash = bindata[:32]  # Assuming SHA-256 hash, which is 32 bytes
    encrypted_data = bindata[32:]

    # Calculate password hash for verification
    provided_password_hash = hashlib.sha256(password.encode()).digest()

    # Verify password
    if password_hash != provided_password_hash:
        print("Incorrect password.")
        return

    # Decrypt data
    decrypted_data = decrypt(encrypted_data, password)

    # Unpack and restore files
    unpack_ref(decrypted_data)

    # Remove vault file after extraction
    os.remove(vlt)

def main():
    print("Syntax:")
    print("enc [password] {folder}  - encrypts the given folder. If none given, encrypts the data/ subfolder.")
    print("dec [password] {vault}   - decrypts the given folder. If none given, decrypts the DefaultVault file.")
    print("quit - quits.")

    command = input("Enter command: ").strip().split()

    if command[0] == "enc":
        password = command[1] if len(command) > 1 else "password123?"
        folder = command[2] if len(command) > 2 else "data"
        create_vault(folder, password)
        print("Folder encrypted successfully.")
    elif command[0] == "dec":
        password = command[1] if len(command) > 1 else "password123?"
        folder = command[2] if len(command) > 2 else "DefaultVault"
        extract_vault(folder + ".vlt", password)
        print("Vault decrypted and files extracted successfully.")
    elif command[0] == "quit":
        quit()
    else:
        print("Invalid command.")

if __name__ == "__main__":
    while True:
        main()
