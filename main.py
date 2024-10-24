import os
import shutil
import zipfile
from tkinter import Tk, Button, Label, filedialog, messagebox
from cryptography.fernet import Fernet
# import pyautogui

# Generate and save a new encryption key
def generate_key():
    key = Fernet.generate_key()
    save_path = filedialog.asksaveasfilename(title="Save Encryption Key", defaultextension=".key", filetypes=[("Key Files", "*.key")])
    if save_path:
        with open(save_path, 'wb') as key_file:
            key_file.write(key)
        messagebox.showinfo("Key Saved", f"Encryption key saved to: {save_path}")
    else:
        messagebox.showwarning("Save Cancelled", "Encryption key generation cancelled.")

# Load encryption key
def load_key():
    key_path = filedialog.askopenfilename(title="Select Encryption Key", filetypes=[("Key Files", "*.key")])
    if key_path:
        with open(key_path, 'rb') as key_file:
            return Fernet(key_file.read())
    else:
        messagebox.showwarning("No Key Selected", "No encryption key selected.")
        return None

# Encrypt a file
def encrypt_file(file_path, cipher):
    with open(file_path, "rb") as file:
        encrypted_data = cipher.encrypt(file.read())
    encrypted_path = f"{file_path}.enc"
    with open(encrypted_path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    return encrypted_path

# Decrypt a file
def decrypt_file(file_path, cipher):
    with open(file_path, "rb") as file:
        decrypted_data = cipher.decrypt(file.read())
    decrypted_path = file_path.replace(".enc", "")
    with open(decrypted_path, "wb") as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path

# Archive and encrypt folder contents while maintaining structure
def archive_and_encrypt():
    folder_path = filedialog.askdirectory(title="Select a Folder to Archive")
    if not folder_path:
        return

    cipher = load_key()
    if not cipher:
        return

    archive_name = f"{os.path.basename(folder_path)}.zip"
    temp_dir = f"{folder_path}_temp"
    os.makedirs(temp_dir, exist_ok=True)

    # Encrypt files and maintain relative structure
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, folder_path)
            encrypted_file = encrypt_file(file_path, cipher)
            encrypted_relative_path = f"{relative_path}.enc"
            dest_path = os.path.join(temp_dir, encrypted_relative_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.move(encrypted_file, dest_path)

    # Create an archive
    with zipfile.ZipFile(archive_name, 'w') as zipf:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, temp_dir)
                zipf.write(file_path, relative_path)

    # Clean up temporary files
    shutil.rmtree(temp_dir)
    messagebox.showinfo("Success", f"Folder archived and encrypted as: {archive_name}")

def unzip_and_decrypt():
    archive_path = filedialog.askopenfilename(title="Select an Archive", filetypes=[("Zip Files", "*.zip")])
    if not archive_path:
        return

    cipher = load_key()
    if not cipher:
        return

    extract_dir = filedialog.askdirectory(title="Select Extraction Directory")
    if not extract_dir:
        return

    # Unzip archive directly into the destination directory
    with zipfile.ZipFile(archive_path, 'r') as zipf:
        zipf.extractall(extract_dir)

    # Walk through the extracted files and decrypt them
    for root, _, files in os.walk(extract_dir):
        for file in files:
            if file.endswith(".enc"):
                encrypted_file_path = os.path.join(root, file)
                decrypted_file_path = encrypted_file_path.replace(".enc", "")
                decrypt_file(encrypted_file_path, cipher)  # Decrypt and write to the correct location
                os.remove(encrypted_file_path)  # Remove encrypted file after decryption

    messagebox.showinfo("Success", f"Archive unzipped and decrypted in: {extract_dir}")


# Create the Tkinter interface
def create_interface():
    root = Tk()
    root.title("Encryption and Archiving Tool")

    Label(root, text="Choose an Action:").grid(row=0, column=0, columnspan=2, pady=10)

    Button(root, text="Generate Encryption Key", command=generate_key, width=30).grid(row=1, column=0, columnspan=2, pady=5)
    Button(root, text="Archive and Encrypt Folder", command=archive_and_encrypt, width=30).grid(row=2, column=0, columnspan=2, pady=5)
    Button(root, text="Unzip and Decrypt Archive", command=unzip_and_decrypt, width=30).grid(row=3, column=0, columnspan=2, pady=5)

    root.mainloop()

# Run the program
if __name__ == "__main__":
    create_interface()
