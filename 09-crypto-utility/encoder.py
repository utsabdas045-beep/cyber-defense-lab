import os # Provides a function to provide an interaction with the OS
from cryptography.fernet import Fernet # Fernet is a class of crytograohy library that uses symmetric library

KEY_FILE = "secret.key" # It holds the secret key

def write_key(): # It is used to write the key
    key = Fernet.generate_key() # It generates the key
    with open(KEY_FILE, "wb") as key_file: # It opens the key and reads it in binary and stores it in key_file
        key_file.write(key)
    print(f"YAYYY New key generated succesfully") # If key is succesfully generated


def load_key(): # It is used to load the key
    if not os.path.exists(KEY_FILE): # It is used to check if the secret key file is present in the system
        print("No key found, creating one key.... ") # It raises an error if no such file found
        write_key() # If no key found than it tells to write a key
    with open(KEY_FILE, "rb") as key_file: # If it is found that it reads binary as stores in key_file and is return as every operation is carried in binary
        return key_file.read()


def select_file(): # It is used to select the file we want to decrypt
    try:
        import tkinter as tk # It is a GUI library
        from tkinter import filedialog # It is for a dialog module
        root = tk.TK() # It is used to create a main tkinter window
        root.withdraw() # It is used to hide the tkinter window that was created
        path = filedialog.askopenfilename(title="Select file name to encrypt") # It opens a file selection dialog
        root.destroy() # It is used to destroy the tkinter window created
        return path # It gives the path of the file that the user want to decrypt
    except Exception:
        return input("Enter the path of the file to encrypt: ").strip() # Raises an error if there is an exception


def encrypt_file(filename): # A function to decrypt the file
    fernet = Fernet(load_key()) # A fernet key is made using the encryption key that will be used to decrypt the file

    with open(filename, "rb") as file: # It will open the plain file in binary read mode 
        original_data = file.read() # It will store the plain file to binary read mode in original_data

    encrypted_data = fernet.encrypt(original_data) # It will encrypt the file in binary using the key

    output_name = filename + ".enc" # It adds an .enc with the output file name
    with open(output_name, "wb") as file: # It write the binary file to normal text file and stores in encrypted data 
        file.write(encrypted_data)

    return output_name # It returns the output


def main():
    print("=== File Encryptor ===")
    filename = select_file() # It is used to select the file name 
 
    if not filename:
        print("No file selected. Exiting.") # Exception when no file selected
        return
 
    try:
        output = encrypt_file(filename) # It gives the encrypted file
        print(f"Success! Encrypted file saved as: {output}")
        print(f"Keep '{KEY_FILE}' safe. Without it, the file cannot be decrypted.")
    except FileNotFoundError:
        print("Error: that file does not exist.")
    except PermissionError:
        print("Error: you don't have permission to read/write that file.")
    except Exception as e:
        print(f"Unexpected error: {e}")
 
 
if __name__ == "__main__":
    main()
