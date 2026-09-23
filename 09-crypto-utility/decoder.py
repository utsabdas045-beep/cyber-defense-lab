import os # Provides a function to provide an interaction with the OS
from cryptography.fernet import Fernet, InvalidToken # Fernet is a class of crytograohy library that uses symmetric library


KEY_FILE = "secret.key" # It holds the secret key


def load_key(): # It is used to load the key
    if not os.path.exists(KEY_FILE): # It is used to check if the secret key file is present in the system
        raise FileNotFoundError(KEY_FILE) # It raises an error if no such file found
    with open(KEY_FILE, "rb") as key_file: # If it is found that it reads binary as stores in key_file and is return as every operation is carried in binary
        return key_file.read()


def select_file(): # It is used to select the file we want to decrypt
    try:
        import tkinter as tk # It is a GUI library
        from tkinter import filedialog # It is for a dialog module
        root = tk.Tk() # It is used to create a main tkinter window
        root.withdraw() # It is used to hide the tkinter window that was created
        path = filedialog.askopenfilename( # It opens a file selection dialog
            title="Select a file to decrypt",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        root.destroy() # It is used to destroy the tkinter window created
        return path # It gives the path of the file that the user want to decrypt
    except Exception:
        return input("Enter the path of the file to decrypt: ").strip() # Raises an error if there is an exception


def decrypt_file(filename): # It is used to decrypt the selected file
    fernet = Fernet(load_key()) # A fernet key is made using the encryption key that will be used to decrypt the file

    with open(filename, "rb") as file: # It will open the encrypted file in binary read mode 
        encrypter_data = file.read() # Stores the binary data

    decrypted_data = fernet.decrypt(encrypter_data) # Decrpts the encrypted data using fernet if correct key is used nand the encryption data is not modified and valid

    folder, name = os.path.split(filename) # It splits into the folder i.e the directory containing the file and name that contains the actual filename
    if name.endswith("enc"): # Checks wheaher the file contains enc
        name = name[:-4] # Removes the last four character i.e .enc
    output_name = os.path.join(folder, "decrypted_" + name) # Creates an output file with the format decrypted added at the begining of the original filename

    with open(output_name, "wb") as file: # Opens the file that contains the decrypted data in binary and writes it from binary to normal ASCII and stores in output_name variable
        file.write(decrypted_data)

    return output_name # Returns the file


def main():
    print("=== File Decryptor ===")
    filename = select_file() # Select the file name
 
    if not filename:
        print("No file selected. Exiting.") # Exception if no file selected
        return
 
    try:
        output = decrypt_file(filename) # Stores the decrypted file in the output
        print(f"Success! Decrypted file saved as: {output}")
    except FileNotFoundError as e:
        if str(e) == KEY_FILE:
            print(f"Error: '{KEY_FILE}' not found. Put the key in this folder.")
        else:
            print("Error: that file does not exist.")
    except InvalidToken:
        print("Error: decryption failed. Wrong key, or the file was "
              "modified/corrupted (integrity check failed).")
    except PermissionError:
        print("Error: you don't have permission to read/write that file.")
    except Exception as e:
        print(f"Unexpected error: {e}")
 
 
if __name__ == "__main__":
    main()