import os
 
import encoder
import decoder
 
 
def generate_new_key():
    
    if os.path.exists(encoder.KEY_FILE):
        print("\nWARNING: a key already exists.")
        print("A new key will replace it, and files encrypted with the")
        print("old key can NO LONGER be decrypted.")
        answer = input("Type 'yes' to continue: ").strip().lower()
        if answer != "yes":
            print("Cancelled. Old key kept.")
            return
    encoder.write_key()
 
 
def show_menu():
    print("\n==============================")
    print("  Secure File Encrypt/Decrypt")
    print("==============================")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Generate a new key")
    print("4. Exit")
 
 
def main():
    while True:
        show_menu()
        choice = input("Choose an option (1-4): ").strip()
 
        if choice == "1":
            encoder.main()
        elif choice == "2":
            decoder.main()
        elif choice == "3":
            generate_new_key()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3 or 4.")
 
 
if __name__ == "__main__":
    main()