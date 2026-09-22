import math # math is used for mathematical calculations.
import secrets # secrets provides cryptographically secure random choices.
import string # string contains predefined character sets like lowercase letters, uppercase letters, digits, punctuation

# Import two functions from our password_analyzer module that checks the password strength and show its score by analyzing it
from password_analyzer import check_password_strength, show_meter

WORD = [ # This list contains words that can be randomly selected to create a passphrase.
    "apple", "river", "cloud", "tiger", "maple", "stone", "ocean", "piano",
    "garden", "rocket", "candle", "forest", "bridge", "silver", "planet",
    "window", "thunder", "island", "pepper", "castle", "magnet", "violin",
    "harbor", "lantern", "meadow", "falcon", "copper", "jungle", "puzzle",
    "sunset", "anchor", "breeze", "canyon", "dragon", "engine", "feather",
    "glacier", "hammer", "iceberg", "jasmine", "kettle", "ladder", "marble",
    "needle", "orchard", "pillow", "quartz", "ribbon", "saddle", "turtle",
]


# Generate a random password.---------------------
def generate_password(length=12, use_number=True, use_special=True): # length for the lenght of the string and also use_number and use_special to add such numbers and special characters
    group = [string.ascii_lowercase,string.ascii_uppercase] # A group that consits of lowercase and uppercase character

    if use_number: # Checks if the user wants number
        group.append(string.digits) # Adds number to the group if the user want so
    if use_special: # Checks if the user wants special characters
        group.append(string.punctuation) # Adds special character if the user wants so

    password = [secrets.choice(group) for group in group] # it randomly chooses any one from the group list to a list called password

    all_characters = "".join(group) # It combines all the selected character group into one called all_character
    while len(password) < length: # Runs loop for the length of the password
        password.append(secrets.choice(all_characters)) # Randomly adds a character to the password list
    secrets.SystemRandom().shuffle(password) # shuffle the password list to make it more random

    return "".join(password) # Gives us the final password


def generate_passphrase(word_count=4, seperator="-"): # Generates a random paraphrase
    chosen = [] # It will select the randomly selected word
    for _ in range(word_count): # Runs until the number of words are fullfiled
        word = secrets.choice(WORD) # chooses a random word from the word list
        if secrets.choice([True, False]): # If true than uppercase or else lowercase and is completely random
            word = word.capitalize() # Capitalize the word if true 
        chosen.append(word) # gives the final word in the chosen list

    number = str(secrets.randbelow(100)) # Random number between 1 to 100
    return seperator.join(chosen) + seperator + number # Gives the final one by the words and a number between a seperator


def get_number(message, minimum, maximum, default): # Ask the user for a number and validate the input 
    while True:
        value = input(f"{message} [{minimum}-{maximum}, default {default}]: ").strip() # input() waits for the user to enter something and removes unnecessary spaces from the beginging and the end by using .strip()
        if value == "": # If the user presses Enter than it takes default
            return default
        if value.isdigit() and minimum <= int(value) <= maximum: # Checks whether the input contains only digits and also check if that number is between minimum and maximum
            return int(value)
        print(f"Please enter a number between {minimum} and {maximum}.") # If the input was invalid, display an error message and repeat the loop


def ask_yes_no(message): # Asks the user a yes/no
    return input(f"{message} (y/n)").strip().lower() == "y"


def show_strength(password): # Shows the strength of the password
    result = check_password_strength(password)
    print(f"Strength: {result['label']} {show_meter(result['score'])} " f"{result['score']}/100 (entropy ~{result['entropy']} bits)")


def main():
    print("Welcome to the Password Generator!")
 
    while True:
        print("\n1. Generate a password")
        print("2. Generate a passphrase")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()
 
        if choice == "1":
            length = get_number("Enter the password length", 8, 64, 12)
            use_numbers = ask_yes_no("Include numbers?")
            use_special = ask_yes_no("Include special characters?")
 
            password = generate_password(length, use_numbers, use_special)
            print("\nGenerated password:", password)
            show_strength(password)
 
        elif choice == "2":
            count = get_number("How many words", 3, 8, 4)
            passphrase = generate_passphrase(count)
            bits = count * math.log2(len(WORD))
            print("\nGenerated passphrase:", passphrase)
            print(f"Word-based entropy: about {bits:.0f} bits "
                  "(grows quickly with a bigger word list)")
            show_strength(passphrase)
 
        elif choice == "3":
            print("Goodbye! Stay safe online.")
            break
 
        else:
            print("Invalid choice. Please enter 1, 2 or 3.")
 
 
if __name__ == "__main__":
    main()