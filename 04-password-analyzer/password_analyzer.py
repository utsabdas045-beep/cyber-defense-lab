import math # math is used for mathematical calculations
import re # re is used to search for patterns in text
import string # string contains predefined character sets like lowercase letters, uppercase letters, digits, punctuation
from getpass import getpass # getpass helps us to enter the password without displaying it on the screen


COMMON_WORDS = [ # These are some of the common words that can be found and is used by various people and is very easy to guess and is bulnerable to brute force attack
    "password", "welcome", "admin", "login", "letmein", "iloveyou",
    "monkey", "dragon", "football", "master", "sunshine", "princess",
    "qwerty", "abc123", "123456", "hello", "shadow", "superman",
]


SEQUENCE = [ # These are some of the common sequence that most of the peaple as is also vulnerable attack
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


LEET_MAP = {"@": "a", "0": "o", "1": "l", "3": "e", "$": "s", "5": "s", "7": "t"} # This is used to replace the letter that closely resemble a character with the given character


def normalize(password): # This function is used to normalize the password to all letter instead of the LEET SPACE by first converting it to lower case and then swapping its values
    text = password.lower() # Converts to lower case
    for symbol, letter in LEET_MAP.items(): # Loop to go through every special character present in the password
        text = text.replace(symbol, letter) # Replace the LEET SPACE special character to a letter
    return text # Returne the final text


def has_sequence(password, size=4): # This function is used to detect any predictable sequence
    text = password.lower() # Converts to lower case
    for seq in SEQUENCE: # Loop that runs throughout the SEQUENCE list
        for i in range(len(seq)-size+1): # Creates every possibe group of 'size' character
            part = seq[i:i + size] # Extracts a section of the sequence
            if part in text or part[::-1] in text: # Checks for the sequence of the character
                return True # If yes than true
    return False # Else false


def has_repeated_sequence(password): # Checks for repeated sequence
    if re.search(r"(.)\1{2,}",password): # Uses the re search for any repeated sequence in the password
        return True
    if re.search(r"(.{2,})\1", password): # Uses the re search for any repeated sequence of characters
        return True
    return False


def find_common_word(password): # Check for any common word
    text = normalize(password) # Using normalize function it converts the password a string of a-z character
    for word in COMMON_WORDS: # Checks every word in COMMON_WORD
        if word in text: # Check for the given word in the password
            return word # If yes than return the word
        return None


def calculate_points(password): # Used to calculate the point
    pool = 0; # Initially the point is 0
    if any(c.islower() for c in password): # If it contains any lower case characters than give points
        pool +=26
    if any(c.isupper() for c in password): # If it contains any upper case characters than give points
        pool +=26
    if any(c.isdigit() for c in password): # If it contains any digit that give points
        pool +=10
    if any(c in string.punctuation for c in password): # If it contains any password than give points
        pool += len(string.punctuation)
    if pool == 0: # If not points are givem
        return 0.0
    return len(password) * math.log2(pool) # A function to calculate the final points with the formula : (legth of the passwor) * (log base 2 of points)


def check_password_strength(password): # It is used to check the password strength
    issues = [] # A list for all the issues
    suggestion = [] # A list for all the suggestion
    score = 0 # For score

    score += min(len(password)*2, 30) # To give the initial score which is 30
    if (len(password) < 8): # To check for too short password length
        issues.append("Password too short")
        suggestion.append("Make the password at least 12 characters")
    elif (len(password)<12):
        suggestion.append("Great a long password")

    if any(c.islower() for c in password): # To check for lower case characters
        score += 10
    else:
        issues.append("No lower case characters")
        suggestion.append("Use lower case characters")

    if any(c.isupper() for c in password): # Ro check for upper case characters
        score += 10
    else:
        issues.append("No upper case characters")
        suggestion.append("Use upper case characters")

    if any(c.isdigit() for c in password): # To check for digits in the password
        score += 10
    else:
        issues.append("No digits present")
        suggestion.append("Use digits to make it strong")

    if any(c in string.punctuation for c in password): # To check for puntuations
        score += 10
    else:
        issues.append("No special character used")
        suggestion.append("Use special characters to make it strong")

    points = calculate_points(password)
    score += min(int(points / 80 * 30), 30)

    if has_repeated_sequence(password): # To check for repeated sequence
        score -= 15
        issues.append("Has repeated sequence of characters")
        suggestion.append("Donot use repeated sequence")

    if has_sequence(password): # To check for predictable sequence
        score -= 15
        issues.append("Has a common words")
        suggestion.append("Donot use predicatable and common words")

    score = max(0, min(score, 100))

# To label the type of password
    if score < 30:
        label = "Very Weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Medium"
    elif score < 85:
        label = "Strong"
    else:
        label = "Very Strong"

    return {
        "score": score,
        "label": label,
        "points": round(points, 1),
        "issues": issues,
        "suggestions": suggestion
    }


def show_meter(score): # Shows the final password
    filled = score // 10
    return "[" + "#" * filled + "-" * (10 - filled) + "]"


def print_report(result): # To print the result
    
    print(f"\nStrength : {result['label']}  {show_meter(result['score'])} {result['score']}/100")
    print(f"Points  : about {result['points']} bits")
 
    if result["issues"]:
        print("\nWhy it is weak:")
        for issue in result["issues"]:
            print(f"  - {issue}")
 
    if result["suggestions"]:
        print("\nHow to improve:")
        for tip in result["suggestions"]:
            print(f"  - {tip}")
 
    if not result["issues"] and not result["suggestions"]:
        print("\n YAYYYYY!!! Great password! No problems found.")

def password_checker(): # Function that deal all of it
    
    print("HEYY!! Welcome to the Password Strength Checker!")
    print("(Your password is checked on your computer only and is never saved.)")
 
    while True:
       
        password = getpass("\nEnter your password (or type 'exit' to quit): ;D ")
 
        if password.lower() == "exit":
            print("Thank you for using the Password Strength Checker! Goodbye! :D")
            break
 
        if password == "":
            print("Please enter a password.")
            continue
 
        print_report(check_password_strength(password))
 
 
if __name__ == "__main__":
    password_checker()