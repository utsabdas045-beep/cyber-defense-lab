import os # Import the os module for working with files, folder and paths
import json # Import json to store and read the baselin in JSON format
import time # Import time to pause between continous monitoring scans
import hashlib # Import hash to calculate SHA 256 hashes
from datetime import datetime # Import datetime to record the date and time of scans

HASH_FILE = "baseline.json" # The file where the original file hashes are stored
REPORT_FILE = "integrity_report.txt" # The file which stores the reports
CHECK_INTERVAL = 10 # The time to wait between two consecutive scans


# Hashing and Scanning ---------
def calculate_sha256(file_path): # Function to calculate the SHA 256 hash of a file
    sha256 = hashlib.sha256()  # This creates a new SHA-256 hash object.
    try:  # Try to open and read the file.
        with open(file_path, "rb") as f: # Open the file in binary read mode.
            while chunk := f.read(65536): # Read the file in chunks of 65,536 bytes. As reading in chunks avoids loading a large file completely into memory.
                sha256.update(chunk) # Add the current chunk of data to the SHA-256 calculation.

    except (FileNotFoundError, PermissionError): # Handle errors if the file disappears or cannot be accessed.
        return None # Return None when the file cannot be read.
    return sha256.hexdigest() # Return the final SHA-256 hash as a hexadecimal string.


def scan_folder(folder): # Function to scan a folder and calculate hashes for all files.
    # Create an empty dictionary to store: the file path in SHA 256 Hash
    file_hashes = {}

    ignore = {os.path.abspath(HASH_FILE), os.path.abspath(REPORT_FILE)} # Create a set containing files that should NOT be monitored.

    for root, dirs, files in os.walk(folder): # os.walk() goes through the folder and all its subfolders.
        for name in files: # Process every file found in the current folder.
            path = os.path.abspath(os.path.json(root, name)) # Create the complete path of the current file. os.path.join() combines folder and filename.os.path.abspath() converts it into an absolute path.

            if path in ignore: # Skip the file if it is the baseline or report file.
                continue
            file_hash = calculate_sha256(path)  # Calculate the SHA-256 hash of the current file.
            if file_hash:  # Only store the file if its hash was successfully calculated.
                file_hashes[path] = file_hash # Store the file path and its hash in the dictionary.

    return file_hashes # Return the complete dictionary containing all file hashes.


# BASELINE STORAGE-------------------------
def save_baseline(folder, hashes): # Function to save the current folder state as the trusted baseline.
    data = {  # Create a dictionary containing baseline information.
        "folder": os.path.abspath(folder), # Store the absolute path of the monitored folder.
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), # Store the date and time when the baseline was created.
        "files": hashes # Store all file paths and their SHA-256 hashes.
    }
    with open(HASH_FILE, "w") as f: # Open the baseline file in write mode.
        json.dump(data, f, indent=2) # Convert the Python dictionary into JSON.


def load_baseline(): # Function to load the previously saved baseline.
    if not os.path.exists(HASH_FILE): # Check whether the baseline file exists.
        return None # Return None if there is no baseline.
    with open(HASH_FILE, "r") as f: # Open the baseline JSON file in read mode.
        return json.load(f) # Convert the JSON data back into a Python dictionary.


# COMPARING AND REPORTING---------------
def compare(baseline_file, current_file): # Function to compare the trusted baseline with the current scan.
    new = [p for p in current_file if p not in baseline_file] # Find files that exist now but did not exist in the baseline as they are new files.
    deleted = [p for p in baseline_file if p not in current_file] # Find files that were in the baseline but are missing now as they are deleted
    modified = [p for p in current_file if p in baseline_file and baseline_file[p] != current_file[p]] # Find files that existed before and still exist but there sha 256 has changed as they are changes.
    unchanged = len(current_file) - len(new) - len(modified) # Calculate the number of files that have not changed.
    return new, modified, deleted, unchanged # Return all four results.


def build_report(folder, new, modified, deleted, unchanged): # Function to create a human-readable integrity report.
    status = "OK - no changes" if not (new or modified or deleted) else "ALERT - change detected" # If there are no new, modified or deleted files, then status is OK
    line = [
        "=" * 60, # Add a separator line.
        f"Scan time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" # Add the current date and time.
        f"Folder : {folder}", # Add the monitored folder path.
        f"Statue : {status}", # Add the scan status.
        "-" * 60, # Add another separator.
    ]
    for p in modified: # Add every modified file to the report.
        line.append(f"[MODIFIED] {p}") # Add [MODIFIED] before the file path.
    for p in new: # Add every new file to the report.
        line.append(f"[NEW] {p}")  # Add [NEW] before the file path.
    for p in deleted: # Add every deleted file to the report.
        line.append(f"[DELETED] {p}") # Add [DELETED] before the file path.
    lines += [
        "-" * 60, # Add another separator.
        f"Unchanged: {unchanged} | Modified: {len(modified)} | " # Show the number of unchanged, modified, new and deleted files.
        f"New: {len(new)} | Deleted: {len(deleted)}",
        "=" * 60,  # Add the final separator.
        "", # Add an empty line after the report.
    ]
    return "\n".join(lines)  


def check_integrity(): # Function to perform one complete integrity check.
    baseline = load_baseline() # Load the trusted baseline from baseline.json.
    if baseline is None: # Check whether a baseline exists.
        print("No baseline found. Create one first (option 1).") # Tell the user to create a baseline first.
        return 

    folder = baseline["folder"] # Get the folder path stored in the baseline.
    if not os.path.isdir(folder):  # Check whether the monitored folder still exists.
        print(f"Monitored folder no longer exists : {folder}") # Inform the user that the folder no longer exists.
        return 
    current = scan_folder(folder) # Scan the monitored folder again.
    new, modified, deleted, unchanged = compare(baseline["files"], current) # Compare the current scan with the trusted baseline.

    report = build_report(folder, new, modified, deleted, unchanged) # Build a readable report using the comparison results.
    print(report)

    with open(REPORT_FILE, "a") as f: # Open the report file in append mode.
        f.write(report + "\n")


# MENU ACTIONS------------------------------
def create_baseline():
    folder = input("Enter the folder path to monitor: ").strip().strip('"')

    if not os.path.isdir(folder):
        print(f"Director '{folder}' doest not exist.")
        return

    hashes = scan_folder(folder)
    save_baseline(folder, hashes)
    print(f"Baseline saved: {len(hashes)} files recorded in {HASH_FILE}")


def continuous_monitor():
    print(f"Monitoring every {CHECK_INTERVAL} seconds. Press Ctrl+C to stop.\n")
    try: 
        while True:
            check_integrity()
            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n Monitoring stopped.")


def main():
    while True:
        print("\n=== File Integrity Monitor ===")
        print("1. Create / update baseline")
        print("2. Check integrity (one scan)")
        print("3. Continuous monitoring")
        print("4. Exit")
 
        choice = input("Choose an option: ").strip()
 
        if choice == "1":
            create_baseline()
        elif choice == "2":
            check_integrity()
        elif choice == "3":
            continuous_monitor()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")
 
 
if __name__ == "__main__":
    main()