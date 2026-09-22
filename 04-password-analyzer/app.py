import tkinter as tk # tkinter is Python's built-in library for making windows, buttons, text boxes, etc.
from tkinter import ttk # ttk gives us nicer looking widgets like tabs and a progress bar

from password_analyzer import check_password_strength # imports the function that checks a password and returns a report
from password_generator import generate_password, generate_passphrase # imports the two generator functions


COLORS = { # A dictionary that maps each strength label to a color, used to color the text on screen
    "Very Weak": "#d32f2f",
    "Weak": "#f57c00",
    "Medium": "#fbc02d",
    "Strong": "#689f38",
    "Very Strong": "#2e7d32",
}


class PasswordApp: # A class that builds and controls the whole window

    def __init__(self, root): # This runs automatically when we create a PasswordApp
        self.root = root # Stores the main window so other methods can use it
        self.root.title("Password Strength Checker & Generator") # Sets the window title bar text
        self.root.geometry("480x520") # Sets the starting width and height of the window

        notebook = ttk.Notebook(root) # Notebook is the tab bar (Check Password / Generate Password)
        notebook.pack(fill="both", expand=True, padx=10, pady=10) # Makes the notebook fill the window with some padding

        check_tab = ttk.Frame(notebook) # A frame (blank container) for the check-password tab
        generate_tab = ttk.Frame(notebook) # A frame for the generate-password tab
        notebook.add(check_tab, text="Check Password") # Adds the first tab with a label
        notebook.add(generate_tab, text="Generate Password") # Adds the second tab with a label

        self.build_check_tab(check_tab) # Fills the check tab with its widgets
        self.build_generate_tab(generate_tab) # Fills the generate tab with its widgets

    # ---------------- CHECK TAB ----------------

    def build_check_tab(self, tab): # Builds everything inside the "Check Password" tab
        tk.Label(tab, text="Enter a password to check:").pack(pady=(10, 0)) # A simple instruction label

        entry_frame = tk.Frame(tab) # A small frame to hold the entry box and the Show checkbox side by side
        entry_frame.pack(pady=5)

        self.password_entry = tk.Entry(entry_frame, width=30, show="*") # The box where the user types their password, show="*" hides it
        self.password_entry.pack(side="left")

        self.show_password = tk.BooleanVar(value=False) # A variable that remembers whether Show is checked or not
        show_button = tk.Checkbutton( # A checkbox that toggles the password's visibility
            entry_frame, text="Show", variable=self.show_password,
            command=self.toggle_password_visibility
        )
        show_button.pack(side="left", padx=5)

        check_button = tk.Button(tab, text="Check Strength", command=self.check_password) # A button that runs check_password() when clicked
        check_button.pack(pady=10)

        self.strength_label = tk.Label(tab, text="", font=("Arial", 13, "bold")) # A label to show the strength word (e.g. Strong)
        self.strength_label.pack(pady=5)

        self.meter = ttk.Progressbar(tab, length=300, maximum=100) # A progress bar used as the visual strength meter, out of 100
        self.meter.pack(pady=5)

        self.entropy_label = tk.Label(tab, text="") # A label to show the estimated entropy in bits
        self.entropy_label.pack()

        self.report_box = tk.Text(tab, height=14, width=55, wrap="word") # A multi-line text box to show issues and suggestions
        self.report_box.pack(pady=10)
        self.report_box.config(state="disabled") # Disabled so the user cannot type inside it, only we can update it

    def toggle_password_visibility(self): # Runs whenever the Show checkbox is clicked
        if self.show_password.get(): # If the checkbox is now checked
            self.password_entry.config(show="") # Show the real characters
        else:
            self.password_entry.config(show="*") # Otherwise hide them with *

    def check_password(self): # Runs when the Check Strength button is clicked
        password = self.password_entry.get() # Reads whatever the user typed in the entry box

        if password == "": # If the box is empty
            self.strength_label.config(text="Please enter a password.", fg="black")
            self.meter["value"] = 0
            self.entropy_label.config(text="")
            self.update_report([])
            return # Stop here, nothing else to check

        result = check_password_strength(password) # Calls our analyzer function, which returns a dictionary
        color = COLORS.get(result["label"], "black") # Looks up the color for this label, defaults to black if not found

        self.strength_label.config( # Updates the strength label with text and color
            text=f"{result['label']}  ({result['score']}/100)", fg=color
        )
        self.meter["value"] = result["score"] # Moves the progress bar to match the score
        self.entropy_label.config(text=f"Estimated entropy: {result['points']} bits") # Shows the entropy value

        lines = [] # A list that will hold every line we want to display in the report box
        if result["issues"]: # If there are any issues
            lines.append("Why it is weak:")
            for issue in result["issues"]: # Loop through each issue and add it as a bullet point
                lines.append(f"  - {issue}")
        if result["suggestions"]: # If there are any suggestions
            lines.append("\nHow to improve:")
            for tip in result["suggestions"]: # Loop through each suggestion and add it as a bullet point
                lines.append(f"  - {tip}")
        if not result["issues"] and not result["suggestions"]: # If there is nothing wrong at all
            lines.append("Great password! No problems found.")

        self.update_report(lines) # Sends the finished list of lines to be displayed

    def update_report(self, lines): # Updates the text box with a new report
        self.report_box.config(state="normal") # Temporarily enable editing so we can change the text
        self.report_box.delete("1.0", tk.END) # Clears everything currently shown
        self.report_box.insert(tk.END, "\n".join(lines)) # Inserts the new lines, joined by newlines
        self.report_box.config(state="disabled") # Disable editing again so the user can't type in it

    # ---------------- GENERATE TAB ----------------

    def build_generate_tab(self, tab): # Builds everything inside the "Generate Password" tab

        length_frame = tk.Frame(tab) # A frame to hold the length label and spinbox together
        length_frame.pack(pady=(15, 5))
        tk.Label(length_frame, text="Password length:").pack(side="left")
        self.length_var = tk.IntVar(value=12) # A variable that stores the chosen length, starting at 12
        tk.Spinbox( # A small up/down number picker for the length
            length_frame, from_=8, to=64, textvariable=self.length_var, width=5
        ).pack(side="left", padx=5)

        self.use_numbers = tk.BooleanVar(value=True) # Remembers whether "Include numbers" is checked
        self.use_special = tk.BooleanVar(value=True) # Remembers whether "Include special characters" is checked
        tk.Checkbutton(tab, text="Include numbers", variable=self.use_numbers).pack()
        tk.Checkbutton(tab, text="Include special characters", variable=self.use_special).pack()

        tk.Button( # A button that generates a password when clicked
            tab, text="Generate Password", command=self.make_password
        ).pack(pady=10)

        phrase_frame = tk.Frame(tab) # A frame to hold the word-count label and spinbox together
        phrase_frame.pack(pady=(15, 5))
        tk.Label(phrase_frame, text="Passphrase word count:").pack(side="left")
        self.word_count_var = tk.IntVar(value=4) # A variable that stores the chosen word count, starting at 4
        tk.Spinbox(
            phrase_frame, from_=3, to=8, textvariable=self.word_count_var, width=5
        ).pack(side="left", padx=5)

        tk.Button( # A button that generates a passphrase when clicked
            tab, text="Generate Passphrase", command=self.make_passphrase
        ).pack(pady=10)

        self.result_entry = tk.Entry(tab, width=40, justify="center", font=("Arial", 12)) # Shows the generated password/passphrase
        self.result_entry.pack(pady=15)

        self.result_strength = tk.Label(tab, text="", font=("Arial", 11, "bold")) # Shows the strength of the generated result
        self.result_strength.pack()

        tk.Button(tab, text="Copy to Clipboard", command=self.copy_result).pack(pady=10) # A button to copy the result

    def make_password(self): # Runs when Generate Password is clicked
        password = generate_password( # Calls the generator function with the values chosen on screen
            length=self.length_var.get(),
            use_numbers=self.use_numbers.get(),
            use_special=self.use_special.get(),
        )
        self.show_result(password) # Displays the result and its strength

    def make_passphrase(self): # Runs when Generate Passphrase is clicked
        passphrase = generate_passphrase(word_count=self.word_count_var.get()) # Calls the passphrase generator with the chosen word count
        self.show_result(passphrase) # Displays the result and its strength

    def show_result(self, value): # Displays a generated password or passphrase and scores it
        self.result_entry.delete(0, tk.END) # Clears whatever was shown before
        self.result_entry.insert(0, value) # Inserts the new value

        result = check_password_strength(value) # Runs the new value through the analyzer
        color = COLORS.get(result["label"], "black") # Looks up the matching color
        self.result_strength.config( # Updates the strength label below the result box
            text=f"Strength: {result['label']} ({result['score']}/100)", fg=color
        )

    def copy_result(self): # Runs when Copy to Clipboard is clicked
        value = self.result_entry.get() # Reads whatever is currently shown in the result box
        if value: # Only copy if there is something to copy
            self.root.clipboard_clear() # Empties the clipboard first
            self.root.clipboard_append(value) # Puts the value onto the clipboard


if __name__ == "__main__": # This only runs when the file is run directly, not when imported
    root = tk.Tk() # Creates the main application window
    app = PasswordApp(root) # Builds the whole app inside that window
    root.mainloop() # Starts the window and keeps it running until closed