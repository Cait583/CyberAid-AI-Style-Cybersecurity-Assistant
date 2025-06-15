import time # This loads the time module and gives the function to pause or delay parts of the program

def print_ai(message): # Creates a function to take an input to simulate the AI typing to the user
    for char in message: # This is a for loop to go through the message one character at a time
        print(char, end='', flush=True) # This prints one character at a time not making a new line each time and creates a typing effect where it will simulate the AI typing
        time.sleep(0.01) # This pauses the program for 0.01 seconds between each character to give the feeling of AI typing back
    print() # This makes the AI messages appear one character at a time

def main(): # Here I am creating a new function to start getting users input the main will call other functions I will be creating
    print_ai("🛡️ Welcome to CyberAid — Your AI-style Cybersecurity Assistant!") # This will be displayed to the user as a greeting typed slowly to give the feeling that an AI is saying this
    while True: # Starts a while loop that will run until the user leaves
        # Here are the options for the user to choose from to give a menu feeling for ease of use
        print("\nPlease choose an option:")
        print("1. Analyze a suspicious email")
        print("2. Check a password for strength")
        print("3. Review a suspicious URL")
        print("4. Scan server logs for brute force attempts")
        print("5. Generate an incident report")
        print("6. Exit\n")

        choice = input("Enter your choice please, only one number (1-6): ") # This tells the user to pick one number to go into the section they want

        # Here I am handling the user choice, to see which number they have chosen and based off that do an action
        if choice == '1':
            analyze_email()
        elif choice == '2':
            check_password()
        elif choice == '3':
            review_url()
        elif choice == '4':
            scan_logs()
        elif choice == '5':
            generate_report()
        elif choice == '6':
            print_ai("👋 Goodbye!")
            break
        else:
            print_ai("❌ Invalid choice, please enter a number between 1 and 6.")

def analyze_email(): # I am creating another new function to group all the emails into a reusable box
    print_ai("\n[Phishing Email Analyzer]") # This tell the user with an AI typing effect that it will analyze the emails to check for any phishing
    email_text = input("Paste the suspicious email content here:\n") # This asks the user to paste or type the email content they want analyzed
    email_text_lower = email_text.lower() # This makes all the email text into lowercase
    suspicious_keywords = ['urgent', 'password', 'verify', 'account', 'click', 'bank', 'login', 'security', 'update', 'risk'] # Here I created a list of common phishing keywords used in emails
    found_keywords = [] # This creates an empty list to keep any of the suspicious keywords found in the email
    for word in suspicious_keywords: # Starts a for loop to go through each word in the suspicious_keywords list one at a time
        if word in email_text_lower:
            found_keywords.append(word) # This will check if the current word appears anywhere in the email text and if it does it will add the word to the list

    if found_keywords: # This will check if found_keywords list is not empty and if yes it is not empty then it shows a warning saying the suspicious keywords were detected. If not then it tells the user no suspicious keywords were found
        print_ai(f"⚠️ Warning: Suspicious keywords detected: {', '.join(found_keywords)}")
    else:
        print_ai("✅ No common phishing keywords detected.")

    print_ai("Remember: This is a simple check, always be cautious with unknown emails!\n") # This gives the user a reminder to use this tool as a basic filter and the user should still be very careful don't fully rely on this

def check_password(): # Created another new function to checks the password which is option 2
    print_ai("\n[Password Strength Checker]") # This has the "AI" print this to show to the user what it is doing
    password = input("Enter the password to check: ") # Informs the user to know give it the password to check for its strength
    # Here I am having Python check each character and letter to ensure it is a strong password
    length_ok = len(password) >= 12
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(not char.isalnum() for char in password)

    score = sum([length_ok, has_upper, has_lower, has_digit, has_special]) # This adds up how many strength rules the password passed with the max score being 5
    # Here it will give the user feedback based off of their password score
    if score == 5:
        print_ai("✅ Strong password! Nice work.")
    elif score >= 3:
        print_ai("⚠️ Decent password, but it could be stronger.")
    else:
        print_ai("❌ Weak password! Consider using more length, symbols, and mixed case.")

    print_ai("\nPassword check results:") # This informs the user what they are missing in the password
    if not length_ok:
        print_ai("- Try making your password at least 12 characters long.")
    if not has_upper:
        print_ai("- Add at least one uppercase letter.")
    if not has_lower:
        print_ai("- Add at least one lowercase letter.")
    if not has_digit:
        print_ai("- Include at least one number.")
    if not has_special:
        print_ai("- Use at least one special character (!, @, #, etc.)")

def review_url(): # Creates a new function for the 3rd choice
    print_ai("\n[Suspicious URL Reviewer]") # Prints the header for the user
    url = input("Enter the URL to check: ").lower() # This asks the user to give the URl for the program to check or "AI" in this case
    suspicious_patterns = ['@', 'http//', 'https//', 'login', 'secure', 'account', 'update', 'free', 'verify', 'bank'] # This creates a list of common suspicious keywords or characters found in URLs
    found_patterns = [] # Makes an empty list to track the suspicious parts
    for pattern in suspicious_patterns: # Here I am using a for loop to go through patterns
        if pattern in url:
            found_patterns.append(pattern)
    # Here I used another for loop to check the patterns if found it will warn the user if not it will let them know it is fine
    if found_patterns:
        print_ai(f"⚠️ Warning: Suspicious patterns detected in URL: {', '.join(found_patterns)}")
    else:
        print_ai("✅ URL looks clean based on basic checks.")
    # This informs the user to always check the URL even if using this to double-check
    print_ai("Remember to always check the URL carefully before clicking!\n")

def scan_logs(): # Creating a new function for number 4
    print_ai("\n[Brute Force Log Scanner]") # Informs the user what this choice is
    print("Paste server log lines (type 'END' on a new line to finish):") # Asks the user to paste the server log lines to scan them
    # Here I created an empty list to keep the logs stored in and started a while and for loop below to check if the user types END to stop collecting the logs
    logs = []
    while True:
        line = input()
        if line.strip().upper() == 'END':
            break
        logs.append(line)
      
    failed_attempts = {} # Creates a dictionary to count the failed login attempts per IP

    for log_line in logs: # This is a for loop to start checking for 'Failed Login' phrase and an IP address pattern
        if 'failed login' in log_line.lower():
            # Here it will extract the IP address and look for the failed login in the lines and counts how many times each IP address was failed login attempts
            import re
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
            if ip_match:
                ip = ip_match.group()
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= 5} # This finds the IPs with 5 or more failed attempts
    # Here I am creating a for loop to check for the results and inform the user if it might show brute force attempts or if it does not
    if suspicious_ips:
        print_ai("⚠️ Potential brute force attack detected from these IP addresses:")
        for ip, count in suspicious_ips.items():
            print_ai(f"- {ip}: {count} failed attempts")
    else:
        print_ai("✅ No brute force attempts detected based on the input logs.")

    print_ai("Always investigate repeated failed logins for security.\n") # Informs the user to always investigate the failed login attempts

def generate_report(): # Here I am creating another new function to handle option 5 for the user
    print_ai("\n[Incident Report Generator]") # Informs the user of their choice
    # Here I am asking the user for information about the incident that occurred
    incident_type = input("Enter the type of incident (e.g., phishing, malware, brute force): ")
    date = input("Enter the date of the incident (YYYY-MM-DD): ")
    affected_systems = input("List affected systems or users (comma separated): ")
    description = input("Describe what happened briefly: ")

    # Here I am creating a formatted multiline string with their info inserted to create an incident report template
    report = f"""
--- Cybersecurity Incident Report ---

Type: {incident_type}
Date: {date}
Affected Systems/Users: {affected_systems}
Description: {description}

--- End of Report ---
"""

    print_ai(report) # Prints the report out for the user to view


if __name__ == "__main__":
    main()
