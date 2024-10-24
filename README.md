[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/jR9X2WQF)
# Password Manager README

## Password Manager

This is a terminal-based password manager built in Java. It not only stores login credentials for applications and websites but also provides additional features such as password generation, category-based organization, and data persistence.

### Requirements

1. **Authentication:**
   - Users must log in to run the program.
   - Implement a hint system for password recovery.
   - Allow the user 3 attempts to login before the program shuts down.
   - For first-time users, enable profile creation with the following requirements:
     - Username
     - Password (with specific requirements - see item 8)
     - First and last name
   - After registration, require the user to log in.

2. **Account Management:**
   - Create a method to take user input to store account information (username and password) based on user-defined categories.
   - Accounts must be retrievable based on categories the user sets for each password (user-friendliness hint, have the categories listed out for the user).
   - Each account entry must include:
     - Name of Account
     - Username of Account
     - Password of Account
     - Category of Account

3. **Data Persistence:**
   - Save account information to a text file. The design of data storage is up to you, but there are more professional methods to develop a No-SQL Flat File Database.

4. **Category Navigation:**
   - Allow users to navigate through the categories they have created.
   - Implement a feature to print out the categories in a list.

5. **Password Generation:**
   - Implement a password generator option if the user requests.
   - Half Credit: Build a method to generate.
   - Full Credit: Build a class that holds a static method to generate.

6. **Account Modification:**
   - Enable users to delete or modify account entries.

7. **Output Format:**
   - The program should provide output in the following organized format, including three account examples:

   ```
   Account 1:
     - Username: {username}
     - Password: {password}
   ---------------------------------
   Account 2:
     - Username: {username}
     - Password: {password}
   ---------------------------------
   Account 3:
     - Username: {username}
     - Password: {password}
   ```

8. **Password Requirements:**
   - Implement password requirements to ensure user input and generated passwords meet specific criteria:
     - At least 1 capital character
     - At least 1 number
     - At least 1 special character (with certain special characters allowed)
     - At least 8 characters long
   - Half Credit: Create a method to check for password requirements.
   - Full Credit: Create a separate class with a static method to check for password requirements.

9. **Bonus Features:**
   - 10% Bonus: Implement the ability to save the file as a password-protected or encrypted file.
   - 5% Bonus: Create a method to calculate the time required to brute force break a password.
   - 15% Bonus: Implement the option to save account information in an actual database and not a text file.

### Computer Science Concepts to Include

1. User Input Handling -> Ensure user inputs are properly validated and handled.
2. Data Structures (Arrays, Lists, ArrayLists, Strings, double vs int, etc).
3. Utilization of Built-in Functions (e.g., for password generation).
4. Loops (for iteration).
5. Commenting (All methods must be documented).
6. Multiple Classes (Suggestions: PasswordRecord, Library, OpenCloseFile, etc.).
7. Error Handling (Prevent runtime errors).
8. User-Friendly Interface and Usability.

### Project Management

- The design overview should include features, implementation details, and assignment of responsibilities.
- Document any external sources used, including commentary on their use. Be sure to also explain what specifically you grabbed from that website.

### Example

If you need an example of a password manager, install and experiment with the following program: [KeePass](https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.52/KeePass-2.52-Setup.exe/download)

This project challenges you to build a feature-rich and secure password manager while adhering to specific requirements and bonus features. Ensure your program is well-documented, user-friendly, and satisfies the specified criteria.
