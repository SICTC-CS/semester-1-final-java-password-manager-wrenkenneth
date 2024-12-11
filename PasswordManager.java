import java.io.*;
import java.util.*;
import java.util.regex.*; //imports pattern and matcher classes
import java.security.MessageDigest; //password hasher
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PasswordManager {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Authentication auth = new Authentication();
        if (auth.authenticate()) {
            AccountManager accountManager = new AccountManager(auth.getCurrentUser());
            accountManager.menu(scanner);
        } else {
            System.out.println("Exiting program. Goodbye!");
        }
        scanner.close();
    }
}

class User {
    private final String username;
    private final String hashedPassword;
    private final String firstName;
    private final String lastName;

    public User(String username, String hashedPassword, String firstName, String lastName) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public boolean checkPassword(String inputPassword) {
        try {
            return hashedPassword.equals(PasswordHasher.hashPassword(inputPassword));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error verifying password", e);
        }
    }

    public String getUsername() {
        return username;
    }

    public String toFileString() {
        return username + "," + hashedPassword + "," + firstName + "," + lastName;
    }

    public static User fromFileString(String fileString) {
        String[] parts = fileString.split(",");
        return new User(parts[0], parts[1], parts[2], parts[3]);
    }
}

// thanks chat gpt for next two functions
class PasswordHasher {
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        //get the instance of the class that will hash the passwords
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //convert the given password into a byte array before hashing it using the instance above
        byte[] hashedBytes = md.digest(password.getBytes());
        //convert hashed byte array into a hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (byte b : hashedBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

class PasswordValidator {
    //precompile and reuse the regex - pattern and matcher explained here: https://www.w3schools.com/java/java_regex.asp#:~:text=Pattern%20Class%20%2D%20Defines%20a%20pattern,in%20a%20regular%20expression%20pattern
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&+=]).{8,}$");

    public static boolean isValid(String password) {
        return PASSWORD_PATTERN.matcher(password).matches();
    }
}

class PasswordGenerator {
    private static final String CHAR_POOL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&+=";
    public static String generate(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < length; i++) {
            password.append(CHAR_POOL.charAt(random.nextInt(CHAR_POOL.length())));
        }
        return password.toString();
    }
}

class Authentication {
    private static final String USER_FILE = "users.txt";
    private final Map<String, User> users = new HashMap<>();
    private int loginAttempts = 3;
    private User currentUser;

    public Authentication() {
        loadUsers();
    }

    public boolean authenticate() {
        Scanner scanner = new Scanner(System.in);
        while (loginAttempts > 0) {
            System.out.print("Enter Username: ");
            String username = scanner.nextLine();
            if (!users.containsKey(username)) {
                System.out.println("User not found. Would you like to register? (yes/no)");
                if (scanner.nextLine().equalsIgnoreCase("yes")) {
                    registerUser(scanner);
                    continue;
                } else {
                    System.out.println("Returning to login menu...");
                    continue;
                }
            }

            System.out.print("Enter Password: ");
            String password = scanner.nextLine();
            currentUser = users.get(username);
            if (currentUser.checkPassword(password)) {
                System.out.println("Login successful!");
                return true;
            } else {
                loginAttempts--;
                System.out.printf("Incorrect password. Attempts remaining: %d%n", loginAttempts);
                if (loginAttempts > 0) {
                    System.out.println("Watch out, you are close to being locked out");
                }
            }
        }
        System.out.println("Too many failed attempts. Program will exit.");
        return false;
    }

    public User getCurrentUser() {
        return currentUser;
    }

    private void registerUser(Scanner scanner)  {
        try {
            System.out.print("Create Username: ");
            String username = scanner.nextLine();
            while (users.containsKey(username)) {
                System.out.println("Username already exists. Try a different one:");
                username = scanner.nextLine();
            }

            System.out.print("Enter First Name: ");
            String firstName = scanner.nextLine();

            System.out.print("Enter Last Name: ");
            String lastName = scanner.nextLine();

            System.out.print("Create Password: ");
            String password = scanner.nextLine();
            while (!PasswordValidator.isValid(password)) {
                System.out.println("Password does not meet the criteria:");
                System.out.println(" - At least 8 characters\n - At least 1 uppercase letter\n - At least 1 digit\n - At least 1 special character");
                password = scanner.nextLine();
            }
            String hashedPassword = PasswordHasher.hashPassword(password); //hash and store password
            User newUser = new User(username, hashedPassword, firstName, lastName);
            users.put(username, newUser);
            saveUsers();
            System.out.println("Account created successfully. Please log in.");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error creating user", e);
        }
    }

    private void loadUsers() {
        File file = new File(USER_FILE);
        if (!file.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                User user = User.fromFileString(line);
                users.put(user.getUsername(), user);
            }
        } catch (IOException e) {
            System.err.println("Error loading user data: " + e.getMessage());
        }
    }

    private void saveUsers() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USER_FILE))) {
            for (User user : users.values()) {
                writer.write(user.toFileString());
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error saving user data: " + e.getMessage());
        }
    }
}


class AccountManager {
    private static final String ACCOUNT_FILE = "users.txt";
    private final Map<String, List<Account>> accounts = new HashMap<>();
    private final User currentUser;

    public AccountManager(User currentUser) {
        this.currentUser = currentUser;
        loadAccounts();
    }

    public void menu(Scanner scanner) {
        while (true) {
            System.out.println("\nMenu Options:");
            System.out.println("1. Create Account");
            System.out.println("2. Delete Account");
            System.out.println("3. View Accounts");
            System.out.println("4. Generate Password");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1 -> createAccount(scanner);
                case 2 -> deleteAccount(scanner);
                case 3 -> viewAccounts();
                case 4 -> System.out.println("Generated Password: " + PasswordGenerator.generate(12));
                case 5 -> {
                    saveAccounts();
                    System.out.println("Exiting... Goodbye!");
                    return;
                }
                default -> System.out.println("Invalid choice. Please try again.");
            }
        }
    }

    private void createAccount(Scanner scanner) {
        System.out.print("Account Name: ");
        String name = scanner.nextLine();

        System.out.print("Username: ");
        String username = scanner.nextLine();

        System.out.print("Password: ");
        String password = scanner.nextLine();
        while (!PasswordValidator.isValid(password)) {
            System.out.println("Invalid password! Try again.");
            password = scanner.nextLine();
        }

        System.out.print("Category: ");
        String category = scanner.nextLine();
        accounts.computeIfAbsent(category, k -> new ArrayList<>())
                .add(new Account(name, username, password));
        System.out.println("Account created successfully!");
    }

    private void deleteAccount(Scanner scanner) {
        System.out.print("Enter the category: ");
        String category = scanner.nextLine();

        if (!accounts.containsKey(category)) {
            System.out.println("Category not found.");
            return;
        }

        List<Account> categoryAccounts = accounts.get(category);
        if (categoryAccounts.isEmpty()) {
            System.out.println("No accounts in this category.");
            return;
        }

        System.out.println("Accounts in " + category + ":");
        for (int i = 0; i < categoryAccounts.size(); i++) {
            System.out.printf("%d. %s%n", i + 1, categoryAccounts.get(i));
        }

        System.out.print("Enter the number to delete: ");
        int index = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        if (index > 0 && index <= categoryAccounts.size()) {
            categoryAccounts.remove(index - 1);
            System.out.println("Account deleted.");
        } else {
            System.out.println("Invalid selection.");
        }
    }

    private void viewAccounts() {
        if (accounts.isEmpty()) {
            System.out.println("No accounts available.");
            return;
        }
        for (String category : accounts.keySet()) {
            System.out.println("\nCategory: " + category);
            for (Account account : accounts.get(category)) {
                System.out.println(account);
            }
        }
    }

    private void loadAccounts() {
        File file = new File(ACCOUNT_FILE);
        if (!file.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String category = parts[3];
                accounts.computeIfAbsent(category, k -> new ArrayList<>())
                        .add(new Account(parts[0], parts[1], parts[2]));
            }
        } catch (IOException e) {
            System.err.println("Error loading accounts: " + e.getMessage());
        }
    }

    private void saveAccounts() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(ACCOUNT_FILE))) {
            for (String category : accounts.keySet()) {
                for (Account account : accounts.get(category)) {
                    writer.write(account.toFileString(category));
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            System.err.println("Error saving accounts: " + e.getMessage());
        }
    }
}

class Account {
    private final String name;
    private final String username;
    private final String password;

    public Account(String name, String username, String password) {
        this.name = name;
        this.username = username;
        this.password = password;
    }

    @Override
    public String toString() {
        return "Account: " + name + ", Username: " + username + ", Password: " + password;
    }

    public String toFileString(String category) {
        return name + "," + username + "," + password + "," + category;
    }
}