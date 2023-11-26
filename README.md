# Flask User Authentication and Authorization

This Flask appn demonstrates user authentication and authorization using various methods such as Basic Auth, Bearer Token and bcrpyt for password hashing.

## Project Overview

This project showcases user authentication and authorization features implemented in a Flask application. It includes functionalities for user sign-up, login, and access control to protected routes.

## Installation and Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/VineetDabholkar2002.git
   ```
2. **Navigate to the Project Directory:**
   ```bash
   cd App
   ```
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Application:**
   ```bash
   python BasicAuth.py
   ```
5. **Access the Application:**
   Open your web browser and navigate to `http://localhost:8080`.

## Features and Routes

- **Sign Up:** `/signup` route allows users to create a new account by providing a unique username and password.
- **Login:** `/login` route enables users to log in using Basic Auth.
- **Protected Route:** Access `/main` route after successful login to view protected content.
- **Token-Based Authentication:** The application generates and verifies Bearer Tokens for user authentication.

## File Structure

- `app.py`: Contains the Flask application logic, routes, and authentication functionalities.
- `templates/`: Directory containing HTML templates for login, signup, and main pages.
- `users.json`: File storing user information, including hashed passwords and salts.

## Usage

1. **Sign Up:**
   - Visit `/signup` to create a new account with a unique username and password.

2. **Login:**
   - Use `/login` to log in using Basic Auth.\

3. **Protected Route:**
   - Access `/main` after successful login to view protected content (in this case you will be routed to Google.com.  Unauthorized access will display an error message.

4. **Authentication Tokens:**
   - Bearer Tokens are generated and verified for user authentication during login. Also they can be set to expire after a certain period of time

## Bcrypt
# Flask User Authentication and Authorization

This Flask application demonstrates user authentication and authorization using various methods such as Basic Auth and Bearer Token.

## Project Overview

This project showcases user authentication and authorization features implemented in a Flask application. It includes functionalities for user sign-up, login, and access control to protected routes.

## Installation and Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/VineetDabholkar2002.git
   ```
2. **Navigate to the Project Directory:**
   ```bash
   cd App
   ```
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Application:**
   ```bash
   python BasicAuth.py
   ```
5. **Access the Application:**
   Open your web browser and navigate to `http://localhost:8080`.

## Features and Routes

- **Sign Up:** `/signup` route allows users to create a new account by providing a unique username and password.
- **Login:** `/login` route enables users to log in using Basic Auth.
- **Protected Route:** Access `/main` route after successful login to view protected content.
- **Token-Based Authentication:** The application generates and verifies Bearer Tokens for user authentication.

## File Structure

- `app.py`: Contains the Flask application logic, routes, and authentication functionalities.
- `templates/`: Directory containing HTML templates for login, signup, and main pages.
- `users.json`: File storing user information, including hashed passwords and salts.

## Usage

1. **Sign Up:**
   - Visit `/signup` to create a new account with a unique username and password.

2. **Login:**
   - Use `/login` to log in using Basic Auth.\

3. **Protected Route:**
   - Access `/main` after successful login to view protected content (in this case you will be routed to Google.com.  Unauthorized access will display an error message.

4. **Authentication Tokens:**
   - Bearer Tokens are generated and verified for user authentication during login.

## Bcrypt
![image](https://github.com/VineetDabholkar2002/BasicAuthentication/assets/93699671/2f57e267-0826-4e5a-b250-3e9c78256993)

This application utilizes bcrypt for secure password hashing and storage:

### What is bcrypt?

- **bcrypt** is a password-hashing function designed to securely hash passwords for storage.
- It employs a strong one-way hashing algorithm, making it computationally intensive and thereby resistant to brute-force attacks.

### How does bcrypt work?

- It generates a salted hash of the password, making each hash unique and preventing rainbow table attacks.
- The computational intensity helps mitigate password cracking attempts by slowing down the hashing process.

### Why use bcrypt?

- **Bcrypt's** resistance to brute-force attacks and its adaptive nature (allowing for increasing computational complexity over time) make it a preferred choice for secure password hashing.



