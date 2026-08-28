<?php
// Securely store the password using bcrypt
$stored_username = "user";
$stored_password_hash = '$2y$10$8N5f6eQmJ0nExI0ktHJ9euX0V/qwjo7ejj64ZPaAlcxL2w5Xhbn3K'; // password123 hashed using bcrypt

// Capture user input
$user_input_username = $_POST['username'];
$user_input_password = $_POST['password'];

// Check if the user input matches the stored username and the hashed password
if ($user_input_username == $stored_username && password_verify($user_input_password, $stored_password_hash)) {
    echo "<h2>Welcome, $user_input_username!</h2>";
    echo "<p>Your sensitive data is now protected with hashing and secure transmission.</p>";
} else {
    echo "<h2>Invalid credentials. Try again.</h2>";
}
?>
