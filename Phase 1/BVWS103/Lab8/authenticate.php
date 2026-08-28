<?php
// Securely store password using password_hash()
$username = "user";
$hashed_password = '$2y$10$8N5f6eQmJ0nExI0ktHJ9euX0V/qwjo7ejj64ZPaAlcxL2w5Xhbn3K'; // password123 hashed using bcrypt

// Capture user input
$user_input_username = $_POST['username'];
$user_input_password = $_POST['password'];

// Use password_verify to securely compare the user input with the hashed password
if ($user_input_username == $username && password_verify($user_input_password, $hashed_password)) {
    // Secure session handling: initiate a session with proper session management
    session_start();
    $_SESSION['username'] = $user_input_username;
    echo "<h2>Welcome, $username!</h2>";
    echo "<p>You are logged in securely.</p>";
} else {
    echo "<h2>Invalid credentials. Try again.</h2>";
}
?>
