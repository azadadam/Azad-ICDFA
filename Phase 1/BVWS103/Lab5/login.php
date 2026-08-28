<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Hardcoded username and password
    if ($username == 'admin' && $password == 'admin123') {
        $_SESSION['username'] = 'admin';
        header("Location: admin_dashboard.php");
    } elseif ($username == 'user' && $password == 'user123') {
        $_SESSION['username'] = 'user';
        header("Location: user_dashboard.php");
    } else {
        echo "<p>Invalid credentials</p>";
    }
}
?>

<form action="login.php" method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required><br>
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required><br>
    <button type="submit">Login</button>
</form>
