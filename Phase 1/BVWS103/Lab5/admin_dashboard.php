<?php
session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

// Check if the user is an admin
if ($_SESSION['username'] !== 'admin') {
    echo "<p>Access denied. You are not authorized to view this page.</p>";
    exit();
}

echo "<h2>Welcome to the Admin Dashboard</h2>";
echo "<p>This is a secret admin page!</p>";
?>
