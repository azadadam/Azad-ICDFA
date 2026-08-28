<?php
session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

echo "<h2>Welcome to the User Dashboard</h2>";
echo "<p>This page is for regular users.</p>";
?>
