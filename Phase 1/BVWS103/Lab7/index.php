<?php
// Check if the user is logged in
session_start();

if (!isset($_SESSION['username'])) {
    echo "<p>Please log in to view the page.</p>";
} else {
    echo "<h2>Welcome to the User Dashboard</h2>";
    echo "<p>This page is for logged-in users.</p>";
}
?>
