<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');  // Sanitize user input

    echo "<p>Hello, $name!</p>";  // Output the sanitized input
}
?>
