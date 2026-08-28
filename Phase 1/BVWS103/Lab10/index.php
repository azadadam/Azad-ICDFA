<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Component Example</title>
    <script src="jquery-4.0.0.min.js"></script> <!-- Old jQuery version -->
</head>
<body>
    <h1>Vulnerable Web Application</h1>
    <p>Click the button below to execute a function that is vulnerable to DOM-based XSS.</p>
    <button id="vulnerableBtn">Click Me</button>

    <script>
    $('#vulnerableBtn').click(function() {
        var userInput = prompt("Enter some text:");
        // Use text() instead of html() to prevent XSS
        $('#vulnerableBtn').text(userInput); // Safely insert text without executing it
    });
    </script>
</body>
</html>
