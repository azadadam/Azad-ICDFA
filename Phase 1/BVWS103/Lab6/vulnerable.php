<?php
session_start();

// Simulated class with a method that can be abused
class User {
    public $username;
    public $role;

    public function __construct($username, $role) {
        $this->username = $username;
        $this->role = $role;
    }

    public function login() {
        echo "<h1>Welcome, " . $this->username . "!</h1>";
        echo "<p>Your role is: " . $this->role . "</p>";
    }
}

if (isset($_POST['json_data'])) {
    // Secure deserialization using json_decode
    $data = json_decode($_POST['json_data'], true);

    // Make sure the data structure is validated before usage
    if (isset($data['username']) && isset($data['role'])) {
        $user = new User($data['username'], $data['role']);
        $user->login();
    } else {
        echo "<h1>Invalid Data</h1>";
    }
} else {
    echo "<h1>Please submit JSON data</h1>";
}
?>

<form method="POST">
    <label for="json_data">JSON Data:</label><br>
    <textarea id="json_data" name="json_data" rows="5" cols="40"></textarea><br>
    <button type="submit">Submit</button>
</form>

