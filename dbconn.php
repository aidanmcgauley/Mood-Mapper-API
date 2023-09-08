<?php

$host = "localhost";
$dbname = "mood_mapper";
$username = "root";
$password = "";

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    exit($conn->connect_error);
}

?>