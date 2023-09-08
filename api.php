<?php

    header("Content-Type: application/json");




    // GET user info
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['get-user']) && isset($_GET['user_id'])) {
        include 'dbconn.php';

        $user_id = $_GET['user_id'];

        $get_user_info = "SELECT * FROM user WHERE user_id = ?";
        $stmt = $conn->prepare($get_user_info);
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if (!$result) {
            http_response_code(500);
            echo json_encode(['message' => 'Unable to process request.']);
            exit();
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(500); 
            echo json_encode(['message' => 'Unable to process request.']); 
        } 
    }



    // GET mood names to populate Q2 in form
    if(($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["get-moods"])) && (isset($_GET["mood_rating_id"]))){

        include "dbconn.php";

        $mood_rating_id = $_GET['mood_rating_id'];

        $stmt = $conn->prepare("SELECT * FROM mood WHERE mood_rating_id = ?");
        $stmt->bind_param("i", $mood_rating_id);
        $stmt->execute();
        
        $result = $stmt->get_result();

        if(!$result){
            exit($conn->error);
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(404); 
            echo json_encode(["message" => "Unable to get moods from mood table in database!"]); 
        } 

    }

    // GET mood triggers to populate Q3 in form
    if(($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["mood-triggers"]))){

        include "dbconn.php";

        $sqlGetTriggers = "SELECT * FROM mood_trigger";
        $result = $conn->query($sqlGetTriggers);

        if(!$result){
            exit($conn->error);
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(404); 
            echo json_encode(["message" => "Unable to get triggers from mood_trigger table in database!"]); 
        } 
    }

    // GET info for moods over time chart
    if(($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["line-chart"])) && (isset($_GET["user_id"]))) {
        include "dbconn.php";
        $user_id = $_GET['user_id'];

        $sqlGetMoodLogInfo = "SELECT mood_log_id, mood_log_timestamp, mood_rating_id
                                FROM mood_log_session
                                WHERE user_id = ?";

        $stmt = $conn->prepare($sqlGetMoodLogInfo);
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if(!$result){
            exit($conn->error);
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(404); 
            echo json_encode(["message" => "Unable to get values from database!"]); 
        }    
    }

    // GET mood triggers and log_session for mood trigger CHART
    if(($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["triggers-chart"])) && (isset($_GET["user_id"]))){

        include "dbconn.php";

        $user_id = $_GET['user_id'];

        $sqlGetTriggers = "SELECT mood_log_session.mood_log_id, mood_log_timestamp, mood_rating_id, 
                            session_triggers.trigger_id, trigger_name
                            FROM mood_log_session
                            INNER JOIN session_triggers ON mood_log_session.mood_log_id = session_triggers.mood_log_id
                            INNER JOIN mood_trigger ON session_triggers.trigger_id = mood_trigger.trigger_id
                            WHERE user_id = ?";

        $stmt = $conn->prepare($sqlGetTriggers);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();

        $result = $stmt->get_result();

        if(!$result){
            exit($conn->error);
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(404); 
            echo json_encode(["message" => "Unable to get values from database!"]); 
        } 
    }

    // GET info for mood list display cards
    if (($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["cards"])) && (isset($_GET["user_id"]))) { 

        include "dbconn.php"; 

        $user_id = $_GET['user_id'];

        $get_mood_log_info = "SELECT mood_log_session.mood_log_id, mood_log_session.mood_log_timestamp, mood_log_session.mood_rating_id,
                            mood.mood_name, diary_entry.diary_entry_text
                            FROM mood_log_session
                            INNER JOIN mood ON mood_log_session.mood_id = mood.mood_id
                            LEFT JOIN diary_entry ON mood_log_session.diary_entry_id = diary_entry.diary_entry_id
                            WHERE user_id = ?
                            ORDER BY mood_log_session.mood_log_timestamp DESC";


        $stmt = $conn->prepare($get_mood_log_info);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if(!$result){
            exit($conn->error);
        }

        // build a response array 
        $api_response = array(); 

        while ($row = $result->fetch_assoc()) { 
            array_push($api_response, $row); 
        } 

        // encode the response as JSON 
        $response = json_encode($api_response); 

        // echo out the response 
        if ($response != false) { 
            http_response_code(200); 
            echo $response; 
        } else { 
            http_response_code(404); 
            echo json_encode(["message" => "Unable to process request!"]); 
        } 

    }

    
    // GET PAGINATED info for mood list display cards
    if (($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["page"])) && (isset($_GET["user_id"])) 
        && (isset($_GET["limit"]))) {

            include "dbconn.php"; 

            // get required info from request
            $user_id = $_GET['user_id'];
            $page = $_GET['page'];
            $limit = $_GET['limit'];
            $offset = ($_GET['page'] - 1) * $limit;

            // count all records
            $count_query = "SELECT COUNT(*) as count FROM mood_log_session WHERE user_id = $user_id";
            $count_result = $conn->query($count_query);
            $count = $count_result->fetch_assoc()['count'];

            $get_mood_log_info = "SELECT mood_log_session.mood_log_id, mood_log_session.mood_log_timestamp, mood_log_session.mood_rating_id,
                                        mood.mood_name, diary_entry.diary_entry_text
                                        FROM mood_log_session
                                        INNER JOIN mood ON mood_log_session.mood_id = mood.mood_id
                                        LEFT JOIN diary_entry ON mood_log_session.diary_entry_id = diary_entry.diary_entry_id
                                        WHERE user_id = ?
                                        ORDER BY mood_log_session.mood_log_timestamp DESC
                                        LIMIT ?, ?";

            $stmt = $conn->prepare($get_mood_log_info);
            $stmt->bind_param("iii", $user_id, $offset, $limit);
            $stmt->execute();

            $result = $stmt->get_result();

            if(!$result){
                exit($conn->error);
            }

            // build a response array 
            $api_response = array(); 

            while ($row = $result->fetch_assoc()) { 
                array_push($api_response, $row); 
            } 

            // add count to response array
            $api_response['count'] = $count;

            // encode the response as JSON 
            $response = json_encode($api_response); 

            // echo out the response 
            if ($response != false) { 
                http_response_code(200); 
                echo $response; 
            } else { 
                http_response_code(404); 
                echo json_encode(["message" => "Unable to process request!"]); 
            } 

    }

   
    // GET info for full info of selected display card
    if (($_SERVER['REQUEST_METHOD']==='GET') && (isset($_GET["full-card"])) && (isset($_GET["log_id"]))){

        include "dbconn.php";

        $log_id = $_GET['log_id'];

        $get_full_card = "SELECT mood_log_session.mood_log_timestamp, mood_log_session.mood_rating_id,
                            mood.mood_name, diary_entry.diary_entry_id, diary_entry.diary_entry_text
                            FROM mood_log_session
                            INNER JOIN mood ON mood_log_session.mood_id = mood.mood_id
                            LEFT JOIN diary_entry ON mood_log_session.diary_entry_id = diary_entry.diary_entry_id
                            WHERE mood_log_session.mood_log_id = $log_id;

                            SELECT session_triggers.trigger_id, mood_trigger.trigger_name
                            FROM session_triggers
                            INNER JOIN mood_trigger ON session_triggers.trigger_id = mood_trigger.trigger_id
                            WHERE session_triggers.mood_log_id = $log_id";
        

        if (mysqli_multi_query($conn, $get_full_card)) {
            $results = array(); // create an empty array to store the results
            // Loop through the results of each query
            do {
                // Get the result set
                if ($result = mysqli_store_result($conn)) {
                    // Fetch the results as an array
                    $rows = mysqli_fetch_all($result, MYSQLI_ASSOC);
                    // Add the results to the array
                    $results[] = $rows;
                    // Free the result set
                    mysqli_free_result($result);
                }
                // Move to the next result set
            } while (mysqli_next_result($conn));

            echo json_encode($results);
        }
        
    }
    










    // VALIDATE email address isn't already taken (for signup page)
    if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['validate-email'])) {
        include 'dbconn.php';

        $_DATA = json_decode(file_get_contents('php://input'), true);

        $email = $_DATA['email'];

        $sql = "SELECT * FROM user WHERE email_address = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $is_available = $result->num_rows === 0;

        header("Content-Type: application/json");
        echo json_encode(["available" => $is_available]);
    }



    // POST - check credential provided at login
    if (($_SERVER["REQUEST_METHOD"] === "POST") && (isset($_GET["check-login"]))) {

        include "dbconn.php";

        // retrieve the email and password from the POST request body
        $login = $_POST['loginEmailUsername'];
        $password = $_POST['loginPassword'];
        
        // query the database to check if the user exists and if the password is correct
        $sql = "SELECT * FROM user WHERE (email_address = ? OR username = ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $login, $login);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password_hash'])) {
                // if the credentials are valid, start a session and set the session ID
                session_start();
                session_regenerate_id();
                $_SESSION['user_id'] = $user['user_id'];
                // if the credentials are valid, return a JSON response with success set to true
                echo json_encode(['success' => true, 'user_id' => $user['user_id']]);
                exit;
            }
        }
        
        // if the credentials are invalid, return a JSON response with success set to false
        echo json_encode(['success' => false]);
        exit;
    }



    // POST writing signup details to user table
    // bind_param used to prevent sql injection attacks
    if (($_SERVER['REQUEST_METHOD']==='POST') && (isset($_GET['signup']))){

        include "dbconn.php";

        parse_str(file_get_contents('php://input'), $_DATA);

        $username = $_DATA['username'];
        $firstname = $_DATA['firstname'];
        $surname = $_DATA['surname'];
        $email = $_DATA['email'];
        $password_hash = $_DATA['passwordHash'];

        $sql = "INSERT INTO user (username, first_name, last_name, email_address, password_hash)
        VALUES (?, ?, ?, ?, ?)";

        $stmt = $conn->stmt_init();

        if (! $stmt->prepare($sql)) {
            die("SQL error: " . $conn->error);
        };

        $stmt->bind_param("sssss",
                $username,
                $firstname,
                $surname,
                $email,
                $password_hash
        );

        if ($stmt->execute()) {
            // If the query was successful, start session and return a success message to the client
            $newUserId = mysqli_insert_id($conn);
            

            $response = array('success' => true, 'user_id' => $newUserId, 'first_name' => $firstname);
            echo json_encode($response);
        } else {
            // If the query failed, check for error code 1062 and return an appropriate error message
            if ($conn->errno === 1062){
                $response = array('success' => false, 'message' => 'Account already exists with that email address');
                echo json_encode($response);
            }else{
                $response = array('success' => false, 'message' => 'SQL error: ' . $conn->error);
                echo json_encode($response);
            }
        }


    }


    // POST writing mood log form to database
    if (($_SERVER['REQUEST_METHOD']==='POST') && (isset($_GET['submit-mood-log']))){ 

        include "dbconn.php";

        // First get values
        parse_str(file_get_contents('php://input'), $_DATA);

        $user_id = $_DATA['user_id'];
        $moodRating = $_DATA['moodRating'];
        $moodID = $_DATA['moodName'];
        $diaryEnt = mysqli_real_escape_string($conn, $_DATA['diaryEntry']);

        $last_diary_ID = null;

        // Insert diary entry only if it is not empty
        if (!empty($diaryEnt)) {
            $insertDiary = "INSERT INTO diary_entry (diary_entry_text) VALUES ('$diaryEnt')";
            $result = $conn->query($insertDiary);
            if(!$result){
                http_response_code(400);
                echo json_encode(["message" => "Failed to insert new diary entry!"]);
                exit($conn->error);
            }else{
                http_response_code(201);
                $last_diary_ID = mysqli_insert_id($conn);
                echo json_encode(["message" => "New diary entry added at id = $last_diary_ID"]);
            }
            
        }

        // Insert q1, q2, and diary_entry_id(if applicable) to mood_log_session table
        if (empty($diaryEnt)) {
            $insertQ1Q2 = "INSERT INTO mood_log_session (user_id, mood_rating_id, mood_id, diary_entry_id) VALUES ('$user_id', '$moodRating', '$moodID', NULL)";
        }else{
            $insertQ1Q2 = "INSERT INTO mood_log_session (user_id, mood_rating_id, mood_id, diary_entry_id) VALUES ('$user_id', '$moodRating', '$moodID', '$last_diary_ID')";
        }
        
        $result2 = $conn->query($insertQ1Q2);

        $last_mood_log_ID = NULL;
        
        if(!$result2){
            http_response_code(400);
            echo json_encode(["message" => "Failed to insert new mood log session!"]);
            exit($conn->error);
        }else{
            http_response_code(201);
            $last_mood_log_ID = mysqli_insert_id($conn);
            echo json_encode(["message" => "New mood log session added at id = $last_mood_log_ID"]);
        }

        /*
        Had to insert rest of form first before inserting in session triggers
        so that we have a mood_log_id from the mood_log_session table
        */ 
        if(!empty($_DATA['trigger'])){

            $triggerArray = explode(',', $_DATA['trigger']);

            foreach($triggerArray as $trigger){
                $sqlQueryTrigs = "INSERT INTO session_triggers (mood_log_id, trigger_id) VALUES ('$last_mood_log_ID', '$trigger')"; 
        
                $result = $conn->query($sqlQueryTrigs);
        
                if(!$result){
                    http_response_code(400);
                    echo json_encode(["message" => "Failed to insert mood triggers!"]);
                    exit($conn->error);
                }else{
                    http_response_code(201);
                    $last_session_trigger_ID = mysqli_insert_id($conn);
                    echo json_encode(["message" => "New mood trigger added at id = $last_session_trigger_ID"]);
                }
            }
        }
    }
















    // PATCH - Update the diary entry and mood triggers 
    if (($_SERVER['REQUEST_METHOD']==='PATCH') && (isset($_GET['update-card']))) {

        include "dbconn.php";

        // First get values
        //parse_str(file_get_contents('php://input'), $_DATA);
        $_DATA = json_decode(file_get_contents('php://input'), true);
        //echo json_encode($_DATA);

        if ($_DATA !== null) {
            $log_id = $_DATA['log_id'];
            $diaryEntID = $_DATA['diary_entry_id'];
            $diaryEnt = mysqli_real_escape_string($conn, $_DATA['diary_entry']);

            // If user tries to update an empty diary(never created when filling in form)
            // Insert new diary entry, get its new ID, to update mood_log_session
            if($diaryEntID === ""){
                $sqlAddDiaryIfIdEmpty = "INSERT INTO diary_entry (diary_entry_text) VALUES ('$diaryEnt')";
                $result = $conn->query($sqlAddDiaryIfIdEmpty);
                if(!$result){
                    http_response_code(400);
                    echo json_encode(["message" => "Failed to overwrite empty diary with new entry!"]);
                    exit($conn->error);
                }else{
                    http_response_code(201);
                    $last_diary_ID = mysqli_insert_id($conn);
                    echo json_encode(["message" => "New diary entry added at id = $last_diary_ID"]);
                }

                // Update mood_log_session with diary id
                $sqlUpdateDiaryIdInMoodSession = "UPDATE mood_log_session SET diary_entry_id = '$last_diary_ID' WHERE mood_log_id = '$log_id'";
                $result = $conn->query($sqlUpdateDiaryIdInMoodSession); // Will return false if wasn't successful

                if(!$result){
                    http_response_code(400);
                    echo json_encode(["message" => "Failed to update diary id in mood log session table!"]);
                    exit($conn->error);
                }else{
                    http_response_code(201);
                    echo json_encode(["message" => "Diary id successfully updated in mood log session table"]);
                }
            } else{
            
                //Update diary entry
                $sqlUpdateDiary = "UPDATE diary_entry SET diary_entry_text = '$diaryEnt' WHERE diary_entry_id = '$diaryEntID'";
                $result = $conn->query($sqlUpdateDiary); // Will return false if wasn't successful

                if(!$result){
                    http_response_code(400);
                    echo json_encode(["message" => "Failed to update diary entry!"]);
                    exit($conn->error);
                }else{
                    http_response_code(201);
                    echo json_encode(["message" => "Diary entry successfully updated at diary_entry_id = $diaryEntID"]);
                }
            }
            
        } else {
            http_response_code(400);
            echo json_encode(["message" => "Failed to read from json decode!"]);
            exit($conn->error);
        }

        
        //Delete existing mood triggers before adding the new ones
        $sqlDeleteTriggers = "DELETE FROM session_triggers WHERE mood_log_id = $log_id";
        $result = $conn->query($sqlDeleteTriggers); // Will return false if delete wasn't successful

        if(!$result){
            http_response_code(400);
            echo json_encode(["message" => "Failed to delete mood triggers!"]);
            exit($conn->error);
        }else{
            http_response_code(201);
            echo json_encode(["message" => "All mood triggers deleted that match id = $log_id"]);
        }

        // Loop through new triggers and update
        if(!empty($_DATA['trigger'])){

            $triggerArray = array_map('intval', $_DATA['trigger']);

            foreach($triggerArray as $trigger){
                $sqlAddUpdatedTrigs = "INSERT INTO session_triggers (mood_log_id, trigger_id) VALUES ('$log_id', '$trigger')"; 
        
                $result = $conn->query($sqlAddUpdatedTrigs);
        
                if(!$result){
                    http_response_code(400);
                    echo json_encode(["message" => "Failed to insert updated mood triggers!"]);
                    exit($conn->error);
                }else{
                    http_response_code(201);
                    $last_session_trigger_ID = mysqli_insert_id($conn);
                    echo json_encode(["message" => "Updated mood trigger added at id = $last_session_trigger_ID"]);
                }
            }

            

        }
    }
















    //DELETE - Delete the selected mood card
    if (($_SERVER['REQUEST_METHOD']==='DELETE') && (isset($_GET['delete-card'])) && (isset($_GET["log_id"]))) {

        include "dbconn.php";

        $log_id = $_GET['log_id'];

        $sqlDeleteTriggers = "DELETE FROM session_triggers WHERE mood_log_id = ?";
        $stmt = $conn->prepare($sqlDeleteTriggers);
        $stmt->bind_param("i", $log_id);
        $stmt->execute();

        // SQL query - delete mls and de
        $sqlDeleteMoodLogAndDiary = "DELETE mood_log_session, diary_entry FROM mood_log_session
                                    LEFT JOIN diary_entry ON mood_log_session.diary_entry_id = diary_entry.diary_entry_id
                                    WHERE mood_log_id = ?";
        $stmt = $conn->prepare($sqlDeleteMoodLogAndDiary);
        $stmt->bind_param("i", $log_id);
        $stmt->execute();

        if($stmt->affected_rows > 0){
            http_response_code(200);
            echo json_encode(["message" => "Mood card deleted successfully"]);
        } else {
            http_response_code(400);
            echo json_encode(["message" => "Failed to delete mood card!"]);
            exit($conn->error);
        }
    }



    // DELETE user account.
    if (($_SERVER['REQUEST_METHOD']==='DELETE') && (isset($_GET['delete-account'])) && (isset($_GET['user_id']))) {

        include "dbconn.php";

        $user_id = $_GET['user_id'];

        echo $user_id;

        // prepare the statement for deleting session triggers
        $deleteSessionTriggers = $conn->prepare("
            DELETE FROM session_triggers 
            WHERE mood_log_id IN 
            (SELECT mood_log_id FROM mood_log_session WHERE user_id = ?)
        ");
        $deleteSessionTriggers->bind_param("i", $user_id);
        $deleteSessionTriggers->execute();

        // prepare the statement for deleting diary entries
        $deleteDiaryEntries = $conn->prepare("
            DELETE FROM diary_entry WHERE diary_entry_id IN 
            (SELECT diary_entry_id FROM mood_log_session WHERE user_id = ?)
        ");
        $deleteDiaryEntries->bind_param("i", $user_id);
        $deleteDiaryEntries->execute();

        // prepare the statement for deleting mood log sessions
        $deleteMoodLogSessions = $conn->prepare("
            DELETE FROM mood_log_session WHERE user_id = ?
        ");
        $deleteMoodLogSessions->bind_param("i", $user_id);
        $deleteMoodLogSessions->execute();

        // prepare the statement for deleting the user
        $deleteUser = $conn->prepare("
            DELeTE FROM user WHERE user_id = ?
        ");
        $deleteUser->bind_param("i", $user_id);
        $result = $deleteUser->execute();
        

        if  ($result) {
            $response = array(
                'status' => 'success',
                'message' => 'User account and related information deleted successfully'
            );
            echo json_encode($response);
        } else {
            $response = array(
                'status' => 'error',
                'message' => 'Error deleting user account and related information: ' . $conn->error
            );
            echo json_encode($response);
        }
        

    }
    

?>