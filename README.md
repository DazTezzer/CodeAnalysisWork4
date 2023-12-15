Задачи
1.	Необходимо найти участок кода, содержащий инъекцию SQL кода в задании Blind Sql Injection на сайте dvwa.local
с использованием статического анализатора кода (Можно использовать официальный ресурс или виртуальную машину Web Security Dojo)
3.	Проанализировать код и сделать кодревью, указав слабые места
```
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
        // Get input
        $id = $_GET[ 'id' ];

        // Check database
        $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

        // Get results
        $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
        if( $num > 0 ) {
                // Feedback for end user
                $html .= '<pre>User ID exists in the database.</pre>';
        }
        else {
                // User wasn't found, so the page wasn't!
                header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

                // Feedback for end user
                $html .= '<pre>User ID is MISSING from the database.</pre>';
        }

        ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```
3.	Разработать свою систему вывода информации об объекте на любом языке,
исключающий возможность инъекции SQL кода. Возможно исправление участка кода из dvwa.local

Требования к системе авторизации
•	Система вывода информации об объекте должна использовать запросы GET с параметрами,
аналогичными из задания Blind SQL injection dvwa
dvwa.local/vulnerabilities/sqli/?username=USER&password=PASS&user_token=TOKEN&Login=Login
4.	Использовать sqlmap для нахождения уязвимости в веб-ресурсе
5.	Использовать Burp для нахождения уязвимости в веб-ресурсе


Задание 1

```
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = $_GET[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			try {
				$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
			} catch (Exception $e) {
				print "There was an error.";
				exit;
			}

			$exists = false;
			if ($result !== false) {
				try {
					$exists = (mysqli_num_rows( $result ) > 0);
				} catch(Exception $e) {
					$exists = false;
				}
			}
			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			try {
				$results = $sqlite_db_connection->query($query);
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}

			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

}

?>
```
Уязвимое место - 
```
	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			try {
				$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
			} catch (Exception $e) {
				print "There was an error.";
				exit;
			}
```
1 Вариант с одинарной кавычкой: Если пользователь вводит следующую строку в поле id: 1' OR '1'='1, то SQL-запрос будет выглядеть следующим образом:
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
Это условие всегда будет истинным и метод mysqli_num_rows() вернет больше 0 результатов, в результате чего скрипт покажет сообщение "User ID exists in the database.".
2 Вариант с комментарием: Если пользователь вводит следующую строку в поле id: 1'; --, то SQL-запрос будет выглядеть следующим образом:
SELECT first_name, last_name FROM users WHERE user_id = '1'; --';
Часть запроса после комментария -- будет проигнорирована, и это позволит получить данные, которые не предназначены для пользователя.

Задание 2 

![image](https://github.com/DazTezzer/CodeAnalysisWork4/assets/125472899/6f4b75a0-bedb-4f57-a205-bdd01194067f)

Задание 3 

SQL-инъекция: В данном коде используется переменная $id, которая напрямую вставляется в SQL-запрос.
Злоумышленник может использовать SQL-инъекцию для выполнения вредоносного кода или получения несанкционированного доступа к данным.
Рекомендуется использовать параметризованные запросы (prepared statements) или функцию экранирования символов для предотвращения этой уязвимости.
Так был исправлен код: 
```
<?php
if (isset($_GET['Submit'])) {
    // Get input
    $id = $_GET['id'];

    // Check database
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = ?";
    $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $getid);
    mysqli_stmt_bind_param($stmt, "s", $id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    // Get results
    $num = mysqli_num_rows($result);
    if ($num > 0) {
        // Feedback for end user
        $html .= '<pre>User ID exists in the database.</pre>';
    } else {
        // User wasn't found, so the page wasn't!
        header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');

        // Feedback for end user
        $html .= '<pre>User ID is MISSING from the database.</pre>';
    }

    mysqli_stmt_close($stmt);
}
?>
```
Задание 4

![image](https://github.com/DazTezzer/CodeAnalysisWork4/assets/125472899/38e24a17-7175-4061-94cf-dcc093622897)
Задание 5

![image](https://github.com/DazTezzer/CodeAnalysisWork4/assets/125472899/7439b98b-7180-48b4-b227-fe91e0b8548c)
