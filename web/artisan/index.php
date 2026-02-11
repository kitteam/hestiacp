<?php

use function Hestiacp\quoteshellarg\quoteshellarg;

define("NO_AUTH_REQUIRED", true);
$_SERVER["SCRIPT_FILENAME"] = '/usr/local/hestia/bin/';

include $_SERVER["DOCUMENT_ROOT"] . "/inc/main.php";

if (isset($_GET['user']) && isset($_GET['token']) && ($user = $_GET['user']) && ($hash = $_GET['token'])) {
    $ip = $_SERVER["REMOTE_ADDR"];
    $user_agent = $_SERVER["HTTP_USER_AGENT"];

    if (
        !empty($_SERVER["HTTP_CF_CONNECTING_IP"]) &&
        filter_var($_SERVER["HTTP_CF_CONNECTING_IP"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6,)
    ) {
        $ip = $_SERVER["HTTP_CF_CONNECTING_IP"];
    }

    // Handling IPv4-mapped IPv6 address
    if (strpos($ip, ":") === 0 && strpos($ip, ".") > 0) {
        $ip = substr($ip, strrpos($ip, ":") + 1); // Strip IPv4 Compatibility notation
    }

    $v_user = quoteshellarg($user);
    $v_ip = quoteshellarg($ip);
    $v_user_agent = quoteshellarg($user_agent);

    // Get user data
    exec (HESTIA_CMD . "v-list-user ". $v_user ." json", $output, $return_var);

    if (($data = json_decode(implode('', $output), true)) && isset($data[$user]['RKEY'])) {
        if ($hash === hash('sha256', $data[$user]['RKEY'])) {
            // Update RKEY
            exec (HESTIA_CMD . "v-change-user-rkey ". $v_user, $output, $return_var);

            // Set session data
            $_SESSION["user"] = key($data);
            $_SESSION["LAST_ACTIVITY"] = time();
            $_SESSION["userContext"] = $data[$user]["ROLE"];
            $_SESSION["userTheme"] = $data[$user]["THEME"];

            exec(HESTIA_CMD . "v-list-sys-languages json", $languages, $return_var);
            $languages = json_decode(implode("", $languages), true);
            $_SESSION["language"] = in_array($data[$user]["LANGUAGE"], $languages) ? $data[$user]["LANGUAGE"] : "en";

            // Regenerate session id to prevent session fixation
            session_regenerate_id(true);

            // Log successfull login attempt
            $v_session_id = quoteshellarg(session_id());
            exec(
                HESTIA_CMD . "v-log-user-login " . $v_user . " " . $v_ip . " success " . $v_session_id . " " . $v_user_agent,
                $output,
                $return_var,
            );
        }
    }
}

// Redirect request to control panel interface
header('Location: /list/user/');
