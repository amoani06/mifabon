<?php
/**
* This file is created by Really Simple Security
*/

if (defined("SHORTINIT") && SHORTINIT) return;

$base_path = dirname(__FILE__);
if( file_exists( $base_path . "/rsssl-safe-mode.lock" ) ) {
    if ( ! defined( "RSSSL_SAFE_MODE" ) ) {
        define( "RSSSL_SAFE_MODE", true );
    }
    return;
}

if ( isset($_GET["rsssl_header_test"]) && (int) $_GET["rsssl_header_test"] ===  431690202 ) return;

if ( defined("RSSSL_HEADERS_ACTIVE" ) ) return;
define( "RSSSL_HEADERS_ACTIVE", true );
if ( file_exists( "C:\xampp\htdocs\mifabon/wp-content/firewall.php" ) ) {
    require_once "C:\xampp\htdocs\mifabon/wp-content/firewall.php";
}

//RULES START

if ( !headers_sent() ) {
header('X-XSS-Protection: 0');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Content-Security-Policy: frame-ancestors \'self\'; ');

}
