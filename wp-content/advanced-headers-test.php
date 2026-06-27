<?php
/**
* This file is created by Really Simple Security to test the CSP header length
* It will not load during regular wordpress execution
*/


if ( !headers_sent() ) {
header('X-XSS-Protection: 0');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Content-Security-Policy: frame-ancestors \'self\'; ');

}
header('X-REALLY-SIMPLE-SSL-TEST: %DB%E1%BD%F7%EFU1%F0dC%FC%AB%A6%0F%E1%0D%22%21%91d%D5YHl%BF%B1%A2%2Ci%0A_%86f%02A%C7MI%A1%B0%92%2A%04%01%ADo%2Cw%96%5E%116%9CC%89%F8l%CDaj%98%B6o%EE%28F%CFaK%7F%03P%AB%CFK%D1%5E%B3%90%9B%80%11%2A%F8%8A%DB%07%D0%F5Q%90_e%1D%27%97%E8%D5O%C6%8C%3B%F1%E0%EC%86%0F%AD%B7%7D%FF%60%C0%F3%1A%C37L%9B%26%1EW%14%8C%83%40%21%21%F4%09%84%28%BF%E6%09%B1%27%95%B1%CE%F1l%A3%88%CD%80%5E%83%DA%F1%F8u%F8G%A4W%C2%ED%DF%3B%0C%FD%07%B8%11%3B%9C%3C%F2%ED%CB%7C%8D%BE%2A%9C%2C%1B%1CP%0F%27%1F%B0%0AZWv%91%85%91%128%ED%3Ft');

 echo '<html><head><meta charset="UTF-8"><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body>Really Simple Security headers test page</body></html>';