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
header('X-REALLY-SIMPLE-SSL-TEST: n%CB%E5+%E7P%89%E4%F3K%A1%F9%0B%A8%1E%E1%8A%E8%AB%C2%3D0%A1Z%B7%C3%1C%EF%1E%8A%3C%E6q%13J%D6%05%84P%BC%D9%FF%83%7C%F5%5E%C3i%2FW%13-%24l%3F%E7%8A%9B%8B%5C%3D%BE%F5%22%B6%8A%2F%27%B3%91%CEj%C0%D0%0E%AFs%16%1D%EA%A1%FC%81%D4%C7%0B%9B%03%E5%87B%C2%0A%5E%C8%1Ccx%BC%C8%F8%EE%82T%A7%08%94%E0%FD%F6n%E0%D2%21jH%E7%D5%FC%08%96pK%EA%2F%BB%21%A6%D4%9B%FD%5D8%D1%A4Q%9F%BD%A5%00%AD0%0C%12%99q%26%84%A7%D9%97%9A%5E%DEn%A9%F9%F3%CD%95%A8%01%82T%EF%BC%F0%19q%02o%9Fa%AD%26%DBH%D5%1A8B%F9%7C%A8%8E%AD%EBz%05%DF%A8%');

 echo '<html><head><meta charset="UTF-8"><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body>Really Simple Security headers test page</body></html>';