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
header('X-REALLY-SIMPLE-SSL-TEST: %B9%1B%8F%F8%BF%B2%C9%98W%E84%89Gnw%3F%D3%C8%F9%2A%8B%C0%CC2hU%0Bu%F20%1FIW%B3%3E%D8l%B3%28%FF%CC%F8%22+%043%AC%F5t%E1%5DO%DA%3C%08%96%057%DFt%9D%2Bn%1Dl%E4x%AA%0A%2Bc%9E6%90%8D%DC%E2%FB%26%40%C0%DE%E6%F7%7Bt3%83%A7%FEz1%AD%D0%98%1CA%A7%89Pf%18T%D4M%1A%DB%81%BBf%F7%FD%E0%C1%DAR%10%CDq%AF%2B%18e%09Q%B2%28%DB%88%1C%DD%A8%10%CB%FA%CAG%AF%0F%C1D%DDl%2A%B3%1B%90%5E%C7%A8%25%EA%F6%01%10%E0%B7+%C0G%BF%FD%83x%17%F30Y%3A1by%DD%E5%01%BA%07%3En%0F%85%DA2%F5%93%84%0D%B8%12%D0%BA%E5%D2%8E%29%17%ED%CC%A4c%9F%');

 echo '<html><head><meta charset="UTF-8"><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body>Really Simple Security headers test page</body></html>';