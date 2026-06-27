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
header('X-REALLY-SIMPLE-SSL-TEST: q%B6%B3%F4%23%2B%94%EE%04Rd%9Fl%B2%07%04%D3%3EhrH%AB%8A%F9%AB8%5E%D0%B8%0F%60H%13%C1%DC%A5%BFx5%AAF%2F%83p%13%60%04%8B%9CW%D8%17%0C%B5%9D%E1%9E%ECq%23%9CP%97Zn%1A%22%0C%26%DA%25t%FA_k%E91%92%DC%14%02%8D%B3P%BDF%95%B2GH%7E9%A0W%24u%E7%27%15Pp%EC%ED%D4c%EB8%0F%BE%E3%E8%91%94%1Au%DF%FA%D9%90%21Ry%C8UY%1B%B6L%CF%D5%DEaY%9D%88im%BAb%80%5C%F6%22%D0%E4%B7%C9T%27RZ%1D%80%25%0F%E2%8F%D2%C6%90+%8A%C3%17%10%D53%B6%0E%EE%FC%2A%C1%07%18%F1%F4v%A4%C9%DFv6O%82%DB%B35%E3VJ%0Cc%01DI%9EcJ%DFkx%82%C6G%92u%B2AU%C5%');

 echo '<html><head><meta charset="UTF-8"><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body>Really Simple Security headers test page</body></html>';