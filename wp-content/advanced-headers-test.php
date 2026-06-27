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
header('X-REALLY-SIMPLE-SSL-TEST: b%A1%B09%B4%E1c%FF%CC%CC%7B%99%E0%B9%04J%A2%C1%E8%B7Q%B4%5D%FE%1C%07%A0C%7D%91%DD%80%F8%40%5Bo%F3%C3%07R%18%B9%0E%24%1F%D2%E5%FA%85%C7.%A3%F3%CF%C2z%B0y%E6Y%1FX%93w%EE%01%2Bd%817%06%E7Q%95%0FK%C7%BD%DDn%C4%EA%0D%93%E8%16%F0%D0%A9s%F8%06%BE7%A1%2B%A9%ED%09%1F%08%C0u%C2%F40%E7%FAv%BFps%5D%85%AC%D9%5CQ%88Duz%06En%C6%BA%13%18%F0%97%2B%E4%8D%2B%07%E0%C9%01%99%E0%8DX%D1N%E5%F0%A1%185a%AA%13VT%7B%5C%2B%81%BE%95%BE%B3%8C%BE%9E%DE%C9c%96Z%D8%2B%E9%EA%5C-Dq%FC%5E%06%0ELB7K%86%EE%B4%D1%D9o%CC%FCh%C6%FA%F5L');

 echo '<html><head><meta charset="UTF-8"><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body>Really Simple Security headers test page</body></html>';