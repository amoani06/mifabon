<?php
if (!defined("RSSSL_HEADERS_ACTIVE") && file_exists( ABSPATH . "wp-content/advanced-headers.php")) {
	require_once ABSPATH . "wp-content/advanced-headers.php";
}

//Begin Really Simple Security session cookie settings
@ini_set('session.cookie_httponly', true);
@ini_set('session.cookie_secure', true);
@ini_set('session.use_only_cookies', true);
//END Really Simple Security cookie settings
//Begin Really Simple Security key
define('RSSSL_KEY', 'gm4UsghW2dW4sCRbDa3Zbq8jtMFBSEsAStUXbJ2b1w1FStnMOGnIaqgFoqW1kTPM');
//END Really Simple Security key

/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'mifabon_db' );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', '' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'k.TJB63S`8xuzRNT*dMupAbDuMR2DduE1Zri+bKF[{%o@aFxf$04GHEIh;q7kjV?' );
define( 'SECURE_AUTH_KEY',  '!T9pSl%Iy59[9)P6]!hb=m96irIyRcOQ0/RLg%sCg[qkkkfwg2M=G&z,}65^CqM>' );
define( 'LOGGED_IN_KEY',    '*?:QpJ/?FbwxtS;@Q%CM+@=qJ;3W)13A _cYOL^L{{qtA*v;#Zrri/M|+,DaB`5h' );
define( 'NONCE_KEY',        '3b^aAF*n0J0Pf9rl|{jWMe/)G<WzmnMJ&:-NYT[NPA%,Reib<fa8&]XvYv1KKq[0' );
define( 'AUTH_SALT',        'T@>{C `=NI+EiJVo.U,l*}339f-4xrNQ.DJ>rT?t[l-bq)|nb7rS)zBP0@^}hxJJ' );
define( 'SECURE_AUTH_SALT', 'eVw!XIW3LN))URI}=N:+iXWIth[!kZx0-`OwU$AT  O0UiFKcss709|H1k`cQ[r_' );
define( 'LOGGED_IN_SALT',   'QtWv ye>K0/vMy_8I(o<}B]SZ5>#D4X,!|Pme6dk#:&Ea_x>+yC0kqP:o7>0:79h' );
define( 'NONCE_SALT',       '8bMs6WL-#LYnd:AVl-iBh%qAE;p93o,!cmxB1(mZT{64PM1)&/vKJWNV!gynmW@T' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 *
 * At the installation time, database tables are created with the specified prefix.
 * Changing this value after WordPress is installed will make your site think
 * it has not been installed.
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#table-prefix
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
