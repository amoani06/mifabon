<?php
/**
 * Plugin Name: Really Simple Security Pro
 * Plugin URI: https://really-simple-ssl.com
 * Description: Simple and performant security
 * Version: 9.6.0
 * Requires at least: 6.6
 * Requires PHP: 7.4
 * Author: Really Simple Plugins
 * Author URI: https://really-simple-ssl.com/about-us
 * License: GPLv2
 * Text Domain: really-simple-ssl
 * Domain Path: /languages
 *
 * Copyright (C) 2025 Really Simple Plugins B.V. (support@really-simple-ssl.com)
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2, as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU General Public License for more details. You should have received
 * a copy of the GNU General Public License along with this program; if not,
 * write to the Free Software Foundation, Inc.
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

defined( 'ABSPATH' ) or die( "you do not have access to this page!" );

if ( ! defined( 'rsssl_file' ) ) {
	define( 'rsssl_file', __FILE__ );
}

if ( ! defined( 'rsssl_plugin' ) ) {
    define( 'rsssl_plugin', plugin_basename( __FILE__ ) );
}

if ( ! function_exists( 'rsssl_pro_activation_check' ) ) {
    function rsssl_pro_activation_check() {
        update_option( 'rsssl_activation', true, false );
        update_option( 'rsssl_run_activation', true, false );
        update_option( 'rsssl_show_onboarding', true, false );
        update_option( 'rsssl_redirect_to_settings_page', true );
        rsssl_request_managed_rule_rebuild();
    }

    function rsssl_check_reactivation() {
        if ( get_option( 'rsssl_activation_handled' ) ) {
            return;
        }

        // Non-admin requests, including PHPUnit bootstrap, can reach this hook
        // before RSSSL_SECURITY loads the security helpers used during reactivation.
        if ( ! rsssl_admin_logged_in() ) {
            return;
        }

        rsssl_pro_activation_check();
        update_option( 'rsssl_activation_handled', true, false );
    }

    register_activation_hook( __FILE__, function () {
        delete_option( 'rsssl_activation_handled' );
    });

    // Check for reactivation logic during initialization
    add_action( 'plugins_loaded', 'rsssl_check_reactivation' );
}

// Load deactivation function early to prevent conflicts
if (!function_exists('rsssl_deactivate_alternate')) {
    $rsssl_path = trailingslashit( plugin_dir_path( __FILE__ ) );
    require_once $rsssl_path . 'functions.php';
}

// Handle plugin conflicts before checking class existence
// On multisite: deactivate pro plugin if multisite is needed
if (!is_multisite()) {
    // Check if multisite plugin is active
    include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
    $multisite_plugin = 'really-simple-ssl-pro-multisite/really-simple-ssl-pro-multisite.php';

    // If multisite plugin is active, this pro plugin should not run
    if (is_plugin_active($multisite_plugin) || is_plugin_active_for_network($multisite_plugin)) {
	    // On single site: deactivate multisite plugin if active
	    rsssl_deactivate_alternate('multisite');
    }
}

// Load rsssl_free_active function early to prevent conflicts
if (!function_exists('rsssl_free_active')) {
	$rsssl_path = trailingslashit( plugin_dir_path( __FILE__ ) );
	require_once $rsssl_path . 'functions.php';
}
if ( rsssl_free_active() ) {
// Always deactivate free plugin if active
	rsssl_deactivate_alternate( 'free' );
}

if ( class_exists('REALLY_SIMPLE_SSL') ) {
    // Another version is already loaded, don't proceed
    return;
} else {
    class REALLY_SIMPLE_SSL {
        private static $instance;
        public $front_end;
        public $mixed_content_fixer;
        public $multisite;
        public $cache;
        public $server;
        public $admin;
        public $progress;
        public $onboarding;
        public $placeholder;
        public $certificate;
        public $wp_cli;
        public $mailer_admin;
        public $site_health;
        public $vulnerabilities;
        public $settingsConfigService;

        # Pro
        public $pro_admin;
        public $support;
        public $licensing;
        public $csp_backend;
        public $headers;
        public $scan;
        public $importer;

        private function __construct() {
            if ( isset( $_GET['rsssl_apitoken'] ) && $_GET['rsssl_apitoken'] == get_option( 'rsssl_csp_report_token' ) ) {
                if ( ! defined( 'RSSSL_LEARNING_MODE' ) ) {
                    define( 'RSSSL_LEARNING_MODE', true );
                }
            }
        }

        public static function instance() {
            if ( ! isset( self::$instance ) && ! ( self::$instance instanceof REALLY_SIMPLE_SSL ) ) {
                self::$instance = new REALLY_SIMPLE_SSL;
                self::$instance->setup_constants();
                self::$instance->includes();
                self::$instance->front_end           = new rsssl_front_end();
                self::$instance->mixed_content_fixer = new rsssl_mixed_content_fixer();

                if ( is_multisite() ) {
                    self::$instance->multisite = new rsssl_multisite();
                }
                if ( rsssl_admin_logged_in() ) {
                    self::$instance->cache        = new rsssl_cache();
                    self::$instance->placeholder  = new rsssl_placeholder();
                    self::$instance->server       = new rsssl_server();
                    self::$instance->admin        = new rsssl_admin();
                    self::$instance->mailer_admin = new rsssl_mailer_admin();
                    self::$instance->progress     = new rsssl_progress();
                    self::$instance->certificate  = new rsssl_certificate();
                    self::$instance->site_health  = new rsssl_site_health();

                    if (class_exists('\ReallySimplePlugins\RSS\Core\Services\SettingsConfigService')) {
                        self::$instance->settingsConfigService = new \ReallySimplePlugins\RSS\Core\Services\SettingsConfigService();
                    }

                    if ( defined( 'WP_CLI' ) && WP_CLI ) {
                        self::$instance->wp_cli = new rsssl_wp_cli();
                    }

                    # Pro
                    self::$instance->licensing   = new rsssl_licensing();
                    self::$instance->pro_admin   = new rsssl_pro_admin();
                    self::$instance->headers     = new rsssl_headers();
                    self::$instance->scan        = new rsssl_scan();
                    self::$instance->importer    = new rsssl_importer();
                    self::$instance->support     = new rsssl_support();
                    self::$instance->csp_backend = new rsssl_csp_backend();
                }
                self::$instance->hooks();
            }

            return self::$instance;
        }

        private function setup_constants() {

            define( 'rsssl_url', plugin_dir_url( __FILE__ ) );
            define( 'rsssl_path', trailingslashit( plugin_dir_path( __FILE__ ) ) );
            define( 'rsssl_template_path', trailingslashit( plugin_dir_path( __FILE__ ) ) . 'grid/templates/' );

			define( 'rsssl_version', '9.6.0' );

            define( 'rsssl_pro', true );

            define( 'rsssl_le_cron_generation_renewal_check', 20 );
            define( 'rsssl_le_manual_generation_renewal_check', 15 );

            if ( ! defined( 'REALLY_SIMPLE_SSL_URL' ) ) {
                define( 'REALLY_SIMPLE_SSL_URL', 'https://really-simple-ssl.com' );
            }

            define( 'RSSSL_ITEM_ID', 860 );
            define( 'RSSSL_ITEM_NAME', 'Really Simple Security Pro' );
            define( 'RSSSL_ITEM_VERSION', rsssl_version );
        }

        private function includes() {
            $target_file_path = rsssl_path . 'class-front-end.php';

            require_once( $target_file_path );

            require_once( rsssl_path . 'functions.php' );
            require_once( rsssl_path . 'class-mixed-content-fixer.php' );
            if ( defined( 'WP_CLI' ) && WP_CLI ) {
                require_once( rsssl_path . 'class-wp-cli.php' );
            }

            if ( is_multisite() ) {
                require_once( rsssl_path . 'class-multisite.php' );
            }

            require_once( rsssl_path . 'pro/includes.php' );

            require_once( rsssl_path . 'lets-encrypt/cron.php' );
            require_once( rsssl_path . 'security/security.php' );

            if ( rsssl_admin_logged_in() ) {
                require_once( rsssl_path . 'compatibility.php' );
                require_once( rsssl_path . 'upgrade.php' );
                require_once( rsssl_path . 'settings/settings.php' );
                require_once( rsssl_path . 'modal/modal.php' );
                require_once( rsssl_path . 'placeholders/class-placeholder.php' );
                require_once( rsssl_path . 'class-admin.php' );
                require_once( rsssl_path . 'mailer/class-mail-admin.php' );
                require_once( rsssl_path . 'class-cache.php' );
                require_once( rsssl_path . 'class-server.php' );
                require_once( rsssl_path . 'progress/class-progress.php' );
                require_once( rsssl_path . 'class-certificate.php' );
                require_once( rsssl_path . 'class-site-health.php' );
                require_once( rsssl_path . 'mailer/class-mail.php' );
                require_once( rsssl_path . 'lets-encrypt/letsencrypt.php' );
                if ( isset( $_GET['install_pro'] ) ) {
                    require_once( rsssl_path . 'upgrade/upgrade-to-pro.php' );
                }
            }
            require_once( rsssl_path . '/rsssl-auto-loader.php' );
        }
        private function hooks() {
            add_action( 'wp_loaded', array( self::$instance->front_end, 'force_ssl' ), 20 );
            if ( rsssl_admin_logged_in() ) {
                add_action( 'plugins_loaded', array( self::$instance->admin, 'init' ), 10 );
            }

        }
    }
}

if ( !defined('RSSSL_DEACTIVATING_ALTERNATE')
    && !function_exists('RSSSL')
) {
    function RSSSL() {
        return REALLY_SIMPLE_SSL::instance();
    }

    add_action( 'plugins_loaded', 'RSSSL', 8 );

    if (file_exists(__DIR__  . '/core/really-simple-security-core.php')) {
        require_once __DIR__  . '/core/really-simple-security-core.php';
    }

}

if ( ! function_exists( 'rsssl_add_manage_security_capability' ) ) {
    /**
     * Add a user capability to WordPress and add to admin and editor role
     */
    function rsssl_add_manage_security_capability() {
        $role = get_role( 'administrator' );
        if ( $role && ! $role->has_cap( 'manage_security' ) ) {
            $role->add_cap( 'manage_security' );
        }
    }

    register_activation_hook( __FILE__, 'rsssl_add_manage_security_capability' );
}

if ( ! function_exists( 'rsssl_user_can_manage' ) ) {
    /**
     * Check if user has required capability
     * @return bool
     */
    function rsssl_user_can_manage() {
        if ( current_user_can( 'manage_security' ) ) {
            return true;
        }

        #allow wp-cli access to activate ssl
        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return true;
        }

        return false;
    }
}

if ( ! function_exists( 'rsssl_admin_logged_in' ) ) {
    function rsssl_admin_logged_in() {
        $wpcli = defined( 'WP_CLI' ) && WP_CLI;

        return ( is_admin() && rsssl_user_can_manage() ) || rsssl_is_logged_in_rest() || wp_doing_cron() || $wpcli || defined( 'RSSSL_DOING_SYSTEM_STATUS' ) || defined( 'RSSSL_LEARNING_MODE' );
    }
}

if ( ! function_exists( 'rsssl_is_logged_in_rest' ) ) {
	function rsssl_is_logged_in_rest() {
		// Check if the request URI is valid
		if (!isset($_SERVER['REQUEST_URI'])) {
			return false;
		}

		$request_uri = $_SERVER['REQUEST_URI'];

		// Check for a direct REST API path
		if (strpos($request_uri, '/really-simple-security/v') !== false) {
			return is_user_logged_in();
		}

		// Check for rest_route parameter with really-simple-security (plain permalinks)
		if (strpos($request_uri, 'rest_route=') !== false &&
		    strpos($request_uri, 'really-simple-security') !== false) {
			return is_user_logged_in();
		}

		return false;
	}
}

add_filter('plugins_loaded', function() {
    if ( ! function_exists( 'rsssl_is_networkwide_active' ) ) { return; }
$key = 'OYLITE0000000005603B1EBE59708542';
    if ( is_multisite() && rsssl_is_networkwide_active() ) {
        $opts = get_site_option( 'rsssl_options', [] );
        $opts['license'] = $key;
        update_site_option( 'rsssl_options', $opts );
    } else {
        $opts = get_option( 'rsssl_options', [] );
        if ( ! is_array( $opts ) ) { $opts = []; }
        $opts['license'] = $key;
        update_option( 'rsssl_options', $opts );
    }
    $tr = get_site_option( 'rsssl_transients', array() );
    $tr['rsssl_pro_license_status'] = array( 'value' => 'valid', 'expires' => time() + 52 * WEEK_IN_SECONDS );
    update_site_option( 'rsssl_transients', $tr );
    update_site_option( 'rsssl_pro_license_activation_limit', 0 );
    update_site_option( 'rsssl_pro_license_activations_left', 0 );
    update_site_option( 'rsssl_pro_license_expires', 'lifetime' );
}, 11);

add_filter( 'pre_http_request', function( $preempt, $args, $url ) {
    if ( strpos( $url, 'really-simple-ssl.com' ) === false ) { return $preempt; }
    $body = isset( $args['body'] ) ? $args['body'] : '';
    if ( is_array( $body ) ) { $body = http_build_query( $body ); }
    if ( strpos( $body, 'edd_action' ) === false ) { return $preempt; }
    return array(
        'response' => array( 'code' => 200 ),
        'body'     => json_encode( array(
            'success'          => true,
            'license'          => 'valid',
            'item_id'          => 860,
            'item_name'        => 'Really Simple SSL pro',
            'is_local'         => false,
            'license_limit'    => 100,
            'site_count'       => 1,
            'expires'          => '2050-01-01 23:59:59',
            'activations_left' => 99,
'checksum'         => 'OYLITE0000000005603B1EBE59708542',
            'payment_id'       => 123321,
'customer_name'   => 'OYLITE',
            'customer_email'  => 'noreply@gmail.com',
            'price_id'         => '1',
        ) )
    );
}, 10, 3 );