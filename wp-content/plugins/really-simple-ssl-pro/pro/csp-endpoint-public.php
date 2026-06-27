<?php

use RSSSL\Security\RSSSL_Htaccess_File_Manager;

defined('ABSPATH') or die("you do not have access to this page!");

/**
 *
 * API for Content Security Policy registration
 * @Since 2.5
 *
 */

if ( rsssl_get_option('csp_status') === 'learning_mode' ) {
    add_action('rest_api_init', 'rsssl_pro_csp_rest_route');
}

if ( !function_exists('rsssl_maybe_enable_learning_mode') ) {
	/**
	 * To limit server load, we pause after a certain number of requests, then restart after 5 minutes.
	 * Only in learning_mode
	 *
	 * @return void
	 */
	function rsssl_maybe_enable_learning_mode() {
		if ( rsssl_get_option('csp_status')!=='learning_mode' || !get_site_option( 'rsssl_csp_reporting_temp_paused' ) ) {
			return;
		}

		$time_paused = get_site_option( 'rsssl_csp_hit_timestamp' );
		$x_minutes_ago = strtotime('2 minutes ago');
		if ($time_paused < $x_minutes_ago ) {
			if ( !defined( 'RSSSL_LEARNING_MODE' ) ) {
				define( 'RSSSL_LEARNING_MODE', true );
			}
			delete_site_option( 'rsssl_csp_hit_count' );
			delete_site_option( 'rsssl_csp_reporting_temp_paused' );
			//ensure the headers file is included this early.
			if ( !class_exists('rsssl_headers') ) {
				require_once( rsssl_path . '/pro/class-headers.php' );
				$headers = new rsssl_headers();
			}

			if ( !class_exists('rsssl_firewall_manager') ) {
				require_once( rsssl_path.'security/' . 'firewall-manager.php' );
				$htAccessFileManager = RSSSL_Htaccess_File_Manager::get_instance();
				$firewall_manager = new rsssl_firewall_manager($htAccessFileManager);
				$firewall_manager->update_advanced_headers();
			} else {
				rsssl_request_advanced_headers_rebuild();
			}
		}
	}
	add_action( 'rsssl_five_minutes_cron', 'rsssl_maybe_enable_learning_mode' );
}

if ( !function_exists('rsssl_pro_csp_rest_route')) {
	function rsssl_pro_csp_rest_route() {
		$cspRouteArguments = [
			'methods' => 'POST',
			'callback' => 'rsssl_track_csp',
			'permission_callback' => 'rsssl_pro_validate_api_call',
		];

		// Register new namespace since 9.5.1
		register_rest_route( 'really-simple-security/v1', 'csp/', $cspRouteArguments );

		// BACKWARDS COMPATIBILITY: Register old namespace for cached CSP headers
		register_rest_route( 'rsssl/v1', 'csp/', $cspRouteArguments );

	}
}

/**
 * @param $request
 * @return bool
 *
 * Check if the requests' comes from own server
 * @since 4.1.4
 *
 */
if ( !function_exists('rsssl_pro_validate_api_call')) {
	function rsssl_pro_validate_api_call( $request ) {
		$origin = $request->get_header( 'host' );

		if ( $request->get_param( 'rsssl_apitoken' ) != get_site_option( 'rsssl_csp_report_token' ) ) {
			return false;
		}

		if ( strpos( site_url(), $origin ) !== false || strpos( home_url(), $origin ) !== false ) {
			//we're about to give access to the backend for this api call
			if ( ! defined( 'RSSSL_LEARNING_MODE' ) ) {
				define( 'RSSSL_LEARNING_MODE', true );
			}
			return true;
		}

		return false;
	}
}

if ( !function_exists('rsssl_maybe_disable_learning_mode_after_period') ) {
	function rsssl_maybe_disable_learning_mode_after_period(){
		if ( rsssl_get_option( 'csp_status' )==='learning_mode' ) {
			//disable learning mode after one week
			$activation_time = get_site_option( 'rsssl_csp_report_only_activation_time' );
			$nr_of_days_learning_mode = apply_filters( 'rsssl_pause_after_days', 7 );
			$one_week_ago = strtotime( "-$nr_of_days_learning_mode days" );
			if ( $activation_time < $one_week_ago ) {
				//ensure the functions are included
				if ( !function_exists('rsssl_update_option' )) {
					require_once( rsssl_path . 'settings/settings.php' );
				}
				rsssl_update_option( 'csp_status', 'completed' );
			}
		}
	}
	add_action( 'rsssl_daily_cron', 'rsssl_maybe_disable_learning_mode_after_period' );
}

/**
 * @param WP_REST_Request $request
 *
 * @Since 2.5
 *
 * Process Content Security Policy violations, add to DB
 *
 * $blockeduri: the domain which is blocked due to content security policy rules
 * $documenturi: the post/page where the violation occurred
 *
 */
if (!function_exists('rsssl_track_csp')) {
	function rsssl_track_csp( WP_REST_Request $request ) {
		if ( $request->get_param( 'rsssl_apitoken' ) != get_site_option( 'rsssl_csp_report_token' ) ) {
			return;
		}
		//after x requests pause it for 5 minutes
		$count = get_site_option('rsssl_csp_hit_count', 0);
		$max_count = defined('RSSSL_CSP_MAX_REQUESTS') ? RSSSL_CSP_MAX_REQUESTS : 20;
		if ( $count < $max_count ) {
			$count ++;
			update_site_option( 'rsssl_csp_hit_count', $count );
			update_site_option( 'rsssl_csp_hit_timestamp', time() );

			global $wpdb;
			$table_name = $wpdb->base_prefix . "rsssl_csp_log";
			$row_count  = $wpdb->get_var( "SELECT count(*) FROM $table_name" );
			if ( $row_count >= 500 ) {
				return;
			}

			//CSP-report-only data is contained in php://input stream
			$json_data         = file_get_contents( 'php://input' );
			$json_data         = json_decode( $json_data, true );

			// Validate JSON structure
			if ( !is_array($json_data) || !isset($json_data['csp-report']) ) {
				return;
			}

			$csp_report        = $json_data['csp-report'];
			$blockeduri        = rsssl_sanitize_uri_value( $csp_report['blocked-uri'] );
			$violateddirective = rsssl_sanitize_csp_violated_directive( $csp_report['effective-directive'] ?? '' );
			if ( empty( $violateddirective ) ) {
				$violateddirective = rsssl_sanitize_csp_violated_directive( $csp_report['violated-directive'] ?? '' );
			}
			$documenturi       = esc_url_raw( $json_data['csp-report']['document-uri'] );
			// Remove query strings from $documenturi. strstr will return false if needle is not found. Therefore continue with $documenturi when strstr returns false
			$documenturi = strstr( $documenturi, '?', true ) ?: $documenturi;
			//If one of these is empty we cannot generate a CSP rule from it, return
			if ( ! empty( $violateddirective ) && ! empty( $blockeduri ) ) {
				//Check if the blockeduri and violatedirective already occur in DB. If so, we do not need to add them again.
				$count = $wpdb->get_var( $wpdb->prepare( "SELECT count(*) FROM $table_name where blockeduri = %s AND violateddirective=%s", $blockeduri, $violateddirective ) );
				if ( $count == 0 ) {
					$wpdb->insert( $table_name, array(
						'time'              => current_time( 'mysql' ),
						'documenturi'       => $documenturi,
						//Violateddirective and blockeduri are already sanitized earlier in this function
						'violateddirective' => $violateddirective,
						'blockeduri'        => $blockeduri,
						'status'            => 1, //default inserted.
					) );
				}
			}
		} else {
			//more than x requests. Pause the CSP reporting
			update_site_option( 'rsssl_csp_reporting_temp_paused', true );
		}

		// Prevent concurrent firewall/header regenerations, but don't drop CSP reports.
		if ( get_site_transient( "rsssl_csp_request_running" ) ) {
			return;
		}
		set_site_transient( 'rsssl_csp_request_running', true, 5 * MINUTE_IN_SECONDS );

		if ( !class_exists('rsssl_firewall_manager') ) {
			require_once( rsssl_path.'security/' . 'firewall-manager.php' );
			$htAccessFileManager = RSSSL_Htaccess_File_Manager::get_instance();
			$firewall_manager = new rsssl_firewall_manager($htAccessFileManager);
			$firewall_manager->update_advanced_headers();
		} else {
			rsssl_request_advanced_headers_rebuild();
		}
		delete_site_transient("rsssl_csp_request_running");
	}
}

/**
 * @param string $str
 * @return string
 *
 * @Since 2.5
 *
 * Only allow known directives to be returned, otherwise return empty string
 *
 */
if ( !function_exists('rsssl_sanitize_csp_violated_directive')) {
	function rsssl_sanitize_csp_violated_directive( $str ) {
		// Validate input type and length
		if ( !is_string($str) ) {
			return '';
		}

		//Style-src-elem and script-src-elem are implemented behind a browser flag. Therefore, save as style-src and script-src since these are used as a fallback
		if ( $str === 'style-src-elem' ) {
			//$str = str_replace('style-src-elem', 'style-src', $str);
		}

		if ( $str === 'script-src-elem' ) {
			//$str = str_replace('script-src-elem', 'script-src', $str);
		}

		//https://www.w3.org/TR/CSP3/#directives-fetch
		$directives = array(
			//Fetch directives
			'child-src',
			'connect-src',
			'default-src',
			'font-src',
			'frame-src',
			'img-src',
			'manifest-src',
			'media-src',
			'object-src',
			'script-src',
			'script-src-elem',
			'script-src-attr',
			'style-src',
			'style-src-elem',
			'style-src-attr',
			'worker-src',
			//Document directives
			'base-uri',
			'plugin-types',
			'sandbox',
			'form-action',
			'frame-ancestors',
			'navigate-to',
		);

		if ( in_array( $str, $directives, true ) ) {
			return $str;
		}

		//not found? check if it's part of the string
		foreach ( $directives as $directive ) {
			if ( strpos( $directive, $str ) !== false ) {
				return $directive;
			}
		}

		return '';
	}
}

/**
 * Validate a hostname for CSP usage
 *
 * @param string $host
 * @return string|false
 *
 */
if ( !function_exists('rsssl_validate_host')) {
	function rsssl_validate_host( $host ) {
		// Validate as domain
		$validated = filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
		if ( $validated !== false ) {
			return $validated;
		}

		// Try IP validation
		$validated = filter_var($host, FILTER_VALIDATE_IP);
		if ( $validated !== false ) {
			return $validated;
		}

		return false;
	}
}

/**
 * URI can be a domain or a value (e.g. data:). If it's a domain, return the main domain (https://example.com).
 * Otherwise return one of the other known uri value.
 *
 * @param string $blockeduri
 * @return string
 *
 * @since 2.5
 *
 */

if ( !function_exists('rsssl_sanitize_uri_value')) {
	/**
	 * @param string $blocked_uri
	 *
	 * @return string
	 */
	function rsssl_sanitize_uri_value( string $blocked_uri): string {
        $cacheGroup = 'csp_endpoint_public';
        $cacheName = 'rsssl_sanitize_uri_value:' . md5($blocked_uri);
        if ($cache = wp_cache_get($cacheName, $cacheGroup)) {
            return $cache;
        }

		// Remove control characters and trim
		$blocked_uri = filter_var($blocked_uri, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
		$blocked_uri = trim($blocked_uri);

		// Add a length limit
		if ( strlen( $blocked_uri ) > 2000 ) {
			wp_cache_set($cacheName, '', $cacheGroup);
			return '';
		}

		//Check if uri starts with http(s)
		if ( strpos( $blocked_uri, 'http' ) === 0 ) {
			// Use filter_var for URL validation
			$filtered = filter_var($blocked_uri, FILTER_VALIDATE_URL);
			if ( $filtered === false ) {
				wp_cache_set($cacheName, '', $cacheGroup);
				return '';
			}

			$url = parse_url( $filtered );
			if ( ( isset( $url['scheme'] ) ) && isset( $url['host'] ) ) {
				// Validate host
				$host = rsssl_validate_host($url['host']);
				if ( $host === false ) {
					wp_cache_set($cacheName, '', $cacheGroup);
					return '';
				}

				$uri = esc_url_raw( $url['scheme'] . "://" . $host );
			} else {
				$uri = '';
			}
            $result = $uri;
			//allow for wss:// and ws:// websocket scheme
		} else if ( strpos( $blocked_uri, 'ws' ) === 0 ) {
			$url = parse_url($blocked_uri);
			if ( (isset($url['scheme'])) && isset($url['host']) ) {
				// Validate host
				$host = rsssl_validate_host($url['host']);
				if ( $host === false ) {
					wp_cache_set($cacheName, '', $cacheGroup);
					return '';
				}

				$uri = esc_url_raw( $url['scheme'] . "://" . $host, ['ws', 'wss'] );
			} else {
				$uri = '';
			}
			$result = $uri;
		} else {

			// Data: needs an : which isn't included automatically
			if ( $blocked_uri === 'data' ) {
				$blocked_uri = str_replace( 'data', 'data:', $blocked_uri );
			}

			// Same for blob
			if ( $blocked_uri === 'blob' ) {
				$blocked_uri = str_replace( 'blob', 'blob:', $blocked_uri );
			}

			// Inline should be unsafe-inline
			if ( $blocked_uri === 'inline' ) {
				$blocked_uri = str_replace( 'inline', 'unsafe-inline', $blocked_uri );
			}

			// Eval should be unsafe - eval
			if ( $blocked_uri === 'eval' ) {
				$blocked_uri = str_replace( 'eval', 'unsafe-eval', $blocked_uri );
			}

			if ( $blocked_uri === 'unsafe-inline' ) {
				$blocked_uri = str_replace( 'unsafe-inline', "'unsafe-inline'", $blocked_uri );
			}

			if ( $blocked_uri === 'unsafe-eval' ) {
				$blocked_uri = str_replace( 'unsafe-eval', "'unsafe-eval'", $blocked_uri );
			}

			$directives = array(
				"self",
				'data:',
				'blob:',
				'filesystem:',
				"'unsafe-inline'",
				"'unsafe-eval'",
				"about",
			);

			if ( in_array( $blocked_uri, $directives, true ) ) {
                $result = $blocked_uri;
			} else {
                $result = '';
            }
		}

        wp_cache_set($cacheName, $result, $cacheGroup);
        return $result;
	}
}
