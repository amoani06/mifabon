<?php
/**
 * The 'Rsssl_Login_Success_Event' class is a part of the 'Really Simple Security pro' plugin,
 * which is developed by the company 'Really Simple Plugins'.
 * This class is responsible for handling the login success event.
 *
 * @package     RSSSL\Pro\Security\WordPress\Eventlog\Events
 */

namespace RSSSL\Pro\Security\WordPress\Eventlog\Events;

use RSSSL\Pro\Security\WordPress\Eventlog\Rsssl_Event_Log_Handler;
use RSSSL\Pro\Security\WordPress\Limitlogin\Rsssl_Geo_Location;

/**
 * Class Rsssl_Login_Success_Event
 * Handles a login success event.
 *
 * @package     RSSSL\Pro\Security\Wordpress\Eventlog\Events
 */
class Rsssl_Login_Success_Event extends Rsssl_Event_Log_Handler {
	/**
	 * Class constructor.
	 *
	 * Initializes the object with a value of 1000.
	 */
	public function __construct() {
		parent::__construct( 1000 );
	}

	/**
	 * Handles the event
	 *
	 * @param array $data Optional data for the event
	 *
	 * @return void
	 */
	public static function handle_event( array $data = array() ): void {
		$_self = new self();
		$event = $_self->get_event( $_self->event_code );

		$user_login          = $data['user_login'] ?? null;
		$event['user_login'] = $user_login;
		// Get the ip address from the data.
		$ip_address          = $data['ip_address'] ?? null;
		$country             = Rsssl_Geo_Location::get_county_by_ip( $ip_address );
		$event_data          = array(
			'iso2_code'    => $country,
			'country_name' => Rsssl_Geo_Location::get_country_by_iso2( $country ),
		);

		// we log the event with the data.
		$_self->log_event( $event, $event_data );
	}

	/**
	 * Sanitizes the given data array.
	 *
	 * @param array $data The data to be sanitized.
	 *
	 * @return array The sanitized data.
	 */
	protected function sanitize( array $data ): array {
		// based on the value if the data is a string we sanitize it.
		foreach ( $data as $key => $value ) {
			if ( is_string( $value ) ) {
				$data[ $key ] = sanitize_text_field( $value );
			}
			if ( isset( $data['ip_address'] ) ) {
				$data['ip_address'] = filter_var( $data['ip_address'], FILTER_VALIDATE_IP );
			}
		}
		// Now here you can add more sanitization for the data for custom values.

		// Return the sanitized data.
		return $data;
	}

}
