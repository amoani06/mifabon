<?php
function rsssl_disable_fields_pro( $fields )
{
    /**
     * If a feature is already enabled, but not by RSSSL, we can simply check for that feature, and if the option in RSSSL is active.
     * We set is as true, but disabled. Because our React interface only updates changed option, and this option never changes, this won't get set to true in the database.
     */

    $third_party_headers = RSSSL()->headers->get_detected_security_headers('thirdparty');
    $header_ids = array_column($third_party_headers, 'option_name');

    // Create lookup map: field_id => array index (handles non-sequential keys correctly)
    $field_id_map = array_combine(array_column($fields, 'id'), array_keys($fields));
    foreach ($fields as $index => $field) {
        $field_id = $field['id'];

        if (in_array($field_id, $header_ids, true)) {
            foreach ($third_party_headers as $header => $data) {
                $detected_option = $data['option_name'];
                if ($field_id !== $detected_option) {
                    continue;
                }
                #disable this option, it's already enabled.
                $fields[$index]['disabled'] = true;
                if ($detected_option === 'csp_frame_ancestors') {
                    if (isset($field_id_map['csp_frame_ancestors_urls'])) {
                        $fields[$field_id_map['csp_frame_ancestors_urls']]['disabled'] = true;
                    }
                }

                #now try to set the value
                if ($field['type'] === 'checkbox') {
                    $fields[$index]['value'] = true;
                }

                if ($detected_option === 'content_security_policy') {
                    if (isset($field_id_map['csp_status'])) {
                        $fields[$field_id_map['csp_status']]['value'] = 'enforced-by-thirdparty';
                    }
                }

                if ($field['type'] === 'permissionspolicy') {
                    if (isset($field_id_map['enable_permissions_policy'])) {
                        $fields[$field_id_map['enable_permissions_policy']]['value'] = true;
                    }
                    $value = $data['value'];
                    $defaults = $field['default'];
                    $possible_values = ['*' => '(*)', '()' => '()', 'self' => '(self)'];
                    $override_value = $defaults;
                    foreach ($defaults as $default_key => $default_item) {
                        $type = $default_item['id'];
                        #set default to allow, in case not set
                        $override_value[$default_key]['value'] = '*';
                        foreach ($possible_values as $setting_value => $detect_value) {
                            $type_value = $type . '=' . $detect_value;
                            if (stripos($value, $type_value) !== false) {
                                $override_value[$default_key]['value'] = $setting_value;
                                $override_value[$default_key]['status'] = true;
                            }
                        }
                    }
                    $fields[$index]['value'] = $override_value;
                }

                if ($field['type'] === 'select') {
                    if (isset($field_id_map[$detected_option])) {
                        $select_field_index = $field_id_map[$detected_option];
                        if (isset($fields[$select_field_index]['options'])) {
                            $found_option = false;
                            foreach ($fields[$select_field_index]['options'] as $key => $label) {
                                //strip comment from the label
                                $label = trim(preg_replace('/\(.*?\)/', '', $label));
                                if (strtolower($label) === strtolower($data['value']) || strtolower($key) === strtolower($data['value'])) {
                                    $fields[$index]['value'] = $key;
                                    $found_option = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

	    // Disable change_login_url + change_login_url_failure_url fields when wp-login.php is not available, and the option has not been set. We can then assume it's done by a different plugin
	    if ($field['id'] === 'change_login_url'
	    && !test_rsssl_wp_login_available()
	    && empty(rsssl_get_option('change_login_url'))
	    ) {
		    $fields[$index]['value'] = __("Login URL already changed by something else than Really Simple Security", "really-simple-ssl");
		    $fields[$index]['disabled'] = true;
	    }

	    if ($field['id'] === 'change_login_url_failure_url'
	        && !test_rsssl_wp_login_available()
	        && empty(rsssl_get_option('change_login_url'))) {
		    $fields[$index]['value'] = __("Login URL already changed by something else than Really Simple Security", "really-simple-ssl");
		    $fields[$index]['disabled'] = true;
	    }

	    # Disable X-Frame-Options if frame ancestors is 'self'
	    if ( $field['id'] === 'x_frame_options' ) {

		    $frame_ancestors_value = rsssl_get_option( 'csp_frame_ancestors' );
		    $frame_ancestors_urls_value = rsssl_get_option( 'csp_frame_ancestors_urls' );

			# Always disable because it's controlled by frame-ancestors
		    $fields[ $index ]['disabled'] = true;

		    # Do not set X-Frame-Options when Frame Ancestor URLs are specified
		    if ( empty( $frame_ancestors_urls_value ) ) {
				switch ( $frame_ancestors_value ) {
					case 'disabled':
						# frame-ancestors → off - x-frame-options → off
						$fields[ $index ]['value'] = 'disabled';
						break;
					case 'none':
						# frame-ancestors → none - x-frame-options → DENY
						$fields[ $index ]['value'] = 'DENY';
						break;
					case 'self':
						# frame-ancestors → self - x-frame-options → SAMEORIGIN
						$fields[ $index ]['value'] = 'SAMEORIGIN';
						break;
					default:
						# frame-ancestors → self + url - x-frame-options → off
						$fields[ $index ]['disabled'] = true;
						$fields[ $index ]['value'] = 'disabled';
						break;
				}
			} else {
				$fields[ $index ]['value'] = 'disabled';
			}

		    add_filter( 'rsssl_option_x_frame_options', function( $value, $name ) use ( $fields, $index ) {
			    return override_x_frame_options( $value, $name, $fields, $index );
		    }, 10, 2 );
		}

		# Disable custom login URL option when using plain permalinks
	    if ( $field['id'] === 'change_login_url_enabled' ) {
		    if ( rsssl_plain_permalinks_enabled() ) {
			    $fields[ $index ]['disabled'] = true;
		    }
	    }


    }

	if ( get_option('rsssl_csp_max_size_exceeded') ) {
		//find csp_status, and set it to disabled
		if (isset($field_id_map['csp_status'])) {
			$fields[$field_id_map['csp_status']]['value'] = 'error';
		}
	}

	return $fields;

}

add_filter('rsssl_fields_values', 'rsssl_disable_fields_pro', 99, 1);

function override_x_frame_options( $value, $name, $fields, $x_frame_options_index ) {
	if ( $name === 'x_frame_options' ) {
		// Set the value from $fields
		$value = $fields[ $x_frame_options_index ]['value'];
	}
	return $value;
}