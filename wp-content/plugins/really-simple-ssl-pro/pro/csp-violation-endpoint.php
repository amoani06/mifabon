<?php defined('ABSPATH') or die();

class rsssl_csp_backend
{
    private static $_this;
    function __construct()
    {

        if (isset(self::$_this))
            wp_die(sprintf(__('%s is a singleton class and you cannot create a second instance.', 'really-simple-ssl'), get_class($this)));

        self::$_this = $this;
        //doesn't execute on prio 10
        add_action('rsssl_install_tables', array( $this, 'update_db_check'), 11 );
        //Remove report only rules on option update
        add_action( 'rsssl_after_save_field', array( $this, 'maybe_reset_csp_count' ), 30,4);

        add_filter( 'rsssl_notices', array($this,'csp_notices'), 20, 1 );
        add_filter( 'rsssl_do_action', array( $this, 'csp_table_data' ), 10, 3 );
        add_filter( 'rsssl_do_action', array( $this, 'csp_manual_addition' ), 10, 3 );
    }

    static function this()
    {
        return self::$_this;
    }

    /**
     * @param array           $response
     * @param string          $action
     * @param array $data
     *
     * @return array
     */
    public function csp_table_data( array $response, string $action, $data): array {
        if ( !rsssl_user_can_manage() ) {
            return $response;
        }
        if ($action === 'learning_mode_data' && isset($data['type']) && $data['type']==='content_security_policy_source_directives'){
            $update_item_id = $data['updateItemId'] ?? false;
            $enabled = $data['enabled'] ?? false;
            $lm_action = $data['lm_action'] ?? 'get';
            if ( !in_array($lm_action, ['get', 'update', 'delete']) ) {
                $lm_action = 'get';
            }

            if ( $lm_action === 'get') {
                return $this->get();
            }

            //in case of update or delete
            $this->update($update_item_id, $enabled, $lm_action );
            return  $this->get();
        }

        return $response;
    }

    /**
     * Catch a manually added CSP entry
     */
    public function csp_manual_addition( array $response, string $action, $data): array
    {
        if ( !rsssl_user_can_manage() || ($action !== 'rsssl_csp_uri_add') ) {
            return $response;
        }

        $violatedDirective = rsssl_sanitize_csp_violated_directive( $data['directive'] );
        if ( empty($violatedDirective) ) {
            return [
                'success' => false,
                'message' => esc_html__('Unknown directive given.', 'really-simple-ssl'),
            ];
        }

        $blockedUri = rsssl_sanitize_uri_value( $data['cspUri'] );
        if ( empty($blockedUri) || ( $this->cspUriContainsAcceptedCharacters($blockedUri) === false )) {
            return [
                'success' => false,
                'message' => esc_html__('Could not recognize given URI.', 'really-simple-ssl'),
            ];
        }

        global $wpdb;

        if ($this->cspEntryExists( $blockedUri, $violatedDirective, $wpdb )) {
            return [
                'success' => false,
                'message' => esc_html__("CSP entry already exists!", 'really-simple-ssl'),
            ];
        }

        $success = $this->addCspEntryToLog( [
            'documenturi' => esc_html__("Manual", "really-simple-ssl"),
            'violateddirective' => $violatedDirective,
            'blockeduri' => $blockedUri
        ], $wpdb );

        $successMessage = esc_html__("CSP entry added successfully!", 'really-simple-ssl');
        $errorMessage = esc_html__("CSP entry could not be added. Try again.", 'really-simple-ssl');

        return [
            'success' => $success,
            'message' => ($success ? $successMessage : $errorMessage)
        ];
    }

    /**
     * Delete the CSP track count when switching from report-paused to report-only
     * @param string $field_name
     * @param mixed $new_value
     * @param mixed $old_value
     * @param string $field_type
     * @since 4.1.1
     *
     */

    public function maybe_reset_csp_count($field_name, $new_value, $old_value, $field_type) {
        if ( !rsssl_user_can_manage()) {
            return;
        }

        if ( $field_name !== 'csp_status') {
            return;
        }

        if ( empty( $old_value) && !empty($new_value) ) {
            $this->add_csp_defaults();
        }

        if ( $old_value === 'completed' && $new_value === 'learning_mode') {
            delete_site_option('rsssl_csp_request_count');
        }
    }

    /**
     * Add default WordPress rules to CSP table.
     *
     */

    public function add_csp_defaults() {
        $rules = array(
            'script-src-data' => array(
                'violateddirective' => 'script-src',
                'blockeduri' => 'data:',
            ),
            'script-src-eval' => array(
                'violateddirective' => 'script-src',
                'blockeduri' => 'unsafe-eval',
            ),
            'img-src-gravatar' => array(
                'violateddirective' => 'img-src',
                'blockeduri' => 'https://secure.gravatar.com',
            ),
            'img-src-data' => array(
                'violateddirective' => 'img-src',
                'blockeduri' => 'data:',
            ),
            'img-src-self' => array(
                'violateddirective' => 'img-src',
                'blockeduri' => 'self',
            ),
        );

        global $wpdb;

        // add $rules to CSP table
        foreach ( $rules as $rule ) {
            $this->addCspEntryToLog( [
                // Default rules, leave documenturi empty
                'documenturi' => 'WordPress',
                'violateddirective' => $rule['violateddirective'],
                'blockeduri' => $rule['blockeduri'],
            ], $wpdb );
        }
    }

    /**
     * Some custom notices for CSP
     *
     * @param $notices
     *
     * @return mixed
     */
    public function csp_notices($notices){

        $missing_tables = get_option('rsssl_table_missing');
        if ( !empty($missing_tables) ) {
            $tables = implode(', ', $missing_tables);
            $notices['database_table_missing'] = array(
                'callback' => '_true_',
                'score' => 10,
                'output' => array(
                    '_true_' => array(
                        'msg' => __("A required database table is missing. Please check if you have permissions to add this database table.", "really-simple-ssl"). " ".$tables,
                        'icon' => 'warning',
                        'plusone' => true,
                        'dismissible' => true
                    ),
                ),
            );
        }
        if ( rsssl_get_option( 'csp_status' ) === 'learning_mode' ) {
            $activation_time = get_site_option( 'rsssl_csp_report_only_activation_time' );
            $nr_of_days_learning_mode = apply_filters( 'rsssl_pause_after_days', 7 );

            $deactivation_time = $activation_time + DAY_IN_SECONDS * $nr_of_days_learning_mode;
            $time_left = $deactivation_time - time();
            $days = round($time_left / DAY_IN_SECONDS, 0);
            //if we're in learning mode, it should not show 0 days
            if ( $days == 0 ) $days = 1;
            $notices['learning_mode_active'] = array(
                'callback' => '_true_',
                'score' => 10,
                'output' => array(
                    'true' => array(
                        'msg' => sprintf(__("Learning Mode is active for your Content Security Policy and will complete in %s days.", "really-simple-ssl"), $days),
                        'icon' => 'open',
                        'plusone' => true,
                        'dismissible' => true
                    ),
                ),
            );
        }

        if ( rsssl_get_option( 'csp_status' ) === 'completed' ) {
            ob_start();
            ?>
            <p><?php _e("Follow these steps to complete the setup:", "really-simple-ssl"); ?></p>
            <ul class="message-ul">
                <li class="rsssl-activation-notice-li"><div class="rsssl-bullet"></div><?php _e("Review the detected configuration in 'Content Security Policy'.", "really-simple-ssl"); ?></li>
                <li class="rsssl-activation-notice-li"><div class="rsssl-bullet"></div><?php _e("Click 'Enforce' to enforce the configuration on your site.", "really-simple-ssl"); ?></li>
            </ul>
            <?php
            $content = ob_get_clean();
            $notices['csp_lm_completed'] = [
                'callback' => '_true_',
                'score'    => 10,
                'output'   => [
                    'true' => [
                        'url' => 'knowledge-base/how-to-use-the-content-security-policy-generator',
                        'msg'                => $content,
                        'icon'               => 'open',
                        'dismissible'        => true,
                    ],
                ],
            ];
        }

        if (get_option('rsssl_csp_max_size_exceeded')){
            $notices['csp_max_size'] = array(
                'callback' => '_true_',
                'score' => 10,
                'output' => array(
                    'true' => array(
                        'title' => __("Content Security Policy maximum size exceeded", "really-simple-ssl"),
                        'msg' => __("Your site has exceeded the maximum size for HTTP headers. To prevent issues, the Content Security Policy won't be added to your HTTP headers.", "really-simple-ssl"),
                        'icon' => 'warning',
                        'url' => 'instructions/content-security-policy-maximum-size-exceeded',
                        'plusone' => true,
                        'dismissible' => true
                    ),
                ),
                'show_with_options' => [
                    'content_security_policy',
                ]
            );
        }

        return $notices;
    }

    /**
     * Check if db should be updated
     */
    public function update_db_check()
    {
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        global $wpdb;
        $table_name = $this->getCspLogTableName($wpdb);
        if ( !get_option('rsssl_csp_db_upgraded') ){
            if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) === $table_name ) {
                $columns = $wpdb->get_results("SHOW COLUMNS FROM $table_name LIKE 'inpolicy'");
                if (count($columns)>0) {
                    $wpdb->query("ALTER TABLE $table_name CHANGE COLUMN inpolicy status text;");
                }

                //convert string 'true' to 1.
                $wpdb->query("UPDATE $table_name set status = 1 where status = 'true'");
            }
            update_option('rsssl_csp_db_upgraded', true);
        }

        $charset_collate = $wpdb->get_charset_collate();
        $sql = /** @lang text */
            "CREATE TABLE $table_name (
          id mediumint(9) NOT NULL AUTO_INCREMENT,
          time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
          documenturi text  NOT NULL,
          violateddirective text  NOT NULL,
          blockeduri text  NOT NULL,
          status text NOT NULL,
          PRIMARY KEY  (id)
        ) $charset_collate";

        dbDelta($sql);
    }



    /**
     * Get current CSP data
     * @return array
     */
    public function get() {
        global $wpdb;
        $table_name = $this->getCspLogTableName( $wpdb );
        $data = [];
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) === $table_name ) {
            // Allow override of display limit
            $limit = defined('RSSSL_CSP_DISPLAY_LIMIT_OVERRIDE') ? (int) RSSSL_CSP_DISPLAY_LIMIT_OVERRIDE : 2000;
            $data = $wpdb->get_results("SELECT * FROM $table_name ORDER BY time DESC LIMIT $limit");
            $tables = get_option('rsssl_table_missing', []);
            if ( in_array($table_name, $tables)) {
                unset($tables[$table_name]);
                update_option('rsssl_table_missing', $tables, false);
            }
        } else {
            $tables = get_option('rsssl_table_missing', []);
            if ( !in_array($table_name, $tables)) {
                $tables[] = $table_name;
            }
            update_site_option('rsssl_csp_db_version', false);
            update_option('rsssl_table_missing', $tables, false);
        }

        return $data;
    }

    /**
     *
     * Update the 'status' database value to true after 'Add to policy' button is clicked in Content Security Policy tab
     *
     * @since 2.5
     */

    public function update($update_item_id, $enabled, $action='update')
    {
        if (!rsssl_user_can_manage()) {
            return;
        }
        global $wpdb;
        $table_name = $this->getCspLogTableName( $wpdb );
        if ( $action === 'update' ) {
            $wpdb->update($table_name, ['status' => $enabled], ['id' => $update_item_id] );
        } else {
            $wpdb->delete( $table_name, [
                'id' => $update_item_id
                ]
            );
        }
    }

    /**
     * Adds a CSP entry to the log.
     *
     * This method inserts a Content Security Policy (CSP) violation entry into
     * the database. It ensures that only predefined keys are accepted and
     * required fields are present.
     *
     * @param array $data The CSP data to log. Should include
     * 'documenturi', 'violateddirective', and 'blockeduri'.
     * @param wpdb|null $wpdb The WordPress database object. If null, the global
     * $wpdb object will be used.
     * @return bool True on success, false on failure.
     */
    protected function addCspEntryToLog(array $data, ?wpdb $wpdb = null): bool
    {
        if ( empty($wpdb) ) {
            global $wpdb;
        }

        $defaults = [
            'time' => current_time( 'mysql' ), // optional in $data
            'documenturi' => '', // required in $data
            'violateddirective' => '', // required in $data
            'blockeduri' => '', // required in $data
            'status' => 1, // optional in $data
        ];

        // Only allow array keys that were predefined
        $givenCspData = array_intersect_key( $data, array_flip( array_keys( $defaults ) ) );

        // Parse given data to allow addition of default values
        $cspEntryData = wp_parse_args( $givenCspData, $defaults );

        // If given data has missing required data, then we abort before doing
        // an insert
        if ( count( $defaults ) != count( array_filter( $cspEntryData) ) ) {
            return false;
        }

        // This is probably done prior to this method. But we do it again just
        // to be sure. The checks should be swift due to utilizing wp_cache.
        $cspEntryData['documenturi'] = sanitize_text_field($cspEntryData['documenturi']);
        $cspEntryData['violateddirective'] = rsssl_sanitize_csp_violated_directive( $cspEntryData['violateddirective'] );
        $cspEntryData['blockeduri'] = rsssl_sanitize_uri_value( $cspEntryData['blockeduri'] );

        $tableName = $this->getCspLogTableName( $wpdb );
        $success = $wpdb->insert( $tableName, $cspEntryData );

        return $success !== false;
    }

    /**
     * Check if a CSP entry exists in the database based on the uri and
     * directive. Optionally pass an WPDB instance.
     */
    protected function cspEntryExists(string $uri, string $directive, ?wpdb $wpdb = null): bool
    {
        $cacheGroup = 'csp_backend';
        $cacheName = 'csp_entry_exists_uri:' . $uri . '_directive:' . $directive;
        if ( $cache = wp_cache_get( $cacheName, $cacheGroup ) ) {
            return $cache;
        }

        if ( empty($wpdb) ) {
            global $wpdb;
        }

        $tableName = $this->getCspLogTableName( $wpdb );
        $directive = rsssl_sanitize_csp_violated_directive( $directive );
        $uri = rsssl_sanitize_uri_value( $uri );

        $result = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT count(*) FROM $tableName where blockeduri = %s AND violateddirective = %s",
                $uri,
                $directive
            )
        );

        $exists = ( $result != 0 );

        wp_cache_set( $cacheName, $exists, $cacheGroup );
        return $exists;
    }

    /**
     * Helper method to return the table name for the CSP log. Optionally pass
     * the previously fetched global $wpdb. When absent this method fetches
     * the global itself.
     */
    private function getCspLogTableName(?wpdb $wpdb = null): string
    {
        if ( empty($wpdb) ) {
            global $wpdb;
        }

        return $wpdb->base_prefix . "rsssl_csp_log";
    }

    /**
     * Validates a user-given string for the Content-Security-Policy header.
     *
     * This method ensures that the input string contains only valid characters.
     * Accepted characters are:
     * - alphanumeric characters (a-z, A-Z, 0-9)
     * - hyphens (-)
     * - colons (:)
     * - question marks (?)
     * - equal signs (=)
     * - forward slashes (/)
     * - periods (.)
     *
     * @return bool Returns true if the input is valid, false otherwise.
     */
    protected function cspUriContainsAcceptedCharacters(string $cspUri): bool
    {
        $pattern = '/^[a-zA-Z0-9\-:?\/.]*$/';
        return ( preg_match($pattern, $cspUri) === 1 );
    }
}
