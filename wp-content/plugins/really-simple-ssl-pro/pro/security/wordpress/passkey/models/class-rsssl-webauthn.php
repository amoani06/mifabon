<?php
/** @noinspection TransitiveDependenciesUsageInspection */
namespace RSSSL\Pro\Security\WordPress\Passkey\Models;

require_once rsssl_path . 'pro/lib/webauthn/bootstrap.php';

use RSSProVendor\Base64Url\Base64Url;
use RSSProVendor\Webauthn\PublicKeyCredentialSource;
use stdClass;

class Rsssl_Webauthn
{
    private string $table_name;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->base_prefix . 'rsssl_webauthn_credentials';
        add_action('rsssl_install_tables', [self::class, 'maybe_install_table']);
    }

    /**
     * Install the table if it doesn't exist
     */
    public static function maybe_install_table(): void {
		$instance = new self();
        if (!$instance->table_exists()) {
            $instance->create_table();
        }
    }

    /**
     * Check if the table exists
     * @return bool
     */
    private function table_exists(): bool {
        global $wpdb;
        $table = $wpdb->get_var(
			$wpdb->prepare('SHOW TABLES LIKE %s', $this->table_name)
		);
        return $table === $this->table_name;
    }

    /**
     * Create the table for storing credentials.
     */
    public function create_table(): void {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE $this->table_name (
           `id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            `publicKeyCredentialId` VARCHAR(255) NOT NULL,
            `type` VARCHAR(50) NOT NULL,
            `transports` TEXT NOT NULL,
            `attestationType` VARCHAR(100) NOT NULL,
            `trustPath` TEXT NOT NULL,
            `aaguid` VARCHAR(50) NOT NULL,
            `credentialPublicKey` TEXT NOT NULL,
            `userHandle` VARCHAR(255) NOT NULL,
            `counter` INT NOT NULL,
            `otherUI` TEXT DEFAULT NULL,
            `user_id` INT NOT NULL,
            `unique_identifier` VARCHAR(255) NOT NULL,
            `authDeviceId` VARCHAR(255) NOT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`)
        ) $charset_collate;";
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        $result = dbDelta($sql);
    }

	/**
	 * Save a PublicKeyCredentialSource instance to the database.
	 *
	 * @param PublicKeyCredentialSource $source
	 * @param int $user_id
	 * @param string $authDeviceId
	 *
	 * @return int The ID of the inserted row, or false on failure.
	 */
    public function save(PublicKeyCredentialSource $source, int $user_id, string $authDeviceId = 'unknown'): int
    {
        global $wpdb;
        $data = [
            'publicKeyCredentialId' => Base64Url::encode($source->getPublicKeyCredentialId()),
            'type' => $source->getType(),
            'transports' => maybe_serialize($source->getTransports()),
            'attestationType' => $source->getAttestationType(),
            'trustPath' => maybe_serialize($source->getTrustPath()->jsonSerialize()),
            'aaguid' => $source->getAaguid()->toString(),
            'credentialPublicKey' => Base64Url::encode($source->getCredentialPublicKey()),
            'userHandle' => Base64Url::encode($source->getUserHandle()),
            'counter' => $source->getCounter(),
            'otherUI' => maybe_serialize($source->getOtherUI()),
            'user_id' => $user_id,
            'authDeviceId' => $authDeviceId,
        ];

        // First we search if the credential already exists if so we update it
	    if( $this->credential_id_exists($data['publicKeyCredentialId']) ) {
            return $this->update( $user_id, $source);
        }

        $result = $wpdb->insert(
            $this->table_name,
            $data,
            [
                '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' , '%d'
            ]
        );

        return $result ? $wpdb->insert_id : 0;
    }

    /**
     * Update a PublicKeyCredentialSource instance in the database.
     *
     * @param int $id
     * @param PublicKeyCredentialSource $source
     * @return bool True on success, false on failure.
     */
    public function update(int $id, PublicKeyCredentialSource $source): bool
    {
        global $wpdb;

        $data = [
            'publicKeyCredentialId' => Base64Url::encode($source->getPublicKeyCredentialId()),
            'type' => $source->getType(),
            'transports' => maybe_serialize($source->getTransports()),
            'attestationType' => $source->getAttestationType(),
            'trustPath' => maybe_serialize($source->getTrustPath()->jsonSerialize()),
            'aaguid' => $source->getAaguid()->toString(),
            'credentialPublicKey' => Base64Url::encode($source->getCredentialPublicKey()),
            'userHandle' => Base64Url::encode($source->getUserHandle()),
            'counter' => $source->getCounter(),
            'otherUI' => maybe_serialize($source->getOtherUI()),
        ];

        $result = $wpdb->update(
            $this->table_name,
            $data,
            ['id' => $id],
            [
                '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s'
            ],
            ['%d']
        );

        return $result !== false;
    }


	/**
	 * Retrieve a PublicKeyCredentialSource instance from the database by ID.
	 *
	 * @param string $key
	 *
	 * @return PublicKeyCredentialSource|null The PublicKeyCredentialSource object or null if not found.
	 */
    public function findByKey(string $key): ?PublicKeyCredentialSource
    {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM $this->table_name WHERE publicKeyCredentialId = %s", $key),
            ARRAY_A
        );

        if (empty($row)) {
            return null;
        }
        return $this->mapRowToEntity($row);
    }

    /**
     * Delete a PublicKeyCredentialSource from the database by ID.
     *
     * @param int $id
     * @return bool True on success, false on failure.
     */
    public function delete(int $id): bool
    {
        global $wpdb;

        return (bool) $wpdb->delete( $this->table_name, [ 'id' => $id], ['%d']);
    }

    /**
     * Map a database row to a PublicKeyCredentialSource entity.
     *
     * @param array $row
     * @return PublicKeyCredentialSource
     */
    protected function mapRowToEntity(array $row): PublicKeyCredentialSource
    {
		$trustPath = $this->normalize_trust_path(
			$this->safe_unserialize($row['trustPath'])
		);

        return PublicKeyCredentialSource::createFromArray([
            'publicKeyCredentialId' => $row['publicKeyCredentialId'],
            'type' => $row['type'],
            'transports' => $this->safe_unserialize($row['transports']),
            'attestationType' => $row['attestationType'],
            'trustPath' => $trustPath,
            'aaguid' => $row['aaguid'],
            'credentialPublicKey' => $row['credentialPublicKey'],
            'userHandle' => $row['userHandle'],
            'counter' => (int)$row['counter'],
            'otherUI' => $this->safe_unserialize($row['otherUI']),
        ]);
    }

	/**
	 * Prefix legacy WebAuthn trust path class names stored before the library was scoped.
	 *
	 * @param mixed $trustPath
	 * @return mixed
	 */
	private function normalize_trust_path($trustPath) {
		if (
			! is_array($trustPath) ||
			! isset($trustPath['type']) ||
			! is_string($trustPath['type'])
		) {
			return $trustPath;
		}

		$type = ltrim($trustPath['type'], '\\');
		if ( strpos($type, 'Webauthn\\TrustPath\\') === 0 ) {
			$trustPath['type'] = 'RSSProVendor\\' . $type;
		}

		return $trustPath;
	}

	/**
	 * Migrate stored WebAuthn trust path class names to the prefixed namespace.
	 *
	 * @return void
	 */
	public function migrate_legacy_trust_path_types(): void {
		global $wpdb;

		if ( ! $this->table_exists() ) {
			return;
		}

		foreach ( (array) $wpdb->get_results(
			$wpdb->prepare('SELECT id, trustPath FROM %i', $this->table_name),
			ARRAY_A
		) as $row ) {
			$trustPath = $this->safe_unserialize($row['trustPath']);
			$normalizedTrustPath = $this->normalize_trust_path($trustPath);

			if ( $normalizedTrustPath === $trustPath ) {
				continue;
			}

			$wpdb->update(
				$this->table_name,
				['trustPath' => maybe_serialize($normalizedTrustPath)],
				['id' => (int) $row['id']],
				['%s'],
				['%d']
			);
		}
	}

    /**
     * Safely unserialize data with restricted classes to prevent PHP object injection.
     *
     * @param mixed $data The data to unserialize
     * @return mixed The unserialized data or original data if not serialized
     */
    private function safe_unserialize($data) {
        if (!is_string($data) || !is_serialized($data)) {
            return $data;
        }
        
        // Only allow basic PHP types, no object instantiation
        return unserialize($data, ['allowed_classes' => false]);
    }

    /**
     * Retrieve the PublicKeyCredentialSource objects by credential ID.
     *
     * @param string $publicKeyCredentialId - The credential ID for which the PublicKeyCredentialSource objects should be retrieved.
     * @return PublicKeyCredentialSource|null - An array of PublicKeyCredentialSource objects.
     */
    public function get_by_credential_id(string $publicKeyCredentialId):?PublicKeyCredentialSource
    {
        global $wpdb;
        // Prepare and execute the query
        $encodedCredentialId = Base64Url::encode($publicKeyCredentialId);
        $result = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM $this->table_name WHERE publicKeyCredentialId = %s", $encodedCredentialId),
            ARRAY_A
        );

        if ($result === null) {
            // handle the case when no result returned
            return null;
        }
        // Map the result to PublicKeyCredentialSource object
        return $this->mapRowToEntity($result);
    }

    /**
     * Retrieve all credentials for a user.
     *
     * @param int $user_id
     * @return array|object|null
     */
    public function get_by_user_id(int $user_id) {
        global $wpdb;

        $query = $wpdb->prepare(
            "SELECT * FROM $this->table_name WHERE user_id = %d",
            $user_id
        );

        $result = $wpdb->get_results($query);

        if($result === null) {
            // get operation failed, print the SQL error
            error_log("Failed to get record by user id. SQL Error: " . $wpdb->last_error);
        }

        foreach ($result as $key => $value) {
            $result[$key] = $this->mapRowToEntity((array) $value);
        }


        return $result;
    }

    public function get_list_user_id(int $user_id) {
        global $wpdb;

        $query = $wpdb->prepare(
            "SELECT id, authDeviceId, created_at, updated_at FROM $this->table_name WHERE user_id = %d",
            $user_id
        );

        $result = $wpdb->get_results($query);
        if($result === null) {
            // get operation failed, print the SQL error
            error_log("Failed to get record by user id. SQL Error: " . $wpdb->last_error);
        }

        return $result;
    }

	/**
	 * Checks if a credential with the given public key credential ID exists.
	 *
	 * @param string $publicKeyCredentialId
	 *
	 * @return bool True if the credential ID exists, false otherwise.
	 */
	private function credential_id_exists($publicKeyCredentialId): bool
	{
		global $wpdb;

		$result = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $this->table_name WHERE publicKeyCredentialId = %s",
				$publicKeyCredentialId
			)
		);

		return (int) $result > 0;
	}

	/**
	 * Delete all data for a specific user ID.
	 * @param int $user_id
	 *
	 * @return bool
	 */
	public function delete_data_by_user_id(int $user_id): bool
	{
		global $wpdb;
		return (bool) $wpdb->delete( $this->table_name , [ 'user_id' => $user_id], ['%d']);
	}

	/**
	 * Update the login data for a specific user.
	 *
	 * @param string $getPublicKeyCredentialId
	 * @param array $array
	 *
	 * @return bool
	 */
    public function update_login(string $getPublicKeyCredentialId, array $array): bool {
        global $wpdb;
        $credential_id = Base64Url::encode($getPublicKeyCredentialId);
        //only update updated_at and look up by credential_id
        $result = $wpdb->update(
            $this->table_name,
            $array,
            ['publicKeyCredentialId' => $credential_id],
            [
                '%s', '%s'
            ],
            ['%s']
        );

        return $result !== false;
    }

}
