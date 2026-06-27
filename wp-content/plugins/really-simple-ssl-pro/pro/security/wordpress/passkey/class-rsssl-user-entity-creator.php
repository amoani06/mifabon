<?php
namespace RSSSL\Pro\Security\WordPress\Passkey;

require_once rsssl_path . 'pro/lib/webauthn/bootstrap.php';

use RSSProVendor\Webauthn\MetadataService\MetadataStatement;
use RSSProVendor\Webauthn\MetadataService\MetadataStatementRepository;
use RSSProVendor\Webauthn\MetadataService\StatusReport;
use RSSProVendor\Webauthn\PublicKeyCredentialUserEntity;

class Rsssl_User_Entity_Creator implements MetadataStatementRepository
{
    public static function create($user): PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            (string) $user->ID,
            $user->user_login,
            $user->display_name
        );
    }

    /**
     * This method is required by the MetadataStatementRepository interface
     * but is not implemented in this class.
     *
     * @param string $aaguid
     * @return MetadataStatement|null
     * @throws \BadMethodCallException
     */
    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        throw new \BadMethodCallException('findOneByAAGUID is not implemented');
    }

    /**
     * This method is required by the MetadataStatementRepository interface
     * but is not implemented in this class.
     *
     * @param string $aaguid
     * @return array|StatusReport[]
     * @throws \BadMethodCallException
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        throw new \BadMethodCallException('findStatusReportsByAAGUID is not implemented');
    }
}
