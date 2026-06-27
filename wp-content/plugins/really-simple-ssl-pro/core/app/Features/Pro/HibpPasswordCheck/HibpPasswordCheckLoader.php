<?php

declare(strict_types=1);

namespace ReallySimplePlugins\RSS\Core\Features\Pro\HibpPasswordCheck;

use ReallySimplePlugins\RSS\Core\Features\AbstractLoader;

class HibpPasswordCheckLoader extends AbstractLoader
{
    /**
     * @inheritDoc
     */
    public function isEnabled(): bool
    {
        return (bool) rsssl_get_option('enable_hibp_check');
    }

    /**
     * Always returns true because password security hooks must be registered
     * on every request. WordPress fires user_register, password_reset, and
     * profile_update hooks on both frontend and admin contexts. Restricting
     * scope to admin only would leave frontend password changes unchecked.
     */
    public function inScope(): bool
    {
        return true;
    }
}
