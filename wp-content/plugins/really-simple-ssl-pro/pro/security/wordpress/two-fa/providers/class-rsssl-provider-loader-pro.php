<?php
namespace RSSSL\Pro\Security\WordPress\Two_Fa\Providers;

use RSSSL\Security\WordPress\Two_Fa\Providers\Rsssl_Provider_Loader;
use RSSSL\Security\WordPress\Two_Fa\Providers\Rsssl_Two_Factor_Provider_Interface;

/**
 * Class Rsssl_Provider_Loader_Pro
 * @package RSSSL\Pro\Security\WordPress\Two_Fa
 *
 * This class is responsible for loading the providers for the two-factor authentication with its pro features.
 */
class Rsssl_Provider_Loader_Pro extends Rsssl_Provider_Loader
{
	/**
	 * Get providers that are available for the two-factor authentication for pro.
	 * @return array
	 */
    public static function get_providers(): array {
        $providers = parent::get_providers();
        $directory = __DIR__ ;
	    foreach ( glob( $directory . '/*.php', GLOB_NOSORT ) as $file) {
            $base_name = str_replace('class-', '', basename($file, '.php'));
            $class_name = 'RSSSL\\Pro\\Security\\WordPress\\Two_Fa\\Providers\\' . str_replace(' ', '_', ucwords(str_replace('-', ' ', $base_name)));
            if (class_exists($class_name) && is_subclass_of($class_name, Rsssl_Two_Factor_Provider_Interface::class)) {
                preg_match('/Rsssl_Two_Factor_(.+)/', $class_name, $matches);
                $method_name = strtolower($matches[1]);
                $providers[$method_name] = $class_name;
            }
        }
        return $providers;
    }
}
