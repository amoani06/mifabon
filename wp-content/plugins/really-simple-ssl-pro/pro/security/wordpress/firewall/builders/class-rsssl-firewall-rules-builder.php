<?php
namespace RSSSL\Pro\Security\WordPress\Firewall\Builders;

use RSSSL\Pro\Security\WordPress\Contracts\Rsssl_Rule_Section_Builder_Interface;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_404_Detection_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Block_List_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Country_Detection_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Debug_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Geo_Database_And_Block_Page_Setting_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Ip_Fetcher_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Plugin_Validation_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_Translatable_Strings_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_User_Agent_Section_Builder;
use RSSSL\Pro\Security\WordPress\Firewall\Builders\Rules\Rsssl_White_List_Section_Builder;

class Rsssl_Firewall_Rules_Builder
{
    /** @var Rsssl_Rule_Section_Builder_Interface[] */
    private array $sectionBuilders = [];

    /**
     * Rsssl_Firewall_Rules_Builder constructor.
     */
    public function __construct()
    {
		//Default sections
		if (defined('WP_DEBUG') && WP_DEBUG) {
	    $this->withDebugSection();
        }
		$this->addSectionBuilder(new Rsssl_Ip_Fetcher_Section_Builder());
    }


	/**
	 * Include a debug section builder when debug is enabled.
	 */
	public function addSectionBuilder(Rsssl_Rule_Section_Builder_Interface $builder): self
	{
		$this->sectionBuilders[] = $builder;
		return $this;
	}

	/**
	 * Include a debug section if WP_Debug is enabled.
	 */
	public function withDebugSection():self {
		$this->addSectionBuilder(new Rsssl_Debug_Section_Builder());
		return $this;
	}

	/**
	 * Validates the plugin directory.
	 */
	public function withPluginValidationSection(): self
	{
		$this->addSectionBuilder(new Rsssl_Plugin_Validation_Section_Builder());
		return $this;
	}

	/**
	 * Adds the translatable strings section.
	 */
	public function withTranslatableStringsSection(): self
	{
		$this->addSectionBuilder(new Rsssl_Translatable_Strings_Section_Builder());
		return $this;
	}

	/**
	 * Adds the block list section.
	 */
	public function withBlockListSection(): self
	{
		$this->addSectionBuilder(new Rsssl_Block_List_Section_Builder());
		return $this;
	}

	/**
	 * Adds the whitelist section.
	 */
	public function withWhitelistSection(): self
	{
		$this->addSectionBuilder(new Rsssl_White_List_Section_Builder());
		return $this;
	}

	/**
	 * Adds the country detection file section.
	 */
	public function withCountryDetectionSection(): self
	{
		$this->addSectionBuilder(new Rsssl_Country_Detection_Section_Builder());
		return $this;
	}

	/**
	 * Adds the Geo Database and Block Page Setting section.
	 */
	public function withGeoDatabaseAndBlockPageSetting(): self
	{
		$this->addSectionBuilder(new Rsssl_Geo_Database_And_Block_Page_Setting_Section_Builder());
		return $this;
	}

	/**
	 * Adds the User Agent section.
	 */
	public function withUserAgentSection():self
	{
		$this->addSectionBuilder(new Rsssl_User_Agent_Section_Builder());
		return $this;
	}

	/**
	 * Adds the 404 detection section.
	 */
	public function with404DetectionSection(): self
	{
		$this->addSectionBuilder(new Rsssl_404_Detection_Section_Builder());
		return $this;
	}


	/**
	 * Builds the firewall rules.
	 * This method compiles all the sections added to the builder
	 * @param 'string'|'array'|'json' $output
	 * @return string|array<string> JSON
	 */
	public function build(string $output = 'string')
	{
	    $sections = [];
	    foreach ($this->sectionBuilders as $builder) {
	        $marker = $builder->getMarker();
	        $section = trim($builder->build());

	        // Always include all sections (even empty) if output is array or json
	        // This ensures that insert_with_markers() can properly clear markers
	        // when countries/regions are removed from the blocklist
	        if ($output === 'array' || $output === 'json') {
	            $sections[$marker] = $section;
	        } else {
	            // For string output, only include non-empty sections
	            if ($section !== '') {
	                $sections[$marker] = $section;
	            }
	        }
	    }

	    if ($output === 'array') {
	        return $sections;
	    }
	    if ($output === 'json') {
	        return json_encode($sections);
	    }

	    return implode(PHP_EOL . PHP_EOL, $sections);
	}
}