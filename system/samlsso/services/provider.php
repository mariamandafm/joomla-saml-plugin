<?php
\defined("_JEXEC") or die;

use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Plugin\System\Samlsso\Extension\Samlsso;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            $container->lazy(Samlsso::class, function (Container $container) {
                $plugin = new Samlsso(
                    (array) PluginHelper::getPlugin("system", "samlsso")
                );
                $plugin->setApplication(Factory::getApplication());
                return $plugin;
            })
        );
    }
};
