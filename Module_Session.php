<?php
namespace GDO\Session;

use GDO\Core\GDO_Module;

final class Module_Session extends GDO_Module
{
    public $module_priority = 9;
    
    public function isCoreModule() { return true; }
    
}
