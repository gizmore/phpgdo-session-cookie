<?php
namespace GDO\Session;

use GDO\Core\Application;
use GDO\User\GDO_User;
use GDO\Util\Math;
use GDO\Crypto\AES;
use GDO\Core\Website;
use GDO\DB\Database;
use GDO\Net\GDT_IP;
use GDO\Util\Random;

/**
 * AES-Cookie driven Session handler.
 * The code is a bit ugly because i mimiced the GDO interface badly.
 *
 * @author gizmore
 * @version 7.0.1
 * @since 6.10.0
 */
final class GDO_Session
{
    const DUMMY_COOKIE_CONTENT = 'GDO_like_16_byte';
    
    public static $INSTANCE;
    public static $STARTED = false;
    
    public static $COOKIE_NAME = 'GDOv7';
    private static $COOKIE_DOMAIN = 'localhost';
    private static $COOKIE_JS = true;
    private static $COOKIE_HTTPS = true;
    private static $COOKIE_SAMESITE = 'Lax';
    private static $COOKIE_SECONDS = 72600;
    
    public static function isDB() { return false; }
    
    private $lock;
    public function setLock($lock)
    {
        $this->lock = $lock;
    }
    
    public function __destruct()
    {
        if ($this->lock)
        {
            Database::instance()->unlock($this->lock);
        }
    }
    
    public function getID() : ?string
    {
        return $this->gdoVar('sess_id');
    }
    
    public static function blank()
    {
        self::$INSTANCE = new self();
        GDO_User::setCurrent(GDO_User::ghost());
        return self::$INSTANCE;
    }
    
    public function getUser()
    {
        if ($uid = $this->gdoVar('sess_user'))
        {
            if ($user = GDO_User::table()->findCached($uid))
            {
                return $user;
            }
            $this->createSession(); # somethings wrong in db!
        }
        return GDO_User::ghost();
    }
    
    public function getIP() { return $this->gdoVar('sess_ip'); }
    public function getTime() { return $this->gdoVar('sess_time'); }
    public function getData() { return $this->gdoVar('sess_data'); }
    public function getLastURL() : ?string
    {
    	return GDO_User::current()->settingVar('User', 'last_url');
    }
    
    
    public function setVar($key, $value)
    {
        if ($key === 'sess_data')
        {
            $this->cookieData = $value ? $value : [];
            $this->cookieChanged = true;
        }
        else
        {
            self::set($key, $value);
        }
    }
    
    public function gdoVar($key) : ?string
    {
        return self::get($key);
    }
    
    public function save()
    {
        return $this;
    }
    
    private array $cookieData = [];
    private bool $cookieChanged = false;
    
    /**
     * @return self
     */
    public static function instance()
    {
        if ( (!self::$INSTANCE) && (!self::$STARTED) )
        {
            self::$INSTANCE = self::start();
            self::$STARTED = true; # only one try
        }
        return self::$INSTANCE;
    }
    
    public function reset(bool $removeInput=false) : self
    {
        self::$INSTANCE = null;
        self::$STARTED = false;
        return $this;
    }
    
    public static function init($cookieName='GDOv7', $domain=null, $seconds=-1, $httpOnly=true, $https=false, $samesite='Lax')
    {
    	$tls = Application::$INSTANCE->isTLS();
        self::$COOKIE_NAME = $cookieName;
        self::$COOKIE_DOMAIN = $domain ? $domain : $_SERVER['HTTP_HOST'];
        self::$COOKIE_SECONDS = Math::clampInt($seconds, -1, 1234567);
        self::$COOKIE_JS = !$httpOnly;
        self::$COOKIE_HTTPS = $https && $tls;
		self::$COOKIE_SAMESITE = $samesite;
        if ($tls)
        {
        	$cookieName .= '_tls';
        }
    }
    
    ######################
    ### Get/Set/Remove ###
    ######################
    public static function get($key, $initial=null)
    {
        $session = self::instance();
        $data = $session ? $session->cookieData : [];
        return isset($data[$key]) ? $data[$key] : $initial;
    }
    
    public static function set($key, $value)
    {
        if ($session = self::instance())
        {
            if (@$session->cookieData[$key] !== $value)
            {
                $session->cookieChanged = true;
                $session->cookieData[$key] = $value;
            }
        }
    }
    
    public static function remove($key)
    {
        if ($session = self::instance())
        {
            if (isset($session->cookieData[$key]))
            {
                $session->cookieChanged = true;
                unset($session->cookieData[$key]);
            }
        }
    }
    
    public static function commit()
    {
        if (self::$INSTANCE)
        {
            self::$INSTANCE->setCookie();
        }
    }
    
    public static function getCookieValue()
    {
        return isset($_COOKIE[self::$COOKIE_NAME]) ? (string)$_COOKIE[self::$COOKIE_NAME] : null;
    }
    
    /**
     * Start and get user session
     * @param string $cookieval
     * @param string $cookieip
     * @return self
     */
    private static function start($cookieValue=true, $cookieIP=true)
    {
        if (Application::$INSTANCE->isCLI())
        {
            return self::createSession();
        }
        
        # Parse cookie value
        if ($cookieValue === true)
        {
            if (!isset($_COOKIE[self::$COOKIE_NAME]))
            {
                return self::createSession();
            }
            $cookieValue = (string)$_COOKIE[self::$COOKIE_NAME];
        }
        
        # Special first cookie
        if ($cookieValue === self::DUMMY_COOKIE_CONTENT)
        {
            $session = self::createSession($cookieIP);
        }
        # Try to reload
        elseif ($session = self::reloadCookie($cookieValue, $cookieIP))
        {
            if ( (!$session->ipCheck()) ||
                 (!$session->timeCheck()) )
            {
                return self::createSession();
            }
        }
        # Set special first dummy cookie
        else
        {
            return self::createSession();
        }
        
        return $session;
    }
    
    public static function reloadCookie($cookieValue)
    {
        if ($decrypted = AES::decryptIV($cookieValue, GDO_SALT))
        {
            $sess = new self();
            if ($sess->cookieData = json_decode(rtrim($decrypted, "\x00"), true))
            {
                self::$INSTANCE = $sess;
                $user = $sess->getUser();
                GDO_User::setCurrent($user);
                return $sess;
            }
            else
            {
                self::createSession();
            }
        }
        return false;
    }
    
    public function ipCheck()
    {
        if ($ip = $this->getIP())
        {
            return $ip === GDT_IP::current();
        }
        return true;
    }
    
    public function timeCheck()
    {
        if ($time = $this->getTime())
        {
            if ( ($time + GDO_SESS_TIME) < Application::$TIME)
            {
                return false;
            }
        }
        return true;
    }
    
    private function setCookie()
    {
    	$app = Application::$INSTANCE;
        if ( (!$app->isCLI()) &&
             (!$app->isInstall()) &&
        	 (!$app->isUnitTests()) &&
             ($this->cookieChanged) )
        {
			if (!setcookie(self::$COOKIE_NAME, $this->cookieContent(), [
				'expires' => Application::$TIME + self::$COOKIE_SECONDS,
				'path' => GDO_WEB_ROOT,
				'domain' => self::$COOKIE_DOMAIN,
				'samesite' => self::$COOKIE_SAMESITE,
				'secure' => self::cookieSecure(),
				'httponly' => !self::$COOKIE_JS,
			]))
			{
                Website::error('err_set_cookie');
                die('ERR');
			}
        }
    }
    
    public function cookieContent()
    {
        if (!isset($this->cookieData['sess_id']))
        {
            $id = Application::$MICROTIME . Random::mrand(1, 100);
            self::set('sess_id', $id);
        }
        $this->cookieData['sess_time'] = Application::$TIME;
        $json = json_encode($this->cookieData);
        $encrypted = AES::encryptIV($json, GDO_SALT);
        return $encrypted;
    }
    
    private static function cookieSecure()
    {
        return self::$COOKIE_HTTPS;
    }
    
    private static function createSession($bindIP=null)
    {
        $session = self::blank();
        $session->cookieChanged = true;
        $session->setCookie();
        return $session;
    }
    
}
