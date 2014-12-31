<?php

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
    die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

if(!defined("PLUGINLIBRARY"))
{
    define("PLUGINLIBRARY", MYBB_ROOT."inc/plugins/pluginlibrary.php");
}

if(!class_exists('Crypto'))
{
	require_once(MYBB_ROOT.'inc/3rdparty/crypto/Crypto.php');
}

function encryptcookie_info()
{
    return array(
        "name"          => "Encrypt Cookie",
        "description"   => "",
        "website"       => "http://my-bb.ir",
        "author"        => "AliReza Tofighi",
        "authorsite"    => "http://my-bb.ir",
        "codename"       => "encryptcookie",
        "compatibility" => "18*"
        );
}

function encryptcookie_is_installed()
{
    global $db;

    return $db->table_exists('cookies');
}

function encryptcookie_install()
{
    if(!file_exists(PLUGINLIBRARY))
    {
        flash_message("The selected plugin could not be installed because <a href=\"http://mods.mybb.com/view/pluginlibrary\">PluginLibrary</a> is missing.", "error");
        admin_redirect("index.php?module=config-plugins");
    }

    global $PL;
    $PL or require_once PLUGINLIBRARY;

    if($PL->version < 11)
    {
        flash_message("The selected plugin could not be installed because <a href=\"http://mods.mybb.com/view/pluginlibrary\">PluginLibrary</a> is too old.", "error");
        admin_redirect("index.php?module=config-plugins");
    }

	global $config, $db;
	if(!is_writable(MYBB_ROOT."inc/config.php"))
	{
        flash_message("We need make changes in <em>config.php</em> but it isn't writable.", "error");
        admin_redirect("index.php?module=config-plugins");	
	}


	// Create the table
	$collation = $db->build_create_table_collation();
	if(!$db->table_exists('cookies'))
	{
		if($db->type == 'pgsql')
		{
			$db->write_query("CREATE TABLE `".TABLE_PREFIX."cookies` (
					`cid` serial,
					`useragent` varchar(200) NOT NULL default '',
					`ips` text NOT NULL,
					`data` text NOT NULL,
					`lastupdate` int NOT NULL default '0',
					PRIMARY KEY (`cid`)
				){$collation}");
		}
		else
		{
			$db->write_query("CREATE TABLE `".TABLE_PREFIX."cookies` (
					`cid` int(10) UNSIGNED NOT NULL auto_increment,
					`randomcode` varchar(200) NOT NULL,
					`useragent` varchar(200) NOT NULL default '',
					`ips` text NOT NULL,
					`data` text NOT NULL,
					`lastupdate` int unsigned NOT NULL default '0',
					PRIMARY KEY (`cid`)
				){$collation}");
		}
	}

	// Make changes in config.php
	if(!isset($config['crypto_key']))
	{
		$key = (Crypto::CreateNewRandomKey());

		global $config;

		if (!isset($config)) {
			require MYBB_ROOT . '/inc/config.php';
		}

		$config = array_merge($config, ['crypto_key' => $key, 'secure_cookies' => 'mybbuser,sid,adminsid']);

		$contents = var_export($config, true);
		$contents = <<<CONFIGPHP
<?php
\$config = {$contents};
CONFIGPHP;

		if (!@file_put_contents(MYBB_ROOT . '/inc/config.php', $contents)) {
			// Show an error I guess...
			flash_message("Please change <em>inc/config.php</em> file to this code: <pre>".nl2br(htmlspecialchars($contents)).'</pre>', "error");
		}

	}

}

function encryptcookie_uninstall()
{
    global $PL, $db;
    $PL or require_once PLUGINLIBRARY;

	$db->drop_table('cookies');

	global $config;

	if (!isset($config)) {
		require MYBB_ROOT . '/inc/config.php';
	}

	unset($config['crypto_key'], $config['secure_cookies']);

	$contents = var_export($config, true);
	$contents = <<<CONFIGPHP
<?php
\$config = {$contents};
CONFIGPHP;

	if (!@file_put_contents(MYBB_ROOT . '/inc/config.php', $contents)) {
		// Show an error I guess...
		flash_message("Please change <em>inc/config.php</em> file to this code: <pre>".nl2br(htmlspecialchars($contents)).'</pre>', "error");
	}
}

function encryptcookie_activate()
{
    global $PL, $mybb;
    $PL or require_once PLUGINLIBRARY;

	$PL->edit_core('encryptcookie', 'inc/functions.php',
		array(
			'search' => 'header($cookie, false);',
			'replace' => 'encryptcookie($name, $value, $expires, $httponly, $cookie);'
		), true);
		

}

function encryptcookie_deactivate()
{
    global $PL;
    $PL or require_once PLUGINLIBRARY;
	$PL->edit_core('encryptcookie', 'inc/functions.php',
		array(), true);
}

function encryptcookie($name, $value, $expires, $httponly, $cookie)
{
	global $mybb, $db, $config, $EncryptCookie;
	if (!isset($config)) {
		require MYBB_ROOT . '/inc/config.php';
	}
	$cookies = explode(',', $config['secure_cookies']);
	if(!in_array($name, $cookies) || !$EncryptCookie->active)
	{
		header($cookie, false);
		return NULL;
	}
	$EncryptCookie->set($name, $value, $expires);
}

function myy_setcookie($name, $value="", $expires="", $httponly=false)
{
	global $mybb;

	if(!$mybb->settings['cookiepath'])
	{
		$mybb->settings['cookiepath'] = "/";
	}

	if($expires == -1)
	{
		$expires = 0;
	}
	elseif($expires == "" || $expires == null)
	{
		$expires = TIME_NOW + (60*60*24*365); // Make the cookie expire in a years time
	}
	else
	{
		$expires = TIME_NOW + (int)$expires;
	}

	$mybb->settings['cookiepath'] = str_replace(array("\n","\r"), "", $mybb->settings['cookiepath']);
	$mybb->settings['cookiedomain'] = str_replace(array("\n","\r"), "", $mybb->settings['cookiedomain']);
	$mybb->settings['cookieprefix'] = str_replace(array("\n","\r", " "), "", $mybb->settings['cookieprefix']);

	// Versions of PHP prior to 5.2 do not support HttpOnly cookies and IE is buggy when specifying a blank domain so set the cookie manually
	$cookie = "Set-Cookie: {$mybb->settings['cookieprefix']}{$name}=".urlencode($value);

	if($expires > 0)
	{
		$cookie .= "; expires=".@gmdate('D, d-M-Y H:i:s \\G\\M\\T', $expires);
	}

	if(!empty($mybb->settings['cookiepath']))
	{
		$cookie .= "; path={$mybb->settings['cookiepath']}";
	}

	if(!empty($mybb->settings['cookiedomain']))
	{
		$cookie .= "; domain={$mybb->settings['cookiedomain']}";
	}

	if($httponly == true)
	{
		$cookie .= "; HttpOnly";
	}

	$mybb->cookies[$name] = $value;

 	header($cookie, false);
}

class EncryptCookie {
	private $data = array();
	private $row = array();
	private $old_data = array();
	
	public $active = false;
	
	private $key;
	
	public $cookiename = 'mybbcookie';
	private $randomcode = 'mybbcookie';
	
	public $cookies = array();

	public function EncryptCookie()
	{
		global $mybb, $db, $config, $cache;
		$plugins = $cache->read('plugins');
		if (!isset($config)) {
			require MYBB_ROOT . '/inc/config.php';
		}
		$this->key = $config['crypto_key'];
		$this->active = $plugins['active']['encryptcookie'] && $this->key;
		if(!$this->active)
		{
			return NULL;
		}
		
		$this->cookies = explode(',', $config['secure_cookies']);
		foreach($this->cookies as $cookie)
		{
			if(isset($mybb->cookies[$cookie]))
			{
				myy_setcookie($cookie, '', -1);
			}
		}
		if($mybb->cookies[$this->cookiename] == '')
		{
			$this->create_ec();
			return NULL;
		}

		$this->randomcode = Crypto::Decrypt(base64_decode($mybb->cookies[$this->cookiename]), $this->key);
		$config['crypto_key'] = $mybb->cookies[$this->cookiename] = '';
		$query = $db->simple_select('cookies', '*', "randomcode='".$db->escape_string($this->randomcode)."'", array('limit'=>1));
		$data = $db->fetch_array($query);
		if($data['useragent'] != md5($_SERVER['HTTP_USER_AGENT']))
		{
			$this->create_ec();
			return NULL;
		}

		$this->row = $data;

		$this->data = $this->old_data = (array)json_decode($data['data']);
		
		add_shutdown(array($this, 'set_query'));
		
		//print_r($this->data);exit;
		
		if(!in_array(md5(get_ip()), explode(',', $data['ips'])))
		{
			if(!defined('IN_ADMINCP') && THIS_SCRIPT != 'member.php' && $this->data['mybbuser'])
			{
				header('location: '.$mybb->settings['bburl'].'/member.php?action=confrim_ip');
				exit;
			}
			elseif(defined('IN_ADMINCP') || !$this->data['mybbuser'])
			{
				$this->create_ec();
				return NULL;
			}
		}
		else
		{
			foreach($this->data as $cookie)
			{
				if($cookie->admin == defined('IN_ADMINCP') && ($cookie->expires == 0 || $cookie->expires > TIME_NOW))
				{
					$mybb->cookies[$cookie->name] = Crypto::Decrypt(base64_decode($cookie->value), $this->key);
				}
			}
		}
	}
	
	public function create_ec()
	{
		if(!$this->active)
		{
			return NULL;
		}

		global $db;
		$this->randomecode = $randomecode = md5(random_str(64).md5($_SERVER['HTTP_USER_AGENT']).time().get_ip()).random_str(134);
		$this->old_data = $this->data = array();
		$db->insert_query('cookies',
			array(
				'randomcode' => $randomecode,
				'data' => $db->escape_string(json_encode($this->data, true)),
				'ips' => md5(get_ip()),
				'useragent' => md5($_SERVER['HTTP_USER_AGENT']),
				'lastupdate' => TIME_NOW
			)
		);
		my_setcookie($this->cookiename, base64_encode(Crypto::Encrypt($randomecode, $this->key)), (24*60*60*30), true);
		add_shutdown(array($this, 'set_query'));
	}

	public function set($name, $value, $expires)
	{
		if(!$this->active)
		{
			return NULL;
		}

		//echo $name.'<br>';
		if($value)
		{
			$value = base64_encode(Crypto::Encrypt($value, $this->key));
			$this->data[$name] = array(
				'admin' => defined('IN_ADMINCP'),
				'name' => $name,
				'value' => $value,
				'expires' => $expires
			);
		}
		else
		{
			unset($this->data[$name]);
		}
	}
	
	public function set_query()
	{
		if(!$this->active)
		{
			return NULL;
		}

		global $db;
		$db->update_query('cookies', array('lastupdate' => TIME_NOW, 'data' => $db->escape_string(json_encode($this->data, true))), "randomcode='".$db->escape_string($this->randomcode)."'", 1);
//		$this->old_data = $this->data;
	}
	
	public function add_ip()
	{
		global $db;
		$ips = explode(',',$this->row['ips']);
		$myip = md5(get_ip());
		if(!in_array($myip, $ips))
		{
			$ips[] = $myip;
		}
		$db->update_query('cookies', array('lastupdate' => TIME_NOW, 'ips' => $db->escape_string(implode(',',$ips))), "randomcode='".$db->escape_string($this->randomcode)."'", 1);
	}
}

global $EncryptCookie, $mybb;
$EncryptCookie = new EncryptCookie();

$plugins->add_hook("datahandler_login_complete_start", "encryptcookie_login");

function encryptcookie_login(&$login){
	global $EncryptCookie;
	$EncryptCookie->add_ip();
}

$plugins->add_hook("global_end", "encryptcookie_forcelogin");

function encryptcookie_forcelogin()
{
	global $mybb, $lang, $EncryptCookie;
	if($mybb->get_input('action') == 'confrim_ip' && THIS_SCRIPT == 'member.php')
	{
		$lang->load('encryptcookie');
		error($lang->confrim_ip_desc, $lang->confrim_ip);
	}
	elseif($mybb->get_input('action') == 'clearcookie')
	{
		$EncryptCookie->create_ec();
		header('location: '.$mybb->settings['bburl']);
	}
}