<?php
/* 
Plugin Name: Login IP Restrictor
Description: Allow login to specific IPs/ROLES ! ALSO, Track logins (COUNTRY+CITY) or just nofity to ADMIN.  (P.S.  OTHER MUST-HAVE PLUGINS FOR EVERYONE: http://bitly.com/MWPLUGINS  )
Version: 2.27
Author: TazoTodua
Author URI: http://www.protectpages.com/profile
Plugin URI: http://www.protectpages.com/
Donate link: http://paypal.me/tazotodua
*/	
if ( ! defined( 'ABSPATH' ) ) exit; //Exit if accessed directly

if(defined('user_IP__LRL')) return;
define('user_IP__LRL',	 $_SERVER['REMOTE_ADDR']);			
		
		
class Login_Restrictor_and_Logs {
	protected $this_version	=2.27;
	public $NameOfSite;
	public $NameOfNewtork;
	protected $whois_site;
	public $AIPS_filename;
	public $AIPS_folder;
	public $plugin_pageslug;
	public $final_adminurl;
	public $Enable_for_subsites;
	public $logs_table_namee;
	protected $my_options_name;
	protected $my_options_array;
	protected $admin_mail;
	protected $txt_separatorrr;
	protected $default_iptext;
	//protected $ips_BACKUPname;
	protected $user_cookiename;
	protected $default_roles;
	protected $unknown_ip_disabled_message;

	public function __construct()	{
		$this->AIPS_folder		=ABSPATH.'wp-content/ALLOWED_IP/';
		$this->whois_site		='http://www.whois.com/whois/';
		$this->Enable_for_subsites=get_site_option('LRL_enable_subsites', false) || !is_multisite();
		$this->unknown_ip_disabled_message=(!empty($GLOBALS['message_to_unknown_ips__LRL']) ? $GLOBALS['message_to_unknown_ips__LRL'] : 'Login is disabled for unknown visitors(<span style="font-size:0.8em;font-style:italic;">from /WP-CONTENT---ALLOWED-IP/</span>). Your IP is: '. user_IP__LRL );
		$this->NameOfSite		=$this->sanitizer(home_url());
		$this->NameOfNewtork	=$this->sanitizer(network_home_url());
		$this->AIPS_filename	='ALLOWED_IPs_FOR_WP_LOGIN.txt';
		
		$this->logs_table_namee	=$GLOBALS['wpdb']->prefix. "restrictor_logins";
		$this->default_iptext	="123.999.999.999 (its James, my friend!)\r\n" . user_IP__LRL . "(this my another PC)\r\n124.999.999.999(its my anoterrr pc..write anything here...),\r\n etc....";
		$this->plugin_pageslug	='lgs-submenu-page';
			//$this->ips_BACKUPname	="backup_ips_".$this->plugin_pageslug.'___'. $this->NameOfSite ;
		$this->admin_mail		=$this->get_option('admin_email');
		$this->my_options_name	='optLRL__arrays';
		$this->txt_separatorrr	="''''''''''";
		// options  
		$this->my_options_array = $this->get_option($this->my_options_name, array()); 
		$this->default_roles	= array('administrator'=>'', 'editor'=>'', 'author'=>'',  'contributor'=>'',   'subscriber'=>'');
		

		//activation hooks;
			register_activation_hook( __FILE__,  array($this, 'lgs_install'));
			//if updare button clicked
				//add_action( 'upgrader_process_complete',  array($this, 'lgs_my_upgrate_function', 10, 2)  );
			register_deactivation_hook( __FILE__,  array($this, 'lgs_uninstall'));
		//add page under SETTINGS
			if(is_multisite())				{ add_action('network_admin_menu',	function() { add_submenu_page( 'settings.php' ,'LOGIN Restrictor','LOGIN Restrictor', 'manage_options' ,$this->plugin_pageslug, array($this, 'lgs_page_callback') );  }   ); }
			if($this->Enable_for_subsites)	{ add_action('admin_menu',			function() { add_submenu_page( 'options-general.php' ,'LOGIN Restrictor','LOGIN Restrictor', 'manage_options' ,$this->plugin_pageslug, array($this, 'lgs_page_callback') );}   );  }

		// run it before the headers and cookies are sent
			add_action('login_init',	array($this, 'logintrackss_checkip'), 1 );
		// check if logged in illegally
			add_action('init',	array($this, 'check_illegaly_loggedin'), 1  ); 
		//check user after LOGIN action (and if needed, send email)
			//add_action('wp_login', 	array($this, 'Insert_ip_into_database__and__email') ); 
			add_filter('authenticate', 	array($this, 'Insert_ip_into_database__and__email'), 91 , 3 );
		//check if VERSION needs REACTIVATION!
			//add_action('admin_notices',		array($this, 'check_version_alert') ); 
		//pass GLOBAL variable when login page happens
			add_action('login_head',		array($this, 'set_login_pagenow') ); 
		//get-set essential options	
			add_action('plugins_loaded',	array($this, 'reupdate_options') ); 
		//notification when updated
			add_action('network_admin_notices',	array($this, 'reactivate_notification') );  
			add_action('admin_notices',			array($this, 'reactivate_notification') );  
			
	
			$this->final_adminurl= (is_multisite()) ? network_admin_url('settings.php?page='.$this->plugin_pageslug) : admin_url( 'admin.php?page='.$this->plugin_pageslug) ;
		
								//===========  links in Plugins list ==========//
								add_filter( "plugin_action_links_".plugin_basename( __FILE__ ), function ( $links ) {   $links[] = '<a href="'. $this->final_adminurl .'">Settings</a>'; $links[] = '<a href="http://paypal.me/tazotodua">Donate</a>';  return $links; } );
								//REDIRECT SETTINGS PAGE (after activation)
								add_action( 'activated_plugin', function($plugin ) { if( $plugin == plugin_basename( __FILE__ ) ) { exit( wp_redirect( $this->final_adminurl ) ); } } );
			
	}
	
	
	
	
	
	
	
	
	
	// ===============================================================//
	// ===================  Activation + UPDATE ======================//
	// ===============================================================//
	public function lgs_install(){	
		// die if not network (when MULTISITE )
		if ( is_multisite() && ! strpos( $_SERVER['REQUEST_URI'], 'wp-admin/network/plugins.php' ) ) {		die ( __( '<script>alert("Activate this plugin only from the NETWORK DASHBOARD.");</script>') );    }
	
		global $wpdb;	$table_name=$this->logs_table_namee;
		$create_table = $wpdb->query("CREATE TABLE IF NOT EXISTS `$table_name` (
			  `id` int(50) NOT NULL AUTO_INCREMENT,
			  `username` varchar(150) CHARACTER SET utf8 NOT NULL,
			  `gmtime` datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
			  `ip` varchar(150) CHARACTER SET utf8 NOT NULL,
			  `country` varchar(250) CHARACTER SET utf8 NOT NULL,
			  `city` varchar(250) CHARACTER SET utf8 NOT NULL,
			  `success` varchar(2) CHARACTER SET utf8 NOT NULL,
			  `extra_column2` varchar(400) CHARACTER SET utf8 NOT NULL,
				PRIMARY KEY (`id`),
				UNIQUE KEY `id` (`id`)
			)  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ; ") or die("error_2345_". $wpdb->print_error());
		$this->reupdate_options();
		//rename old column name
	}
	
	
	
	
	
	
	
	public function reupdate_options(){	
		global $wpdb;
		$this->changeCreate_FileFolders();
		
		
		if(empty($this->my_options_array) || $this->my_options_array['version'] <= 2.24) {
			
		  //at first, check if something not updated from previous version (this needed if update was done using JAVASCRIPT, so, ACTIVATION hook wasnt triggered)
			$table_name=$this->logs_table_namee;
			if(empty($this->my_options_array) || $this->my_options_array['version'] <= 2.17) { 
				$res= $wpdb->query("ALTER TABLE `$table_name` CHANGE  `time` `gmtime` VARCHAR(255) NOT NULL;"); 
			}
		  //adding CITY
			if(empty($this->my_options_array) || $this->my_options_array['version'] <= 2.22) {
				$need_update=true;
				$res= $wpdb->query("SELECT * FROM information_schema.COLUMNS WHERE   TABLE_SCHEMA = '".DB_NAME."' AND TABLE_NAME = '$table_name' AND COLUMN_NAME = 'city'"); 
				if(empty($res)){
					$res= $wpdb->query("ALTER TABLE `$table_name` ADD `city` varchar(255)  CHARACTER SET utf8   NOT NULL   AFTER country;");
				}
			}
				
		  // =================	get  settings	==========================//
			$opts = $this->my_options_array;
			
		  // =================	FOR version check	==========================//
			if(empty($opts["version"]) || 	$opts["version"]!= $this->this_version) {$need_update=true;
				$opts["version"]=$this->this_version;
			}
			
		  // =================	FOR WHOIS 	==========================//
			if(!array_key_exists('lgs_enable_WHOIS',$opts)) {$need_update=true; 
				$opts["lgs_enable_WHOIS"]=false; 
			} 
			
		  // =================	FOR updat notification 	==========================//
			if(!array_key_exists('admin_reactivate_notice_shown',$opts)) {$need_update=true; 
				$opts["admin_reactivate_notice_shown"]=0; 
			} 
							
		  // =================	FOR allowance checkboxes ==========================//
			foreach ($this->default_roles as $name=>$value){	
				if(empty($opts['optin_for_white_ipss']) || !array_key_exists($name,$opts['optin_for_white_ipss']) ) {$need_update=true; 
					$opts["optin_for_white_ipss"][$name]=3; 
				}
			}
			
		  // =================  FOR backup file ==========================//
			//$opts[$this->ips_BACKUPname]		= $this->get_option($this->ips_BACKUPname);
			

		  // ================= if modifications needed ==========================//
			if (isset($need_update)) { $this->update_option($this->my_options_name, $opts );  $this->my_options_array=$opts;  $GLOBALS['LRL_updated']=true;}
		}
	}
	
								
						public function reactivate_notification(){
							$opts = $this->my_options_array;
							if ( $opts['admin_reactivate_notice_shown'] < 1 || !empty($GLOBALS['LRL_updated']) ){
								if($this->iss_admiiiiiin()){
									$opts['admin_reactivate_notice_shown']=1;
									echo '<div style="font-size:2em; background:pink; padding: 130px 130px;"> <a href="'.admin_url('plugins.php').'" target="_blank">LOGIN-Restrictor</a> was re-activated in order to implement the new updates.</div>';
									$this->update_option($this->my_options_name, $opts );
								}
							}
						}
	

	
	
						// ============  update from old  (<2.17) version   ================
							public function changeCreate_FileFolders(){ 
							  //if main file doesnt exist
								if(!file_exists($this->path_of_IPs())) {	$content=false;
								  //create new directory (if not exists)
									if (!file_exists($this->path_of_IPs_folder())) {  mkdir($this->path_of_IPs_folder(), 0755, true); } 
									
								  //if old plugin version(<2.13) file/directory exists, then remove them
									$phpFILE='ALLOWED_IPs_FOR_WP_LOGIN.php';
									foreach(array('http','https') as $HTTPs){
										$f1= $this->AIPS_folder.$HTTPs.'___'.$this->NameOfSite.'/'.$phpFILE;
										  if (file_exists(dirname($f1).'/.htaccess')) {unlink(dirname($f1).'/.htaccess');}
										  if (file_exists($f1)) {$content=file_get_contents($f1); unlink($f1); @rmdir(dirname($f1));}
										$f2= $this->AIPS_folder.$HTTPs.'___'.$this->NameOfSite.'/'.$this->AIPS_filename;
										  if (file_exists($f2)) {$content=file_get_contents($f2); unlink($f2); @rmdir(dirname($f2));}
									}
									
									$f4=ABSPATH.'ALLOWED_IP/'.$this->NameOfSite.'/'.$phpFILE; 
									  if (file_exists($f4)) {$content=file_get_contents($f4); unlink($f4); @rmdir(dirname($f4));}
									$f5=ABSPATH.'ALLOWED_IP/'.str_ireplace('www.','', $_SERVER['HTTP_HOST']).'/'.$phpFILE;
									  if (file_exists($f5)) {$content=file_get_contents($f5); unlink($f5); @rmdir(dirname($f5));}
									$f6=$this->path_of_IPs_folder().$phpFILE;
									  if (file_exists($f6)) {$content=file_get_contents($f6); unlink($f6);}
										
								 //if $content is read from old file OR there was BACKUP
									$final_content='';
									// if(!empty($this->my_options_array[$this->ips_BACKUPname])) { $final_content = $this->my_options_array[$this->ips_BACKUPname];	}
									
									if (empty($final_content)) {
									  //try to copy from main site
									  if (file_exists($this->path_of_IPs(true))){
										 $text1= file_get_contents($this->path_of_IPs(true));
									  }
									  if (!empty($text1)){$final_content=$text1;}
									  else{
										//now, create a new type of content
										$editable_roles=$this->default_roles; 
										foreach ($editable_roles as $name=>$value){
										  $final_content .=  
											"\r\n".$this->txt_separatorrr.  $name  .
											"\r\n".( 
												($name=='administrator' && $content)  ?  $content : $this->default_iptext  
											).
											"\r\n\r\n\r\n";  
										}
										$final_content .=  "\r\n".$this->txt_separatorrr;
									  }
									  file_put_contents($this->path_of_IPs(),  $final_content);	chmod($this->path_of_IPs(),0600);
									}
								}
								
								// if HTACCESS doesnt exist there
								if(!file_exists($this->path_of_IPs_folder().'.htaccess')){
									file_put_contents($this->path_of_IPs_folder().'.htaccess',"#LoginRestroctorPlugin \r\n<IfModule mod_php5.c>\r\nRewriteEngine On\r\norder deny,allow\r\ndeny from all\r\n</IfModule>\r\n#######LoginRestroctorPlugin#########");
								}
							}
							
						// ============== update from old version  =========================

						
						
	// =================================================================== //
	// ================== #### Activation + Update ### =================== //
	// =================================================================== //














	
	
	//   ========================================= TYPICAL FUNCTIONS ================================================== //
	//   =============================================================================================================== //
	
	public function lgs_uninstall()	{        }			//unlink($this->path_of_IPs());
	public function iss_admiiiiiin(){	require_once(ABSPATH.'wp-includes/pluggable.php');	return (current_user_can('activate_plugins')? true:false);}
	public function iss_admiiiiiin_network(){	require_once(ABSPATH.'wp-includes/pluggable.php');	return (current_user_can('manage_network')? true:false);}
	public function validate_pageload($value, $actNAME)
		{ if(!isset($value) || !wp_verify_nonce($value, $actNAME) ) { die("not allowed (error473 _LoginRestrict plugin)");} }
	public function role_ips($name)
		{preg_match('/'.addslashes($this->txt_separatorrr).$name.'(.*?)'.addslashes($this->txt_separatorrr).'/si', file_get_contents($this->allowed_ipss_file_CREATED()), $new);  return $new[1];}
	public function RandomString(){  return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, '15'); }
	public function get_user_roles(){  	
		require_once(ABSPATH.'wp-admin/includes/user.php'); return get_editable_roles();
	}
	protected function sanitizer($path){ 
		$path1= (substr($path,-1)=='/') ?  substr($path,0,-1) : $path;   // remove last / chart
		$path2= preg_replace('/\W/si','_', str_ireplace( array('https:','http:','//www.','//','/'), array('','','','','-'),  $path1) );   
		return $path2;
	}

 	protected function simple_encrypt($text,$salt)	{  	return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $salt, $text, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));}
	protected function simple_decrypt($text,$salt)	{  	return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $salt, base64_decode($text), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))); }
	
	public function get_option($x,$y=false)	{ return ($this->Enable_for_subsites ? get_option($x,$y) : get_site_option($x,$y)); }
	public function update_option($x,$y)	{ return ($this->Enable_for_subsites ? update_option($x,$y) : update_site_option($x,$y)); }
	public function is_admin_pg(){  return (is_admin() || defined('Login_page__LRL')); }

	//when on login page, then set variable
	public function set_login_pagenow(){ $GLOBALS['pagenow']=='wp-login.php'; }
	public function path_of_IPs($main_site=false)		{  return $this->path_of_IPs_folder($main_site).$this->AIPS_filename; }
	public function path_of_IPs_folder($main_site=false){  return $this->AIPS_folder.(!$this->Enable_for_subsites || $main_site? $this->NameOfNewtork.'/'  : $this->NameOfSite .'/'); }
	
	//if file doesnt exist still, then create..
	public function allowed_ipss_file_CREATED() {
		$file	=$this->path_of_IPs();
		//if file doesnt exist (i dont know why, but lets check..), then re-create essentials
		if(!file_exists($file))		{	$this->changeCreate_FileFolders();	}
		return $file;
	}
	// get content of listed IPs
	public function IP_is_in_content($content=false, $ip=false, $re_call=true){	$ip=($ip ? $ip : user_IP__LRL);
		if(!$content) {
			if (!$re_call && isset($GLOBALS['IPs_got_CONTENT__lrl'])) { $content = $GLOBALS['IPs_got_CONTENT__lrl']; }
			else{$content= file_get_contents($this->allowed_ipss_file_CREATED()); }
		}
		$GLOBALS['IPs_got_CONTENT__lrl']= $content;
		$starred_IP= preg_replace('/(.*?)\.(.*?)\.(.*?)\.(.*)/si', '$1.$2.$3.'.'*' , $ip );
		return (stripos($content, $ip) !== false  || stripos($content,  $starred_IP) !== false );
	}

	//   =========================================================================================== //
	//   ====================================   PLUGIN FUNCTIONS    ================================== //
	//   =========================================================================================== //
	
	// at first, see, if all ROLES has enabled IP_PROTECTION, then check:   if IP is unlisted from file, then block him
	public function check_if_directly_forbidden($username='') { 
		if ( !in_array("1", $this->my_options_array["optin_for_white_ipss"]) && !in_array("2", $this->my_options_array["optin_for_white_ipss"])  ){    $this->die_if_ip_unlisted('',$username);    }
	}
	public function die_if_ip_unlisted($rolename='', $username=false){ 
		$allwd_ips = (!empty($rolename) ? $this->role_ips($rolename) : false ) ;
	  //if ip is not in list
		if(!$this->IP_is_in_content($allwd_ips)){
			//last check : if authentificated by GSTSA  [see in the end of this file]
			$user= wp_get_current_user();  
			if(  (!empty($user->user_login) && $this->GSTSA_userIsAuthorized__LRL($user->user_login))
				    ||
				($username && $this->GSTSA_enabled_for_user__LRL($username))
			)
			   {
				//do nothing
			}
			else{
				die($this->unknown_ip_disabled_message );
			}
		}
	}
	 

	public function logintrackss_checkip(){  
		// if(!defined('Login_page__LRL')) {define('Login_page__LRL',true);}
	  //IF my "2step SMS-AUTH" plugin in not implemented by administrator, then we directly check if UNKNOWN IPs are blocked at all!
	  //else (in case SMS-AUTH is activated) we wont directly block unknown IPs,but let them to try SMS codes...
		if (!$this->GSTSA_is_activated__LRL()){	  $this->check_if_directly_forbidden();	}
	  //now (if above passed) check if incorrect login is made
		if (!empty($_POST['log']) && !empty($_POST['pwd']))	{   $this->checkUserAllowed(sanitize_text_field(esc_attr($_POST['log'])));  }
	}
	// Check if illegally logged in
	public function check_illegaly_loggedin(){  if($this->is_admin_pg()){  if (is_user_logged_in()){ $this->checkUserAllowed(); }  }	}
	
	public function checkUserAllowed($submitted_username=''){	
	  //default first check 
		$this->check_if_directly_forbidden($submitted_username);
	  //otherwise, go on....
		require_once(ABSPATH . 'wp-includes/pluggable.php');
	  //if username not passed
		if (empty($submitted_username )) { $user_info= wp_get_current_user();  $submitted_username = $user_info->user_login; }
	  //if still not found any username,then die..
		if (empty($submitted_username )) { die ("nouser error_2542  (LoginRestrictor Plugin)"); }
		else {
		  //if login using email
			if (stripos($submitted_username,'@')!==false) { $userARRAY=get_user_by( 'email',$submitted_username); }
		  //DONT USE here elseif!   becase if  username contains email sign (rarely happens,but...), then we should do the below
			if (empty($userARRAY)){ $userARRAY=get_user_by( 'login', $submitted_username );}
		}

	  //if USER NOT found still, then die...
		if (empty($userARRAY)){ die("not user (error572   LoginRestrict plugin)");   }
	  //
		else {
		  //if logged-in user's role is PROTECTED, then check  if IP allowed....  otherwise, LET HIM FREEE !!!!
			if ( $this->my_options_array['optin_for_white_ipss'][ $userARRAY->roles[0]] == 3 ){	
				$this->die_if_ip_unlisted($userARRAY->roles[0],$submitted_username);	
			}
		}
	}





	

	//insert user login into database (and if needed, send email to admin)
	public function Insert_ip_into_database__and__email($user_data=false){  
	  global $wpdb;	$table_name = $wpdb->prefix."restrictor_logins";
	  if (!empty($user_data->errors)) { return $user_data;}
	  
	  $userARRAY= $user_data ? $user_data : wp_get_current_user();   $user_role = $userARRAY->roles[0]; 
		
	  //=================INSERT IN DATABASE===============
		if ($this->my_options_array['lgs_enable_WHOIS'] != 'yes' ){		//if user has enabled remote whois
			include_once( dirname(__file__)."/ip_country_data/GeoIP_V2/sample-test.php" ); $ip_country = $country_name;
		}
		else{
			$got_resultt = wp_remote_retrieve_body(wp_remote_get($this->whois_site. user_IP__LRL));
			preg_match('/address:(.*?)address:(.*?)address:(.*?)address:(.*?)address:(.*?)phone/si',$got_resultt, $output1);
			//preg_match('/address:(.*?)phone/si',$got_resultt, $output2);
			$ip_country = !empty($output1[5]) ?  $output1[5].'('.$output1[4].')' :  '';
		}
		
		$insert = $wpdb->query($wpdb->prepare("INSERT INTO $table_name (username, gmtime,ip,country, success) VALUES (%s, %s, %s, %s, %s)", $userARRAY->data->user_login, current_time('mysql',1), user_IP__LRL, $ip_country, 1));    //DATE is in ACCEPTABLE SQL format!!

		$allwd_ips = $this->role_ips($user_role);
		//Send notification if no-listed IP 
		if (stripos($allwd_ips, user_IP__LRL) === false)	{
			if ($this->my_options_array['optin_for_white_ipss'][$user_role] == 2){
				$subjectt	="UNKNOWN IP(".user_IP__LRL.") has logged into ".home_url()." ";
				$full_messag="\r\n\r\n Someone with an IP ".user_IP__LRL." (COUNTRY:$ip_country) has logged into your site. \r\n\r\n (if you know him, you can add him to whitelist: " . $this->final_adminurl ;
				// To send HTML mail, the Content-type header must be set
				$headers  = "MIME-Version: 1.0\r\nContent-type: text/html\r\nFrom: LOGIN RESTRICT <noreply@noreply.com>\r\nReply-To: noreply@noreply.com\r\nX-Mailer: PHP/".phpversion();

				if ($_SERVER['HTTP_HOST'] != 'localhost'){
					$result = mail( $this->admin_mail ,$subjectt, $full_messag ,$headersss) ? "okkk" : "problemm";
					//file_put_contents(dirname(__file__).'/aaaa.txt',$result);
				}
			}
		}
		return $user_data;
	}


	
	
	public function lgs_page_callback(){ 
	
		global $wpdb;	$table_name = $wpdb->prefix . "restrictor_logins";
		$editable_roles = $this->get_user_roles();
		$opts=$this->my_options_array;
	  // ======= if settings updated  ====== //	
		  //if records cleared
			if (!empty($_POST['clear_ltk'])) { $this->validate_pageload($_POST['nonce_upd'],'lo_clear');  $wpdb->get_results("DELETE FROM ".$table_name." WHERE success='0' OR success='1'"); }
		  //if WHOIS method changed (currently disabled)
			//if (!empty($_POST['Whois_Method'])) { $this->my_options_array['lgs_enable_WHOIS'] = $_POST['Whois_Method'];	}
		  //IF page updated
			if (!empty($_POST['update_ips'])) 			{
				$this->validate_pageload($_POST['update_ips'],'lo_upd');
		
				foreach ($editable_roles as $name=>$value){  $opts['optin_for_white_ipss'][$name] = $_POST['whitelist_ips'][$name]; }
			  //change IP file
			  
				$final='';
				foreach ($editable_roles as $name=>$value){ $final .=  "\r\n".$this->txt_separatorrr.$name."\r\n".$_POST['lgs_white_IPS'][$name]."\r\n\r\n\r\n";  }   $final = $final.$this->txt_separatorrr;
				file_put_contents($this->allowed_ipss_file_CREATED(),	$final );
				//$opts[$this->ips_BACKUPname] = $final;
				
				if (isset($_POST['enable_subsites'])) {
					if($this->iss_admiiiiiin_network() && is_multisite()) {
						$this->Enable_for_subsites=$_POST['enable_subsites'];
						update_site_option('LRL_enable_subsites', $this->Enable_for_subsites ); 
					}
				}
			}
			
			foreach($editable_roles as $name=>$value) {
				if( !array_key_exists($name, $opts['optin_for_white_ipss']) ){	$opts["optin_for_white_ipss"][$name]= 3;  }
			}
			
		  //TRIGGER update
			if (!empty($_POST)) { $this->update_option($this->my_options_name, $opts); }
	  // ======= if settings updated  ====== //	
	 
	 
	// ===================================== 
		$ipfile_content 	= file_get_contents($this->allowed_ipss_file_CREATED());
		$whiteips_answer	= $opts['optin_for_white_ipss'];
		?>	
			
			
		<style>
		.my_login_tracks tr.succeed{ background-color:#A6FBA6;} .my_login_tracks tr.succeed:hover{ background-color:#A2E4A2;} 
		.my_login_tracks tr.failed{ background-color:#FFC8BF;} 	.my_login_tracks tr.failed:hover{ background-color:#f2a3cd;} 
		.my_login_tracks tr.unknown{ background-color:#eeeeee;} .my_login_tracks tr.unknown:hover{ background-color:#e7e7e7;} 
		.my_login_tracks tr { line-height: 1em; }  
		.my_login_tracks .widefat td {border: 1px solid; border-width: 0 0px 1px 0;} 
		.my_login_tracks .nonlistedIp{background-color:#fe8b8b;font-size:1.6em;}
		.inputboxx {cursor: pointer; font-size:2em; padding:20px; border:4px solid rgb(209,126,56); border-radius:8px;  box-shadow: 0px 0px 7px rgb(153, 153, 153);      background: transparent linear-gradient(to bottom, rgb(251, 6, 6) 0%, rgb(191, 110, 78) 100%) repeat scroll 0% 0%;    color: white;  text-shadow:1px 1px 1px #e6ece6; }
		.boxxed { padding: 5px;  border:2px solid rgb(209, 126, 56);  border-radius:8px;  box-shadow: 0px 0px 7px rgb(153, 153, 153) }
		</style>
		<div class="my_login_tracks"><!-- ENABLE/DISABLE OPTIONS -->
			<form method="post" action="">
				<p class="submit">
						<!--
						<b style="font-size:1.2em;">Turn on City Detection too?</b>  <a href="javascript:alert('If this is disabled, then you will see only COUNTRY NAME of visitor, and you have to click that, and you will see full report for that IP. However, you can ENABLE this option, and then you will see CITY name too (along with COUNTRY NAME), but that process prolongs the log-in process by 3 seconds. ');">read more!!</a> 
						<?php //if ($this->my_options_array['lgs_enable_WHOIS']=='yes') {$enab='checked';$disab='';} else{$enab='';$disab='checked';} ?>
						<br/><input type="radio" name="Whois_Method" value="yes" <?php //echo $enab;?>  />ENABLE	<input type="radio" name="Whois_Method" value="no"  <?php //echo $disab;?> />DISABLE
						<br/><br/>
						-->	
					<div class="">
					Enable per SUB-site: <?php if (is_network_admin()){ echo '<span style="color:red;"> <input type="hidden" value="0" name="enable_subsites" /><input type="checkbox" name="enable_subsites" value="1" '.($this->Enable_for_subsites ? 'checked="checked"' : '') .'/> </span>';} ?>  <a style="margin:0 0 0 10px;" href="javascript:alert('If you are using MULTI-SITE wordpress, you can modify these settings globally from NETWORK DASHBOARD. Here you will see the checkbox, if you enter this page in NETWORK DASHBOARD');">click to read!</a> 
					</div>
						
					<div style="font-size:1.2em;font-weight:bold;margin:20px 0 0 0;">
						<table>
						<tr><td>* IP WHITELISTING setting: </td> <td><a style="margin:0 0 0 20px;" href="javascript:alert('1) Allow ALL  - plugin wont do anything, anyone will be allowed. (no restriction to unknown IPS and no notifications).\r\n2) get MAIL NOTIFICATION (if your server supports mailsending) at <?php echo $this->admin_mail;?> (address is changeable from Settings>General) when anyone logins, whose IP is not in this list. \r\n3) Block anyone to access LOGIN page at all [whose IP is not in the list]. \r\r\n(DONT FORGET TO INSERT YOUR IP TOO! HOWEVER,IF YOU BLOCK YOURSELF,enter your wordpress directory (from FTP) and add your IP into this file: WP-CONTENT-\u0022ALLOWED_IP\u0022 . otherwise delete this plugin.)\r\n');">click to read!</a>
						</td></tr>
						<tr><td>* Adding Variable IP : </td> <td><a style="margin:0 0 0 20px;" href="javascript:alert('You can insert Asterisk IP instead of last 3 chars. For example:\r\n 111.111.111.*\r\n\r\n\r\np.s.In case you dont like this plugin, you may need something \u0022login attempt blocker\u0022 plugins (For example, \u0022Wordfence Security\u0022,\u0022Brute force login protection\u0022,\u0022Login Protection\u0022 or etc...)');">click to read!</a></td></tr>
						<tr><td>* description of ROLES : </td> <td><a href="javascript: window.open('https://codex.wordpress.org/Roles_and_Capabilities#Summary_of_Roles', '_blank');void(0);">read the website</a></td></tr>
						</td></tr>
						</table>
						<br/>
						<br/>
								
					</div>
					<div style="text-align:center; background-color: rgb(234, 127, 127); padding:10px; font-size:1.8em; ">(your IP is <b style="color:red; background-color:yellow;"><?php echo user_IP__LRL;?></b>)</div>
					<br/>
					<br/>	
					<br/>
					
					
								<?php foreach ($editable_roles as $name=>$value){
									$d3 = $whiteips_answer[$name] == 3 ? "checked" : '';
									$d2 = $whiteips_answer[$name] == 2 ? "checked" : '';
									$d1 = $whiteips_answer[$name] == 1 || empty($whiteips_answer[$name]) ? "checked" : '';
									?>
								
									<div class="white_list_ipps" style="background-color:#1EE41E; padding:5px; margin:0 0 20px 10%; width:60%;">
										<div style="font-size:3em;  line-height:1em; margin:10px ; text-align:center; font-weight:bold;"> <?php echo $name;?>s</div>
										<table style="border: 1px solid;"><tbody><thead><tr><td style="width:140px;">&nbsp;</td><td>&nbsp;</td></tr>
											<tr><td>Allow All </td>				<td><input onclick="lg_radiod();" type="radio" name="whitelist_ips[<?php echo $name;?>]" value="1" <?php echo $d1;?> /></td></tr>
											<tr><td>Mail notification</td>	<td><input onclick="lg_radiod();" type="radio" name="whitelist_ips[<?php echo $name;?>]" value="2" <?php echo $d2;?> /></td></tr>
											<tr><td>Deny NON-listed IPs</td><td><input onclick="lg_radiod();" type="radio" name="whitelist_ips[<?php echo $name;?>]" value="3" <?php echo $d3;?> /></td></tr>
											<tr><td>&nbsp;</td><td>
											</td></tr>
										</tbody></table>
											
										<div class="DIV_whiteipieldd_<?php echo $name;?>" style="overflow-y:auto;">
											<?php	
											$current_role_content = $this->role_ips($name);
											if($name=='administrator' && empty($current_role_content) ){$current_role_content=$this->default_iptext;}
											$liness=explode("\r\n", $current_role_content );	
											?>
											<textarea id="whiteips_fieldd_<?php echo $name;?>" style="width:100%;height:250px;" name="lgs_white_IPS[<?php echo $name;?>]"><?php foreach (array_filter($liness) as $line) {echo $line."\r\n";}?></textarea>
										</div>
									</div>
										
								<?php } ?>					
						
						
						<script type="text/javascript">
						function lg_radiod()	{
							var ed_roles = [<?php foreach ($editable_roles as $name=>$value){echo "'$name',";} ;?>];
							for (i=0; i< ed_roles.length; i++){
								var valllue = document.querySelector('input[name="whitelist_ips['+ed_roles[i]+']"]:checked').value;
								var DIVipfieldd = document.getElementsByClassName("DIV_whiteipieldd_"+ed_roles[i])[0];
								if(valllue == "2" || valllue == "3")	{DIVipfieldd.style.opacity = "1";}	else {DIVipfieldd.style.opacity = "0.3";}
							}
						}
						lg_radiod();
						</script>
						
						<div style="clear:both;"></div>
						<div style="position: fixed; bottom: 0px; left: 45%;"> <input type="submit"  value="SAVE" onclick="return foo23();"   class="inputboxx" /></div>
						<input type="hidden" name="update_ips" value="<?php echo wp_create_nonce('lo_upd');?>" />
						<br/>
					<script type="text/javascript">
					function foo23()			{
						var IPLIST_VALUE=document.getElementById("whiteips_fieldd_administrator").value;
						var user_ip="<?php echo user_IP__LRL;?>";
						
						var TurnedONOFF = document.querySelector('input[name="whitelist_ips[administrator]"]:checked').value;
						if (TurnedONOFF != "1")	{
							if (IPLIST_VALUE.indexOf(user_ip) == -1)	{
								if(!confirm("YOUR IP(" + user_ip +") is not in ADMINISTRATORS list! Are you sure you want to continue?")){return false;}
							}
						}
						return true;
					}
					</script>
				</p> 
			</form>
			<br/><br/><h2>All logins:</h2>
			<table class="widefat" cellpadding="3" cellspacing="3"><tr><th>Username</th><th>Time (wp local)</th><th>IP <span style="font-size:0.8em;"><br/>(red IP means that <br/> he isn't in above lists)</span></th><th>COUNTRY (<a href="javascript:alert('This is just an approximate country name. To view the full info for a particular IP, then in this column, click that COUNTRY NAME and you will be redirected to the WHOIS WEBSITE, where you will see the FULL INFORMATION of that IP.');">Read THIS!!</a>)</th><th>Succeed?</th></tr>
			<?php
			$results = $wpdb->get_results("SELECT username,gmtime,IP,country,success FROM ".$table_name." ORDER BY gmtime DESC");
			if ($results){	foreach ($results as $e) {
					//determine country
						if(!empty($e->country))	 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank"> '.$e->country.'</a>';}
						elseif(in_array($e->IP,array('::1','127.0.0.1'))) {$countryyy ='<span style="color:#c8c6c6;">localhost</span>';}
						else 					 {$countryyy =  '<a href="'. $this->whois_site . $e->IP.'" target="_blank"> problem_54_from_plugin</a>';}
					echo '<tr class="succeed"><td>'.$e->username.'</td><td>'. get_date_from_gmt($e->gmtime)  . '</td><td><span class="'.(!$this->IP_is_in_content(false,$e->IP) ? 'nonlistedIp' : '') .'">'.$e->IP.'</span></td><td>'.$countryyy.'</td><td>succeed<td></tr>';
				}} ?>
			</table>
			
			<!-- clean records -->
			<form method="post" action="">	<input type="hidden" name="clear_ltk" value="true"/><input type="submit" name="logintracks_submit" value="Clean login data"/><input type="hidden" name="nonce_upd" value="<?php echo wp_create_nonce('lo_clear');?>" />
			</form>		<br/><br/>p.s. To view other MUST-HAVE Wordpress Plugins, visit <a href="http://codesphpjs.blogspot.com/2014/10/must-have-wordpress-plugins.html#activity_plugins" target="_blank">http://codesphpjs.blogspot.com/2014/10/must-have-wordpress-plugins.html#activity_plugins</a><br/><br/><br/>
		</div>
<?php	}











	// =======================================
	// integrate with my beloved country's (Georgia) SMS authentificator plugin, if that plugin is installed
	// =======================================
	public function GSTSA_is_activated__LRL(){  
		if(defined('version__GSTSA')){	$opts=get_opts__GSTSA();  if($opts['integrate_with_lrl']) { return true; }  	}	return false;
	}
	public function GSTSA_userIsAuthorized__LRL($username=false){ 
		if($this->GSTSA_is_activated__LRL())	{ return CheckIfCookieSet__GSTSA($username);	}	return false;
	}
	public function GSTSA_enabled_for_user__LRL($username=false){ 
		if($this->GSTSA_is_activated__LRL())	{ return IfUserSMSenabled__GSTSA($username);	}	return false;
	}

	
	
	
	
	
}	

$GLOBALS['Login_Restrictor_and_Logs'] = new Login_Restrictor_and_Logs;

?>