<?php
/*
 * Connect_google Controller
 */
class Connect_google extends CI_Controller {
	
	/**
	 * Constructor
	 */
	function __construct() {
		parent::__construct ();
		
		// Load the necessary stuff...
		$this->load->config ( 'account/account' );
		$this->load->helper ( array (
				'language',
				'account/ssl',
				'url',
				'openid' 
		) );
		$this->load->library ( array (
				'account/authentication',
//				'account/authorization' 
		) );
		$this->load->model ( array (
				'account/account_model',
				'account_openid_model' 
		) );
		$this->load->language ( array (
				'general',
				'account/sign_in',
				'account/account_linked',
				'account/connect_third_party' 
		) );
	}


	private function getOpenIDFromToken($client, $token) {
		$id_token = json_decode($token);
		$ticket = $client->verifyIdToken($id_token->{'id_token'});
		if ($ticket) {
			$data = $ticket->getAttributes();
			return $data['payload']['openid_id']; // user ID
		}
		return false;
	}



	function index() {
		
		// --> Som
		
		// Include two files from google-php-client library in controller
		set_include_path (get_include_path() . PATH_SEPARATOR . '/sites/dev.archivesupport.kbb1.com/public/application/libraries/account/google-api-php-client/src/Google' );
		require_once APPPATH . "libraries/account/google-api-php-client/src/Google/autoload.php" ;
		require APPPATH . "libraries/account/google-api-php-client/src/Google/Client.php";
		require APPPATH . "libraries/account/google-api-php-client/src/Google/Service/Oauth2.php";
		
		// Store values in variables from project created in Google Developer Console
		$client_id = '476947191236-voia2kkes0ujf8oakltefbjmtvr3qca1.apps.googleusercontent.com';
		$client_secret = '1DgZDXW5uNfiqeX3P_Q2wSOz';
		$redirect_uri = 'http://dev.archivesupport.kbb1.com/account/connect_google';
		// $simple_api_key = '< Generated API Key >';
		
		// Create Client Request to access Google API
		$client = new Google_Client ();
		$client->setApplicationName ( "PHP Google OAuth Login Example" );
		$client->setClientId ( $client_id );
		$client->setClientSecret ( $client_secret );
		$client->setRedirectUri ( $redirect_uri );
		//$client->setDeveloperKey ( 'AIzaSyAdusKrsDIOATTgAS0CJlxnoA8r6YuFFMw' );
		$client->addScope ( "https://www.googleapis.com/auth/userinfo.email" );
		$client->setOpenidRealm($redirect_uri);
		// <-- Som
		
		// Enable SSL?
		maintain_ssl ( $this->config->item ( "ssl_enabled" ) );
		
		// Get OpenID store object
		$store = new Auth_OpenID_FileStore ( $this->config->item ( "openid_file_store_path" ) );
		
		// Get OpenID consumer object
		$consumer = new Auth_OpenID_Consumer ( $store );
		
		
		// Begin OpenID authentication process -- Som --
		$objOAuthService = new Google_Service_Oauth2 ( $client );
		
		if(! isset($authURL))
			unset($_SESSION['access_token']);	

		// Add Access Token to Session
		if (isset ( $_GET ['code'] )) {
			$client->authenticate ( $_GET ['code'] );
			$_SESSION ['access_token'] = $client->getAccessToken ();
			header ( 'Location: ' . filter_var ( $redirect_uri, FILTER_SANITIZE_URL ) );
		}
		
		// Set Access Token to make Request
		if (isset ( $_SESSION ['access_token'] ) && $_SESSION ['access_token']) {
			$client->setAccessToken ( $_SESSION ['access_token'] );
			$openid_id = $this->getOpenIDFromToken($client, $client->getAccessToken());
		}
		
		// Get User Data from Google and store them in $data
		if ($client->getAccessToken ()) {
			$userData = $objOAuthService->userinfo->get ();
			$data ['userData'] = $userData;
			$_SESSION ['access_token'] = $client->getAccessToken ();
			$openid_id = $this->getOpenIDFromToken($client, $client->getAccessToken());
		} else {
			$authUrl = $client->createAuthUrl ();
			$data ['authUrl'] = $authUrl;
			header ( 'Location:' . $authUrl);
			die();
		}
		
		// <-- Som
		// if ($this->input->get ( 'janrain_nonce' )) {
		// Complete authentication process using server response
		// $response = $consumer->complete ( site_url ( 'account/connect_google' ) );
		
		// Check the response status
		// if ($response->status == Auth_OpenID_SUCCESS) {
		if (isset($userData)) {
			// Check if user has connect google to a3m
			// if ($user = $this->account_openid_model->get_by_openid ( $response->getDisplayIdentifier () )) {
			if ($user = $this->account_openid_model->get_by_openid ( $openid_id )) {
				// Check if user is not signed in on a3m
				if (! $this->authentication->is_signed_in ()) {
					// Run sign in routine
					$this->authentication->sign_in ( $user->account_id );
				}
				$user->account_id === $this->session->userdata ( 'account_id' ) ? $this->session->set_flashdata ( 'linked_error', sprintf ( lang ( 'linked_linked_with_this_account' ), lang ( 'connect_google' ) ) ) : $this->session->set_flashdata ( 'linked_error', sprintf ( lang ( 'linked_linked_with_another_account' ), lang ( 'connect_google' ) ) );
				redirect ( 'account/account_linked' );
			}  // The user has not connect google to a3m
else {
				// Check if user is signed in on a3m
				if (! $this->authentication->is_signed_in ()) {
					$openid_google = array ();
					
			$client->setAccessToken ( $_SESSION ['access_token'] );
			$openid_id = $this->getOpenIDFromToken($client, $client->getAccessToken());
					// if ($ax_args = Auth_OpenID_AX_FetchResponse::fromSuccessResponse ( $response )) {
					if ($userData) {
						//$openid_google = $userData;
							//$openid_google ['username'] = $userData->getEmail();
							$email = $userData->getEmail();
							$openid_google ['fullname'] = $userData->getName();
							//$openid_google ['dateofbirth'] ;
							$openid_google ['gender'] = $userData->getGender();
							//$openid_google ['postalcode'];
							//$openid_google ['country'] = $ax_args ['http://axschema.org/contact/country/home'] [0];
							$openid_google ['language'] = $userData->getLocale();
							//$openid_google ['timezone'] = $ax_args ['http://axschema.org/pref/timezone'] [0];
							$openid_google ['firstname'] = $userData->getGivenName(); // google only
							$openid_google ['lastname'] = $userData->getFamilyName(); // google only
					}
					
					// Store user's google data in session
					$this->session->set_userdata ( 'connect_create', array (
							array (
									'provider' => 'openid',
									'provider_id' =>isset($openid_id) ? $openid_id : '12345',
									'email' => isset ( $email ) ? $email : NULL 
							),
							$openid_google 
					) );
					
					// Create a3m account
					redirect ( 'account/connect_create' );
				} else {
					// Connect google to a3m
					// $this->account_openid_model->insert ( $response->getDisplayIdentifier (), $this->session->userdata ( 'account_id' ) );
					$this->account_openid_model->insert ( $openid_id, $this->session->userdata ( 'account_id' ) );
					$this->session->set_flashdata ( 'linked_info', sprintf ( lang ( 'linked_linked_with_your_account' ), lang ( 'connect_google' ) ) );
					redirect ( 'account/account_linked' );
				}
			}
		}  // Auth_OpenID_CANCEL or Auth_OpenID_FAILURE or anything else
else {
			$this->authentication->is_signed_in () ? redirect ( 'account/account_linked' ) : redirect ( 'account/sign_up' );
		}
		// }
		
		// $auth_request = $consumer->begin($this->config->item("openid_google_discovery_endpoint"));
		
		// Create ax request (Attribute Exchange)
		$ax_request = new Auth_OpenID_AX_FetchRequest ();
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/namePerson/friendly', 1, TRUE, 'username' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/contact/email', 1, TRUE, 'email' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/namePerson', 1, TRUE, 'fullname' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/birthDate', 1, TRUE, 'dateofbirth' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/person/gender', 1, TRUE, 'gender' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/contact/postalCode/home', 1, TRUE, 'postalcode' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/contact/country/home', 1, TRUE, 'country' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/pref/language', 1, TRUE, 'language' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/pref/timezone', 1, TRUE, 'timezone' ) );
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/namePerson/first', 1, TRUE, 'firstname' ) ); // google only
		$ax_request->add ( Auth_OpenID_AX_AttrInfo::make ( 'http://axschema.org/namePerson/last', 1, TRUE, 'lastname' ) ); // google only
			                                                                                                                   // $auth_request->addExtension($ax_request);
			                                                                                                                   
		// Redirect to authorizate URL
			                                                                                                                   
		header("Location: ".$authUrl);
	}
}


/* End of file connect_google.php */
/* Location: ./application/account/controllers/connect_google.php */
