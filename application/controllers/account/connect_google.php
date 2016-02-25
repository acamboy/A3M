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
				'account/openid' 
		) );
		$this->load->library ( array (
				'account/authentication' 
		) )
		// 'account/authorization'
		;
		$this->load->model ( array (
				'account/account_model',
				'account/account_openid_model' 
		) );
		$this->load->language ( array (
				'general',
				'account/sign_in',
				'account/account_linked',
				'account/connect_third_party' 
		) );
	}
	
	// This method extracts openID2 ID form id token for backward compatibility
	private function getOpenIDFromToken($client, $token) {
		$id_token = json_decode ( $token );
		$ticket = $client->verifyIdToken ( $id_token->{'id_token'} );
		if ($ticket) {
			$data = $ticket->getAttributes ();
			return $data ['payload'] ['openid_id']; // user ID
		}
		return false;
	}
	function index() {
		
		// Include two files from google-php-client library in controller
		// to get composer work, set_include_path should contain absolute path to 'google-api-php-client/src/Google' 
		set_include_path ( get_include_path () . PATH_SEPARATOR . APPPATH .'application/libraries/google-api-php-client/src/Google' );
		require_once APPPATH . "libraries/google-api-php-client/src/Google/autoload.php";
		require APPPATH . "libraries/google-api-php-client/src/Google/Client.php";
		require APPPATH . "libraries/google-api-php-client/src/Google/Service/Oauth2.php";
		
		// Store values in variables from project created in Google Developer Console
		// I guess the correct way to load laod it from CI config/account
		$client_id = '';
		$client_secret = '';
		$redirect_uri = '';
		
		// Create Client Request to access Google API
		$client = new Google_Client ();
		$client->setApplicationName ( "A3M with OAuth2 support" );
		$client->setClientId ( $client_id );
		$client->setClientSecret ( $client_secret );
		$client->setRedirectUri ( $redirect_uri );
		$client->addScope ( "email" );
		// OpenID 2.0 Backward compatiblity (getting the same openid_id):
		// In order to get the same openid_id (provider_id) as the one, that is already stored for existing users in DB,
		// you'll need to use EXACTLY the same openid.realm value as you used during the initial OpenID2 flows
		// Source: http://stackoverflow.com/a/23051643/524743 
		//         http://stackoverflow.com/q/29229204/524743
		$client->setOpenidRealm ( $redirect_uri ); // needed to get openid id
		                                           
		// Enable SSL?
		maintain_ssl ( $this->config->item ( "ssl_enabled" ) );
		
		// Get OpenID store object
		$store = new Auth_OpenID_FileStore ( $this->config->item ( "openid_file_store_path" ) );
		
		// Get OpenID consumer object
		$consumer = new Auth_OpenID_Consumer ( $store );
		
		// Begin OpenID authentication process
		$objOAuthService = new Google_Service_Oauth2 ( $client );
		
		if (! isset ( $authURL )) // avoiding login with expired access token
			unset ( $_SESSION ['access_token'] );
			
			// Add Access Token to Session
		if (isset ( $_GET ['code'] )) {
			$client->authenticate ( $_GET ['code'] );
			$_SESSION ['access_token'] = $client->getAccessToken ();
			header ( 'Location: ' . filter_var ( $redirect_uri, FILTER_SANITIZE_URL ) );
		}
		
		// Set Access Token to make Request
		if (isset ( $_SESSION ['access_token'] ) && $_SESSION ['access_token']) {
			$client->setAccessToken ( $_SESSION ['access_token'] );
			$openid_id = $this->getOpenIDFromToken ( $client, $client->getAccessToken () );
		}
		
		// Get User Data from Google and store them in $data
		if ($client->getAccessToken ()) {
			$userData = $objOAuthService->userinfo->get ();
			$data ['userData'] = $userData;
			$_SESSION ['access_token'] = $client->getAccessToken ();
			$openid_id = $this->getOpenIDFromToken ( $client, $client->getAccessToken () );
		} 

		else { // will redirect to google login page
			$authUrl = $client->createAuthUrl ();
			$data ['authUrl'] = $authUrl;
			header ( 'Location:' . $authUrl );
			die (); // it makes redirection work :)  
		}
		
		if (isset ( $userData )) { // if authenticantion vs. google succeeded, we can process to sign in procedure
			// Check if user has connect google to a3m
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
					
					if ($userData) {
						$email = $userData->getEmail ();
						$openid_google = array('fullname' => $userData->getName (),
						'gender' => $userData->getGender (),
						'language' => $userData->getLocale (),
						'firstname' => $userData->getGivenName (), // google only
						'lastname' => $userData->getFamilyName (), // google only
						);
					}
					
					// Store user's google data in session
					$this->session->set_userdata ( 'connect_create', array (
							array (
									'provider' => 'openid',
									'provider_id' => isset ( $openid_id ) ? $openid_id : NULL,
									'email' => isset ( $email ) ? $email : NULL 
							),
							$openid_google 
					) );
					
					// Create a3m account
					redirect ( 'account/connect_create' );
				} else {
					// Connect google to a3m
					$this->account_openid_model->insert ( $openid_id, $this->session->userdata ( 'account_id' ) );
					$this->session->set_flashdata ( 'linked_info', sprintf ( lang ( 'linked_linked_with_your_account' ), lang ( 'connect_google' ) ) );
					redirect ( 'account/account_linked' );
				}
			}
		}  // Auth_OpenID_CANCEL or Auth_OpenID_FAILURE or anything else
else {
			$this->authentication->is_signed_in () ? redirect ( 'account/account_linked' ) : redirect ( 'account/sign_up' );
		}
	}
}


/* End of file connect_google.php */
/* Location: ./application/account/controllers/connect_google.php */
