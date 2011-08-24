<?php defined('SYSPATH') or die('No direct script access.');

/**
 * Interface for oauth2 access token model
 *
 * @package   OAuth2
 * @category  Model_Interface
 * @author    Managed I.T.
 * @copyright (c) 2011 Managed I.T.
 * @license   https://github.com/managedit/kohana-oauth2/blob/master/LICENSE.md
 */
interface Kohana_Model_OAuth2_Interface_Auth_Code
{
	/**
	 * Find a auth code
	 *
	 * @param string $code      code to find
	 * @param int    $client_id client id to pair with
	 * 
	 * @return Model_OAuth2_Auth_Code
	 */
	public static function find_code($code, $client_id = NULL);

	/**
	 * Create a auth code
	 *
	 * @param int    $client_id    client id to create with
	 * @param string $redirect_uri redirect uri to create with
	 * @param int    $user_id      the user id to create with
	 * @param string $scope        scope to create with
	 * 
	 * @return Model_OAuth2_Auth_Code
	 */
	public static function create_code(
		$client_id, $redirect_uri, $user_id = NULL, $scope = NULL
	);

	/**
	 * Deletes a auth code
	 * 
	 * @param string $code the code to delete
	 */
	public static function delete_code($code);
}