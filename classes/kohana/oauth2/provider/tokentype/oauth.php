<?php defined('SYSPATH') or die('No direct script access.');

/**
 * OAuth token support
 *
 * @link       http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer
 * @package    OAuth2
 * @category   Library
 * @author     Managed I.T.
 * @copyright  (c) 2011 Managed I.T.
 * @license    https://github.com/managedit/kohana-oauth2/blob/master/LICENSE.md
 */
abstract class Kohana_OAuth2_Provider_TokenType_OAuth extends Kohana_OAuth2_Provider_TokenType_Bearer {

	const TOKEN_TYPE = 'OAuth';

	/**
	 * Get the name for this token type
	 *
	 * @return string
	 */
	public function get_token_type()
	{
		return OAuth2_Provider_TokenType_OAuth::TOKEN_TYPE;
	}

	protected function _find_token_string()
	{
		$authorization_header = $this->_request->headers('authorization');

		$header = preg_match('/^OAuth (.*)/i', $authorization_header, $matches);

		if ($header)
		{
			return $matches[1];
		}
		/**
		 * There are some PITA sections of the spec to check for..
		 *
		 * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2
		 * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3
		 */
		else if ($this->_request->post('access_token') !== NULL)
		{
			return  $this->_request->post('access_token');
		}
		else if ($this->_request->query('access_token') !== NULL)
		{
			return $this->_request->query('access_token');
		}
		else
		{
			throw new OAuth2_Exception_InvalidToken('The access token provided is expired, revoked, malformed, or invalid for other reasons.');
		}
	}

	/**
	 * Get the additional params for this token type
	 *
	 * @return array
	 */
	public function get_token_params()
	{
		return array(
			'token_type' => OAuth2_Provider_TokenType_OAuth::TOKEN_TYPE,
		);
	}
}
