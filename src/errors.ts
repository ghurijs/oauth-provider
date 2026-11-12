import { GhuriError } from '@ghuri/core'

/** OAuth 2.1 / RFC 6749 error codes, plus RFC 8707 `invalid_target` and RFC 7591 registration errors. */
export type OAuth2ErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'invalid_target'
  | 'access_denied'
  | 'login_required'
  | 'consent_required'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'unsupported_token_type'
  | 'invalid_redirect_uri'
  | 'invalid_client_metadata'
  | 'slow_down'

/** A protocol error answered as `{ error, error_description }` (or a redirect with them). */
export class OAuth2Error extends GhuriError {
  constructor(
    readonly error: OAuth2ErrorCode,
    readonly description: string,
    readonly status = 400,
  ) {
    super(description)
  }

  toJSON(): Record<string, string> {
    return { error: this.error, error_description: this.description }
  }
}
