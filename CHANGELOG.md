# Changelog

## 0.1.0-alpha.0

- Initial alpha: an OAuth 2.1 authorization server in the style of django-oauth-toolkit (app label
  `oauth2_provider`, `OAUTH2_PROVIDER` settings, `oauth2_provider_*` tables), built for remote MCP servers
  (Claude.ai, ChatGPT, Claude Code, Codex) and APIs, on Workers + D1 and Node + Postgres / SQLite.
- Endpoints (`oauth2ProviderUrls`): `authorize/` (code flow, PKCE `S256` only, RFC 9207 `iss` on every response,
  login redirect, pluggable consent step with `approve({ scope, props })`), `token/` (`authorization_code`,
  `refresh_token` with rotation and reuse detection; `none`, `client_secret_basic`, `client_secret_post`),
  `revoke_token/` (RFC 7009), `register/` (RFC 7591, rate-limited); `oauth2WellKnownUrls`: RFC 8414 metadata
  (`client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported`) and a JWKS for
  asymmetric keys.
- Client ID Metadata Documents: URL `client_id`s fetched with SSRF guards (https only, no IP literals / internal
  hosts, no redirects, 5 KB, 5 s), `client_id` must equal the URL, cached as `Application` rows per `Cache-Control`.
- RFC 8707 resource indicators: access tokens are RFC 9068 JWTs with `aud` = the resource; `verifyAccessToken(token,
  { audience })` checks signature, expiry, audience and (by default) that the grant is still active.
- Models `Application`, `Grant` (user consent with scopes, resource and `props`), `AuthorizationCode`, `RefreshToken`;
  codes, refresh tokens and secrets are stored only as SHA-256 hashes. Loopback redirect URIs match on any port.
- `@ghuri/oauth-provider/admin` (with a "Revoke selected grants" action), `@ghuri/oauth-provider/rest`
  (`OAuth2Authentication`, `TokenHasScope`), `ghuri cleartokens`.
