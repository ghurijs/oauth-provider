# @ghuri/oauth-provider

An **OAuth 2.1 authorization server** for [Ghuri](https://github.com/ghurijs/ghuri), in the style of
[django-oauth-toolkit](https://django-oauth-toolkit.readthedocs.io): let Claude.ai, ChatGPT, Claude Code and Codex (or
any OAuth client) connect to your MCP server or API with the user's consent. Runs on Cloudflare Workers + D1 and on
Node + Postgres / SQLite; tokens never sit in the database in usable form.

> Status: alpha (`0.1.0-alpha.0`). APIs may change.

```bash
npm install @ghuri/oauth-provider @ghuri/oauth
```

## What you get

- `authorize/` with PKCE (`S256` only), a default consent page or your own consent handler, RFC 9207 `iss`
- `token/` (authorization code, rotating refresh tokens with reuse detection), `revoke_token/` (RFC 7009),
  `register/` (RFC 7591 dynamic registration)
- Client ID Metadata Documents (URL `client_id`s, fetched with SSRF protection and cached)
- RFC 8414 discovery, RFC 8707 audience-bound RFC 9068 JWT access tokens, loopback redirects on any port
- `Application`, `Grant`, `AuthorizationCode`, `RefreshToken` models with migrations, admin pages and `cleartokens`

## Quick start: an MCP server with OAuth

```ts title="src/settings.ts"
import { OAuth2ProviderConfig } from '@ghuri/oauth-provider'

INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, AgentsConfig, OAuth2ProviderConfig],
MIDDLEWARE: [SessionMiddleware, CsrfMiddleware, AuthenticationMiddleware],
OAUTH2_PROVIDER: { SCOPES: { 'theme:read': 'Read your theme', 'theme:write': 'Edit your theme' } },
```

```ts title="src/urls.ts"
import { McpServer, tool } from '@ghuri/agents'
import { oauth2ProviderUrls, oauth2WellKnownUrls, verifyAccessToken } from '@ghuri/oauth-provider'

const mcp = new McpServer({
  tools: [tool({ name: 'theme_get', description: 'Read the theme', scopes: ['theme:read'], execute })],
  oauth: { verifyAccessToken },
})

export const urlpatterns = [
  path('accounts/', include(authUrls)),           // login page for the consent step
  path('oauth/', include(oauth2ProviderUrls)),    // authorize/, token/, revoke_token/, register/
  path('mcp/', mcp.urls),
  path('', include(oauth2WellKnownUrls)),         // /.well-known/oauth-authorization-server
  path('', include(mcp.wellKnownUrls)),           // /.well-known/oauth-protected-resource/mcp
]
```

Run `npx ghuri migrate`, deploy, and paste `https://your.site/mcp/` into the client.

## Your own consent step

```ts
OAUTH2_PROVIDER: {
  CONSENT_HANDLER: async (ctx) => {
    if (!ctx.form) return renderConsentPage(ctx)          // post `request` (ctx.pending) back to ctx.action
    if (!('allow' in ctx.form)) return ctx.deny()
    return ctx.approve({ scope: ctx.request.scopes, props: { storeId: ctx.form.store } })
  },
}
```

`props` are stored on the grant and returned by `verifyAccessToken()` (`request.auth.props` in MCP tools and REST views).

## REST APIs

```ts
import { OAuth2Authentication, TokenHasScope } from '@ghuri/oauth-provider/rest'

class ApiAuth extends OAuth2Authentication { audience = 'https://your.site/api' }
class ThemeView extends APIView {
  authenticationClasses = [ApiAuth]
  permissionClasses = [TokenHasScope]
  requiredScopes = ['theme:write']
}
```

## Admin

```ts
import '@ghuri/oauth-provider/admin'   // Applications, Grants (with "Revoke selected grants"), tokens
```

Full guide, client setup (Claude.ai, ChatGPT, Claude Code, Codex) and every setting: the Ghuri docs,
*Topics → MCP server with OAuth*.

## License

MIT
