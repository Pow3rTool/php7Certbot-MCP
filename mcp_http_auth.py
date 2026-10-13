"""Bearer authentication for MCP HTTP discovery and execution.

Vendored across the production MCPs. Token verification and per-tool authorization
remain service-owned. No SDK upgrade, session-format change, or new OAuth issuer.
"""
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse


@dataclass(frozen=True)
class HTTPAuth:
    resource: str
    tenant: str
    scope: str
    verify: Callable[[str], object]

    def __post_init__(self):
        url = urlsplit(self.resource)
        if (url.scheme != "https" or not url.hostname or url.username or
                url.password or url.query or url.fragment or
                any(c in self.resource for c in '\r\n"\\')):
            raise ValueError("MCP resource must be a fixed HTTPS URL")

    @property
    def metadata_url(self):
        url = urlsplit(self.resource)
        return f'{url.scheme}://{url.netloc}/.well-known/oauth-protected-resource{url.path.rstrip("/")}'


class HTTPBearerMiddleware:
    def __init__(self, app, *, config: HTTPAuth):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        # nginx's legacy `location /name` + proxy_pass .../ introduces a second
        # slash for /name/.well-known/... . Only this fixed public metadata path
        # is aliased; no general path rewriting or unauthenticated MCP bypass.
        if scope['path'] in ('/.well-known/oauth-protected-resource',
                             '//.well-known/oauth-protected-resource'):
            if scope['method'] not in ('GET', 'HEAD'):
                response = JSONResponse({'error': 'method_not_allowed'}, status_code=405,
                                        headers={'Allow': 'GET, HEAD', 'Cache-Control': 'no-store'})
            else:
                response = JSONResponse({
                    'resource': self.config.resource,
                    'authorization_servers': [f'https://login.microsoftonline.com/{self.config.tenant}/v2.0'],
                    'scopes_supported': [self.config.resource.rstrip('/') + '/' + self.config.scope],
                    'bearer_methods_supported': ['header'],
                }, headers={'Cache-Control': 'no-store'})
                if scope['method'] == 'HEAD':
                    response.body = b''
            return await response(scope, receive, send)

        headers = [value for name, value in scope.get('headers', []) if name.lower() == b'authorization']
        token = ''
        if len(headers) == 1:
            auth = headers[0].decode('latin-1')
            scheme, _, value = auth.partition(' ')
            if scheme.lower() == 'bearer':
                token = value.strip()
        identity = None
        if token and len(token) <= 65536:
            try:
                identity = await run_in_threadpool(self.config.verify, token)
            except Exception:
                # A verifier/JWKS failure must not disclose details or fall open.
                identity = None
        if identity is None:
            challenge = f'Bearer resource_metadata="{self.config.metadata_url}"'
            if headers:
                challenge += ', error="invalid_token"'
            response = JSONResponse({'error': 'invalid_token'}, status_code=401,
                                    headers={'WWW-Authenticate': challenge, 'Cache-Control': 'no-store'})
            return await response(scope, receive, send)

        # Do not cache identity in the MCP session. Every HTTP request is checked,
        # and the existing handlers continue to enforce their own roles and OBO.
        async def no_store(message):
            if message['type'] == 'http.response.start':
                message['headers'] = [(k, v) for k, v in message.get('headers', [])
                                      if k.lower() != b'cache-control']
                message['headers'].append((b'cache-control', b'no-store'))
            await send(message)
        return await self.app(scope, receive, no_store)


class AuthenticatedFastMCP(FastMCP):
    """Protect both supported HTTP app factories, including mcp.run()."""
    def __init__(self, *args, http_auth: HTTPAuth, **kwargs):
        self.http_auth = http_auth
        super().__init__(*args, **kwargs)

    def streamable_http_app(self):
        app = super().streamable_http_app()
        app.add_middleware(HTTPBearerMiddleware, config=self.http_auth)
        return app

    def sse_app(self, mount_path=None):
        app = super().sse_app(mount_path)
        app.add_middleware(HTTPBearerMiddleware, config=self.http_auth)
        return app
