"""SZLG+ OpenID Connect client setup."""

import local_settings
from authlib.integrations.django_client import OAuth
from django.urls import reverse


DEFAULT_DISCOVERY_URL = (
    "https://sso.szlg.info/o/.well-known/openid-configuration"
)


def _setting(name, default=""):
    value = getattr(local_settings, name, default)
    return value.strip() if isinstance(value, str) else ""


CLIENT_ID = _setting("SZLG_OIDC_CLIENT_ID")
CLIENT_SECRET = _setting("SZLG_OIDC_CLIENT_SECRET")
DISCOVERY_URL = _setting("SZLG_OIDC_DISCOVERY_URL", DEFAULT_DISCOVERY_URL)
if not DISCOVERY_URL:
    DISCOVERY_URL = DEFAULT_DISCOVERY_URL

oauth = OAuth()
oauth.register(
    name="szlg",
    client_id=CLIENT_ID or None,
    client_secret=CLIENT_SECRET or None,
    server_metadata_url=DISCOVERY_URL,
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",
    },
)


class OIDCNotConfigured(Exception):
    """Raised when the confidential SZLG+ client credentials are missing."""


def get_szlg_oidc_client():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise OIDCNotConfigured
    return oauth.create_client("szlg")


def get_szlg_oidc_redirect_uri(request):
    """Use an explicit registered URI, or derive it from the incoming request."""
    configured_uri = _setting("SZLG_OIDC_REDIRECT_URI")
    if configured_uri:
        return configured_uri
    return request.build_absolute_uri(reverse("szlg_oidc_callback"))
