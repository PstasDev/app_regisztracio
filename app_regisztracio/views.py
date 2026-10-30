import secrets

from authlib.integrations.base_client.errors import OAuthError
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login as auth_login
from django.contrib.auth.models import Group, User
from django.db import IntegrityError, transaction
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render, resolve_url
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET
from requests.exceptions import RequestException
from validate_email import validate_email
from seged import tagja

from .models import SzlgPlusIdentity
from .oidc import (
    OIDCNotConfigured,
    get_szlg_oidc_client,
    get_szlg_oidc_redirect_uri,
)


OIDC_NEXT_SESSION_KEY = "szlg_oidc_next_urls"
MAX_PENDING_OIDC_LOGINS = 10


def _safe_next_url(request, candidate):
    default_url = resolve_url(settings.LOGIN_REDIRECT_URL)
    if not isinstance(candidate, str) or not candidate:
        return default_url
    if url_has_allowed_host_and_scheme(
        candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return candidate
    return default_url


def _remember_next_url(request, state, candidate):
    pending = request.session.get(OIDC_NEXT_SESSION_KEY, {})
    if not isinstance(pending, dict):
        pending = {}
    while len(pending) >= MAX_PENDING_OIDC_LOGINS:
        pending.pop(next(iter(pending)))
    pending[state] = _safe_next_url(request, candidate)
    request.session[OIDC_NEXT_SESSION_KEY] = pending


def _pop_next_url(request, state):
    pending = request.session.get(OIDC_NEXT_SESSION_KEY, {})
    if not isinstance(pending, dict):
        request.session.pop(OIDC_NEXT_SESSION_KEY, None)
        return _safe_next_url(request, None)

    target = pending.pop(state, None) if isinstance(state, str) else None
    if pending:
        request.session[OIDC_NEXT_SESSION_KEY] = pending
    else:
        request.session.pop(OIDC_NEXT_SESSION_KEY, None)
    return _safe_next_url(request, target)


def _claim_text(claims, name, max_length):
    value = claims.get(name)
    return value[:max_length] if isinstance(value, str) else ""


def _profile_from_claims(claims):
    return {
        "email": _claim_text(claims, "email", 254),
        "first_name": _claim_text(claims, "given_name", 150),
        "last_name": _claim_text(claims, "family_name", 150),
    }


def _user_for_szlg_identity(issuer, subject, claims):
    identity = (
        SzlgPlusIdentity.objects.select_related("user")
        .filter(issuer=issuer, subject=subject)
        .first()
    )
    if identity:
        return identity.user

    UserModel = get_user_model()
    profile = _profile_from_claims(claims)
    identity_query = SzlgPlusIdentity.objects.select_related("user")

    # A concurrent first sign-in for the same subject may win the unique
    # constraint. In that case, discard this transaction and use its identity.
    for _ in range(3):
        try:
            with transaction.atomic():
                identity = identity_query.filter(
                    issuer=issuer, subject=subject
                ).first()
                if identity:
                    return identity.user

                user = UserModel.objects.create_user(
                    username=f"szlgplus_{secrets.token_hex(16)}",
                    password=None,
                    **profile,
                )
                group, _ = Group.objects.get_or_create(
                    name="idegen_regisztralo"
                )
                user.groups.add(group)
                identity = SzlgPlusIdentity.objects.create(
                    user=user,
                    issuer=issuer,
                    subject=subject,
                )
            return identity.user
        except IntegrityError:
            identity = identity_query.filter(
                issuer=issuer, subject=subject
            ).first()
            if identity:
                return identity.user

    raise RuntimeError("Could not create the SZLG+ identity.")


@require_GET
def szlg_oidc_login(request):
    try:
        client = get_szlg_oidc_client()
    except OIDCNotConfigured:
        return HttpResponse(
            "Az SZLG+ bejelentkezés nincs konfigurálva a local_settings.py fájlban.",
            status=503,
        )

    state = secrets.token_urlsafe(32)
    _remember_next_url(request, state, request.GET.get("next"))
    try:
        return client.authorize_redirect(
            request,
            get_szlg_oidc_redirect_uri(request),
            state=state,
        )
    except (OAuthError, RequestException):
        _pop_next_url(request, state)
        messages.error(
            request,
            "Az SZLG+ bejelentkezést most nem sikerült elindítani. Próbáld újra később.",
        )
        return redirect("login")


@require_GET
def szlg_oidc_callback(request):
    try:
        client = get_szlg_oidc_client()
        token = client.authorize_access_token(request)
    except OIDCNotConfigured:
        return HttpResponse(
            "Az SZLG+ bejelentkezés nincs konfigurálva a local_settings.py fájlban.",
            status=503,
        )
    except (OAuthError, RequestException):
        _pop_next_url(request, request.GET.get("state"))
        messages.error(
            request,
            "Az SZLG+ bejelentkezés nem sikerült vagy megszakadt. Próbáld újra.",
        )
        return redirect("login")

    next_url = _pop_next_url(request, request.GET.get("state"))
    userinfo = token.get("userinfo")
    if not userinfo or not hasattr(userinfo, "get"):
        return HttpResponseBadRequest("Hiányzó SZLG+ felhasználói adatok.")

    issuer = userinfo.get("iss")
    subject = userinfo.get("sub")
    if (
        not isinstance(issuer, str)
        or not issuer
        or len(issuer) > 255
        or not isinstance(subject, str)
        or not subject
        or len(subject) > 255
    ):
        return HttpResponseBadRequest("Érvénytelen SZLG+ azonosító.")

    user = _user_for_szlg_identity(issuer, subject, userinfo)
    if not user.is_active:
        messages.error(
            request,
            "Ehhez a helyi fiókhoz jelenleg nem lehet bejelentkezni.",
        )
        return redirect("login")

    profile = _profile_from_claims(userinfo)
    for field, value in profile.items():
        setattr(user, field, value)
    user.save(update_fields=list(profile))

    request.session.cycle_key()
    auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return redirect(next_url)


def regisztracio(request):
    if request.user.is_authenticated:
        return render(request, 'regisztracio/visszajelzes.html', {
                    'hosszu': f'Sőt, be is van jelentkezve, {request.user.last_name} {request.user.first_name}.',
                    'rovid': 'Már regisztrált az oldalra.',
                })

    if request.method == "GET":
        return redirect("https://sso.szlg.info/register/")
    


def valaszto(request):
    context = {
        'linkek': [
        ]
        }
    
    if request.user.is_authenticated:
        if tagja(request.user, 'admin'):
            context['linkek'].append(
                {'url': 'admin', 'nev': 'Adminisztráció', }         # fix
                )
    else:
        context['linkek'] += [
            {'url': 'regisztracio', 'nev': 'Regisztráció', },       # fix
            {'url': 'accounts/login', 'nev': 'Bejelentkezés', },    # fix
        ]

    return render(request, "regisztracio/valaszto.html", context)
