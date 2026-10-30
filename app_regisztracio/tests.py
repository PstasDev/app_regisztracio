from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.urls import reverse


ISSUER = "https://sso.szlg.info/o"


class SzlgOIDCTests(TestCase):
    def _userinfo(self, **overrides):
        claims = {
            "iss": ISSUER,
            "sub": "szlg-subject-123",
            "email": "student@example.org",
            "email_verified": True,
            "given_name": "Teszt",
            "family_name": "Diák",
        }
        claims.update(overrides)
        return claims

    def _set_pending_state(self, state, next_url="/"):
        session = self.client.session
        session["szlg_oidc_next_urls"] = {state: next_url}
        session.save()

    def test_login_page_offers_szlg_plus(self):
        response = self.client.get(reverse("login"))

        self.assertContains(response, "Bejelentkezés SZLG+-szal")

    @patch("app_regisztracio.views.get_szlg_oidc_client")
    def test_login_uses_registered_callback_and_remembers_local_next(self, get_client):
        oidc_client = Mock()
        oidc_client.authorize_redirect.return_value = HttpResponseRedirect(
            "https://sso.szlg.info/o/authorize/"
        )
        get_client.return_value = oidc_client

        response = self.client.get(
            reverse("szlg_oidc_login"), {"next": "/codeweek/"}
        )

        self.assertEqual(response.status_code, 302)
        _, callback_uri = oidc_client.authorize_redirect.call_args.args
        state = oidc_client.authorize_redirect.call_args.kwargs["state"]
        self.assertEqual(
            callback_uri,
            "http://testserver/auth/oidc/callback/",
        )
        self.assertTrue(state)
        self.assertEqual(
            self.client.session["szlg_oidc_next_urls"][state], "/codeweek/"
        )

    @patch("app_regisztracio.views.get_szlg_oidc_client")
    def test_login_ignores_external_next_url(self, get_client):
        oidc_client = Mock()
        oidc_client.authorize_redirect.return_value = HttpResponseRedirect(
            "https://sso.szlg.info/o/authorize/"
        )
        get_client.return_value = oidc_client

        self.client.get(
            reverse("szlg_oidc_login"), {"next": "https://attacker.example/"}
        )

        state = oidc_client.authorize_redirect.call_args.kwargs["state"]
        self.assertEqual(self.client.session["szlg_oidc_next_urls"][state], "/")

    @patch("app_regisztracio.views.get_szlg_oidc_client")
    def test_callback_creates_user_and_reuses_issuer_subject_identity(self, get_client):
        oidc_client = Mock()
        oidc_client.authorize_access_token.return_value = {
            "userinfo": self._userinfo()
        }
        get_client.return_value = oidc_client

        self._set_pending_state("state-one", "/codeweek/")
        response = self.client.get(
            reverse("szlg_oidc_callback"),
            {"state": "state-one", "code": "authorization-code"},
        )

        self.assertRedirects(response, "/codeweek/", fetch_redirect_response=False)
        User = get_user_model()
        user_id = self.client.session["_auth_user_id"]
        user = User.objects.get(pk=user_id)
        self.assertEqual(user.email, "student@example.org")
        self.assertEqual(user.first_name, "Teszt")
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.groups.filter(name="idegen_regisztralo").exists())

        oidc_client.authorize_access_token.return_value = {
            "userinfo": self._userinfo(email="updated@example.org")
        }
        self._set_pending_state("state-two")
        response = self.client.get(
            reverse("szlg_oidc_callback"),
            {"state": "state-two", "code": "another-code"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))
        user.refresh_from_db()
        self.assertEqual(user.email, "updated@example.org")
        self.assertEqual(user.szlgplus_identity.subject, "szlg-subject-123")
        self.assertEqual(User.objects.count(), 1)

    @patch("app_regisztracio.views.get_szlg_oidc_client")
    def test_callback_does_not_link_an_existing_account_by_email(self, get_client):
        User = get_user_model()
        existing_user = User.objects.create_user(
            username="student@example.org",
            email="student@example.org",
            password="local-password",
        )
        oidc_client = Mock()
        oidc_client.authorize_access_token.return_value = {
            "userinfo": self._userinfo()
        }
        get_client.return_value = oidc_client
        self._set_pending_state("state-one")

        response = self.client.get(
            reverse("szlg_oidc_callback"),
            {"state": "state-one", "code": "authorization-code"},
        )

        self.assertEqual(response.status_code, 302)
        sso_user = User.objects.get(pk=self.client.session["_auth_user_id"])
        self.assertNotEqual(sso_user.pk, existing_user.pk)
        self.assertEqual(sso_user.email, existing_user.email)
        self.assertTrue(existing_user.has_usable_password())

    @patch("app_regisztracio.views.get_szlg_oidc_client")
    def test_callback_rejects_missing_subject(self, get_client):
        oidc_client = Mock()
        oidc_client.authorize_access_token.return_value = {
            "userinfo": {"iss": ISSUER}
        }
        get_client.return_value = oidc_client

        response = self.client.get(
            reverse("szlg_oidc_callback"),
            {"state": "state-one", "code": "authorization-code"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(get_user_model().objects.count(), 0)
