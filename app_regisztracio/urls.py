from django.urls import path

from . import views


urlpatterns = [
    path("login/", views.szlg_oidc_login, name="szlg_oidc_login"),
    path("callback/", views.szlg_oidc_callback, name="szlg_oidc_callback"),
]
