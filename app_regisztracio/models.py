from django.conf import settings
from django.db import models


class SzlgPlusIdentity(models.Model):
    """A validated SZLG+ OIDC subject linked to one local Django account."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="szlgplus_identity",
    )
    issuer = models.URLField(max_length=255)
    subject = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("issuer", "subject"),
                name="appreg_szlgplus_issuer_subject_unique",
            )
        ]

    def __str__(self):
        return f"SZLG+ identity for user {self.user_id}"
