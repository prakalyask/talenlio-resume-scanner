# users/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import date


class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('regular', 'Regular'),
    )

    role = models.CharField(
        max_length=10, choices=ROLE_CHOICES, default='regular')
    credits = models.IntegerField(default=20)
    last_reset_date = models.DateField(null=True, blank=True,
                                       help_text="Tracks the last date when daily credits were reset.")

    def __str__(self):
        return f"{self.username} ({self.role})"

    def reset_credits_if_new_day(self):
        """
        Checks if today's date is different from last_reset_date.
        If yes, reset credits to 20 and update last_reset_date.
        """
        today = date.today()
        if self.last_reset_date != today:
            self.credits = 20
            self.last_reset_date = today
            self.save()


class CreditRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('denied', 'Denied'),
    )

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="credit_requests")
    requested_credits = models.IntegerField()
    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Request from {self.user.username} for {self.requested_credits} credits ({self.status})"
