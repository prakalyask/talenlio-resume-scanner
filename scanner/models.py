# scanner/models.py
from django.db import models
from django.conf import settings
import os


class Document(models.Model):
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='documents'
    )
    title = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to='documents/')
    extracted_text = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)
    # New fields for AI results
    gemini_score = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True)
    gemini_response = models.TextField(null=True, blank=True)
    resume_summary = models.TextField(
        null=True, blank=True)  # New field for summary

    def __str__(self):
        return self.title if self.title else f"Doc_{self.pk} by {self.uploaded_by.username}"

    def delete(self, *args, **kwargs):
        # For admin hard deletion: remove file from disk.
        file_path = self.file.path
        super().delete(*args, **kwargs)
        if os.path.exists(file_path):
            os.remove(file_path)


class ScanLog(models.Model):
    """
    Logs each document scan or upload event, so we can track usage.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    document = models.ForeignKey(
        Document, on_delete=models.CASCADE, null=True, blank=True)
    credits_used = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        doc_info = f"Doc {self.document.id}" if self.document else "No doc"
        return f"ScanLog: {self.user.username} used {self.credits_used} credits on {doc_info} at {self.timestamp}"
