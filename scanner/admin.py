# scanner/admin.py
from django.contrib import admin
from .models import Document,  ScanLog


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'uploaded_by', 'uploaded_at')
    search_fields = ('title', 'uploaded_by__username')


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "document", "credits_used", "timestamp")
