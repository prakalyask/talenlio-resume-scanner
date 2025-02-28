# scanner/urls.py
from django.urls import path
from .views import (
    upload_document_view,
    list_documents_view,
    matches_view,
    upload_document_ui_view,
    list_documents_ui_view,
    matches_ui_view,
    delete_document_ui_view,
    score_document_view,
)

urlpatterns = [
    path('upload/', upload_document_view, name='upload_document'),
    path('documents/', list_documents_view, name='list_documents'),
    path('matches/<int:doc_id>/', matches_view, name='matches_view'),

    path('ui/upload/', upload_document_ui_view, name='upload_document_ui'),
    path('ui/documents/', list_documents_ui_view, name='list_documents_ui'),
    path('ui/matches/<int:doc_id>/', matches_ui_view, name='matches_ui'),
    path('ui/documents/<int:doc_id>/delete/',
         delete_document_ui_view, name='delete_document_ui'),
    path('ui/documents/<int:doc_id>/score/',
         score_document_view, name='score_document_ui'),
]
