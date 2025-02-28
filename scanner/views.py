import google.generativeai as genai
# import google.generativeai as palm  # Use the recommended import alias
from .models import Document, ScanLog
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.utils import timezone
from django.conf import settings
from django.shortcuts import render
from django.shortcuts import redirect

import re

from users.credit_utils import check_and_deduct_credits
from .models import Document
from .utils import extract_text_from_docx, naive_extract_text_from_pdf

from django.db.models import Count, Sum
from datetime import timedelta

from django.shortcuts import get_object_or_404

# from google.generativeai import Client


import os
import math


@csrf_exempt
@login_required
def upload_document_view(request):
    """
    POST /scanner/upload/
    Form-data:
      file: <file.pdf or file.docx>
      title: optional
    Deduct 1 credit, store the file, extract text if docx or pdf (naively), save to Document model.
    """
    if request.method == 'POST':
        # 1) Deduct 1 credit
        success, error_response = check_and_deduct_credits(
            request.user, cost=1)
        if not success:
            return error_response  # e.g. insufficient credits

        # 2) Check if a file is provided
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return HttpResponseBadRequest("No file uploaded.")

        title = request.POST.get('title', '')
        file_name = uploaded_file.name.lower()

        # 3) Create Document object
        doc = Document.objects.create(
            uploaded_by=request.user,
            title=title,
            file=uploaded_file,
            uploaded_at=timezone.now(),
        )

        extracted_text = ""

        # 4) Extract text if DOCX or PDF
        if file_name.endswith('.docx'):
            try:
                extracted_text = extract_text_from_docx(doc.file.path)
            except Exception as e:
                print("Error extracting from DOCX:", e)

        elif file_name.endswith('.pdf'):
            try:
                extracted_text = naive_extract_text_from_pdf(doc.file.path)
            except Exception as e:
                print("Error extracting from PDF:", e)

        # 5) Save extracted text
        doc.extracted_text = extracted_text
        doc.save()

        return JsonResponse({
            'status': 'success',
            'message': f'Document uploaded & 1 credit deducted. (Extension: {file_name})',
            'doc_id': doc.id
        })

    return JsonResponse({'message': 'Use POST to upload a document.'}, status=405)


@login_required
def list_documents_view(request):
    """
    GET /scanner/documents/
    Returns a list of documents:
      - If user.role == "admin": returns all documents
      - Otherwise: returns only the documents uploaded by the current user
    """
    if request.method == 'GET':
        # If admin, list all. Else, only user’s own.
        if request.user.role == 'admin':
            docs = Document.objects.all()
        else:
            docs = Document.objects.filter(uploaded_by=request.user)

        data = []
        for d in docs:
            data.append({
                'id': d.id,
                'title': d.title,
                'uploaded_by': d.uploaded_by.username,
                'uploaded_at': d.uploaded_at.isoformat(),
            })

        return JsonResponse({'status': 'success', 'documents': data})

    return JsonResponse({'message': 'Use GET to list documents.'}, status=405)


def simple_similarity(text1, text2):
    """
    Basic cosine similarity based on word frequency.
    This can be replaced with more advanced logic or AI-based matching.
    """
    # Convert to lower and split on whitespace
    words1 = text1.lower().split()
    words2 = text2.lower().split()

    # Count frequency
    freq1 = {}
    freq2 = {}

    for w in words1:
        freq1[w] = freq1.get(w, 0) + 1
    for w in words2:
        freq2[w] = freq2.get(w, 0) + 1

    # Dot product
    all_words = set(freq1.keys()).union(set(freq2.keys()))
    dot = sum(freq1.get(w, 0) * freq2.get(w, 0) for w in all_words)

    # Magnitudes
    mag1 = math.sqrt(sum(val**2 for val in freq1.values()))
    mag2 = math.sqrt(sum(val**2 for val in freq2.values()))

    if mag1 == 0 or mag2 == 0:
        return 0.0
    return dot / (mag1 * mag2)


@login_required
def matches_view(request, doc_id):
    """
    GET /scanner/matches/<doc_id>/
    Returns a list of documents that match the specified doc's text,
    with a similarity_score for each.
    """
    if request.method == 'GET':
        # 1) Fetch the target document
        try:
            target_doc = Document.objects.get(id=doc_id)
        except Document.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Document not found.'}, status=404)

        # 2) If user is not admin, verify they own this document
        if request.user.role != 'admin' and target_doc.uploaded_by != request.user:
            return JsonResponse({'status': 'error', 'message': 'Access denied.'}, status=403)

        # 3) Compare with other documents to find matches
        all_docs = Document.objects.exclude(id=doc_id)
        results = []

        for d in all_docs:
            if d.extracted_text:  # only compare if the doc has text
                score = simple_similarity(
                    target_doc.extracted_text or "",
                    d.extracted_text or ""
                )
                # We can filter out zero scores or keep them
                if score > 0.0:
                    results.append({
                        'doc_id': d.id,
                        'title': d.title,
                        'uploaded_by': d.uploaded_by.username,
                        'similarity_score': round(score, 3)
                    })

        # 4) Sort matches by descending similarity
        results.sort(key=lambda x: x['similarity_score'], reverse=True)

        return JsonResponse({
            'status': 'success',
            'target_doc': target_doc.title,
            'matches': results
        })

    return JsonResponse({'message': 'Use GET for matches.'}, status=405)


@csrf_exempt
@login_required
def upload_document_view(request):
    """
    POST /scanner/upload/
    Form-data:
      file: <file.pdf or file.docx>
      title: optional
    Deduct 1 credit, store the file, extract text if docx or pdf (naively), save to Document model.
    Also logs the event in ScanLog.
    """
    if request.method == 'POST':
        # 1) Deduct 1 credit
        success, error_response = check_and_deduct_credits(
            request.user, cost=1)
        if not success:
            return error_response

        # 2) Check if a file is provided
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return HttpResponseBadRequest("No file uploaded.")

        title = request.POST.get('title', '')
        file_name = uploaded_file.name.lower()

        # 3) Create Document object
        doc = Document.objects.create(
            uploaded_by=request.user,
            title=title,
            file=uploaded_file,
            uploaded_at=timezone.now(),
        )

        extracted_text = ""

        # 4) Extract text if DOCX or PDF
        if file_name.endswith('.docx'):
            try:
                extracted_text = extract_text_from_docx(doc.file.path)
            except Exception as e:
                print("Error extracting from DOCX:", e)

        elif file_name.endswith('.pdf'):
            try:
                extracted_text = naive_extract_text_from_pdf(doc.file.path)
            except Exception as e:
                print("Error extracting from PDF:", e)

        # 5) Save extracted text
        doc.extracted_text = extracted_text
        doc.save()

        # 6) Log the scan event
        ScanLog.objects.create(
            user=request.user,
            document=doc,
            credits_used=1  # We deducted 1 credit
        )

        return JsonResponse({
            'status': 'success',
            'message': f'Document uploaded & 1 credit deducted. (Extension: {file_name})',
            'doc_id': doc.id
        })

    return JsonResponse({'message': 'Use POST to upload a document.'}, status=405)


# @login_required
# def upload_document_ui_view(request):
#     """
#     Renders the UI for document upload.
#     """
#     return render(request, 'scanner/upload.html')


@login_required
def list_documents_ui_view(request):
    """
    Renders a UI page for listing documents in reverse order (newest first),
    showing only documents that are not marked as deleted.
    """
    if request.user.role == 'admin':
        docs = Document.objects.filter(
            is_deleted=False).order_by('-uploaded_at')
    else:
        docs = Document.objects.filter(
            uploaded_by=request.user, is_deleted=False).order_by('-uploaded_at')
    context = {'documents': docs}
    return render(request, 'scanner/documents_list.html', context)


@login_required
def matches_ui_view(request, doc_id):
    """
    Renders the UI page for document matches.
    """
    target_doc = get_object_or_404(Document, id=doc_id)
    if request.user.role != 'admin' and target_doc.uploaded_by != request.user:
        return HttpResponseForbidden("Access denied.")
    all_docs = Document.objects.exclude(id=doc_id)
    results = []
    for d in all_docs:
        if d.extracted_text:
            score = simple_similarity(
                target_doc.extracted_text or "", d.extracted_text or "")
            if score > 0.0:
                results.append({
                    'doc_id': d.id,
                    'title': d.title,
                    'uploaded_by': d.uploaded_by.username,
                    'similarity_score': round(score, 3)
                })
    results.sort(key=lambda x: x['similarity_score'], reverse=True)
    context = {
        'target_doc': target_doc,
        'matches': results,
    }
    return render(request, 'scanner/matches.html', context)


@login_required
@csrf_exempt  # Remove if you include CSRF tokens in your form
def upload_document_ui_view(request):
    """
    Renders the upload form on GET.
    On POST, processes the document upload, deducts credits, and renders a confirmation page.
    """
    if request.method == 'POST':
        # Deduct credit
        success, error_response = check_and_deduct_credits(
            request.user, cost=1)
        if not success:
            context = {'error': "Insufficient credits."}
            return render(request, 'scanner/upload.html', context)

        # Check for file
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            context = {'error': "No file uploaded."}
            return render(request, 'scanner/upload.html', context)

        title = request.POST.get('title', '')
        file_name = uploaded_file.name.lower()

        # Create a Document object
        doc = Document.objects.create(
            uploaded_by=request.user,
            title=title,
            file=uploaded_file,
            uploaded_at=timezone.now(),
        )

        # Extract text from DOCX or PDF
        extracted_text = ""
        if file_name.endswith('.docx'):
            try:
                extracted_text = extract_text_from_docx(doc.file.path)
            except Exception as e:
                print("Error extracting DOCX:", e)
        elif file_name.endswith('.pdf'):
            try:
                extracted_text = naive_extract_text_from_pdf(doc.file.path)
            except Exception as e:
                print("Error extracting PDF:", e)

        doc.extracted_text = extracted_text
        doc.save()

        # Log the scan event
        ScanLog.objects.create(
            user=request.user,
            document=doc,
            credits_used=1
        )

        # Prepare confirmation message
        context = {
            'message': f"Document '{doc.title or 'Untitled'}' uploaded successfully! (ID: {doc.id})"
        }
        return render(request, 'scanner/upload_result.html', context)

    # GET: Render the upload form
    return render(request, 'scanner/upload.html')


@login_required
@csrf_exempt  # Remove if using CSRF tokens properly in your form.
def delete_document_ui_view(request, doc_id):
    """
    Deletes a document.
    - Admin users: Hard deletion (removes DB record and file from /media).
    - Regular users: Soft deletion (sets is_deleted flag to True).
    After deletion, the page refreshes.
    """
    doc = get_object_or_404(Document, id=doc_id, is_deleted=False)

    # Only the owner or admin can delete the document.
    if request.user.role != 'admin' and doc.uploaded_by != request.user:
        return HttpResponseForbidden("Access denied.")

    if request.user.role == 'admin':
        # Hard delete: removes the document record and deletes the file.
        doc.delete()
        # Optionally: log this deletion in a ScanLog if desired.
    else:
        # Soft delete: mark the document as deleted.
        doc.is_deleted = True
        doc.save()

    return redirect('/scanner/ui/documents/')


def parse_score(response_text):
    """
    Extracts a numerical score from the API response.
    Assumes the response contains a line like "Score: <number>"
    """
    match = re.search(
        r"Score:\s*(\d{1,3}(?:\.\d+)?)", response_text, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return 0.0


def parse_summary(response_text):
    """
    Extracts the summary text from the API response.
    Assumes the response contains a line starting with "Summary:".
    """
    match = re.search(r"Summary:\s*(.*)", response_text,
                      re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""


# @csrf_exempt  # Remove if using CSRF tokens
# @login_required
# def score_document_view(request, doc_id):
#     """
#     Scores the document (resume) using the Gemini API via Google's generativeai package.
#     If a score and summary already exist, returns the cached result.
#     Otherwise, calls the API, stores the result, and returns it as JSON.
#     """
#     doc = get_object_or_404(Document, id=doc_id, is_deleted=False)

#     if request.user.role != 'admin' and doc.uploaded_by != request.user:
#         return HttpResponseForbidden("Access denied.")

#     if doc.gemini_score is not None and doc.resume_summary is not None:
#         # Return cached result
#         return JsonResponse({
#             'gemini_score': float(doc.gemini_score),
#             'gemini_response': doc.gemini_response,
#             'resume_summary': doc.resume_summary,
#         })

#     try:
#         # Configure the client with your API key.
#         palm.configure(api_key="AIzaSyAMqAeKABFjdmWRvSIAh8uxSIXHX9-rMCU")
#         prompt = (
#             "Rate this resume out of 100 and provide a concise summary of the resume. "
#             "Use the extracted text below:\n" + (doc.extracted_text or "")
#         )
#         response = palm.generate_text(
#             model="gemini-2.0-flash-lite",
#             prompt=prompt,
#             temperature=0
#         )
#         # or response['text'] depending on the API response structure
#         full_response = response.text

#         score = parse_score(full_response)
#         summary = parse_summary(full_response)

#         # Cache the results in the document record.
#         doc.gemini_score = score
#         doc.gemini_response = full_response
#         doc.resume_summary = summary
#         doc.save()

#         return JsonResponse({
#             'gemini_score': score,
#             'gemini_response': full_response,
#             'resume_summary': summary,
#         })
#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)

@login_required
def score_document_view(request, doc_id):
    """
    Scores the document using the Gemini API.
    If a score and summary already exist, returns the cached result.
    Otherwise, calls the Gemini API, stores and returns the result.
    Only the owner or an admin can access.
    """
    doc = get_object_or_404(Document, id=doc_id, is_deleted=False)

    if request.user.role != 'admin' and doc.uploaded_by != request.user:
        return HttpResponseForbidden("Access denied.")

    # If results are already cached, return them
    if doc.gemini_score is not None and doc.resume_summary is not None:
        return JsonResponse({
            'gemini_score': float(doc.gemini_score),
            'gemini_response': doc.gemini_response,
            'resume_summary': doc.resume_summary,
        })

    try:
        # Configure the Google Generative AI with your API key
        import google.generativeai as genai
        genai.configure(api_key="AIzaSyAMqAeKABFjdmWRvSIAh8uxSIXHX9-rMCU")

        # Create the model
        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = (
            "Rate this resume out of 100 and provide a concise summary of the resume. "
            "Use the extracted text below:\n" + (doc.extracted_text or "")
        )

        # Generate content using the model
        response = model.generate_content(prompt)
        full_response = response.text

        score = parse_score(full_response)
        summary = parse_summary(full_response)

        # Store the results in the document
        doc.gemini_score = score
        doc.gemini_response = full_response
        doc.resume_summary = summary
        doc.save()

        return JsonResponse({
            'gemini_score': score,
            'gemini_response': full_response,
            'resume_summary': summary,
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
