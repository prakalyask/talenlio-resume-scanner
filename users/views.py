# users/views.py
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import User
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model

from .models import User, CreditRequest
from .credit_utils import check_and_deduct_credits

import matplotlib.pyplot as plt
from io import BytesIO
import base64
import json

from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponseForbidden
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from django.views.decorators.csrf import requires_csrf_token
from django.template import Context, Template
from django.db.models import Count, Sum
from scanner.models import ScanLog, Document
import collections
import re

import csv
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from scanner.models import ScanLog


@requires_csrf_token
def custom_csrf_failure_view(request, reason="", template_name="403_csrf.html"):
    """
    Return a JSON response instead of the default HTML page.
    """
    return JsonResponse({
        "status": "error",
        "message": "CSRF verification failed. Reason: " + str(reason)
    }, status=403)


User = get_user_model()


def auth_page_view(request):
    """
    Renders the authentication page.
    If the user is logged in, show the logout section.
    Otherwise, show both the login and signup forms.
    Any messages or errors are passed via the context.
    """
    context = {}
    if request.user.is_authenticated:
        context['logged_in'] = True
        context['username'] = request.user.username
        return redirect('/users/profile/')
    else:
        context['logged_in'] = False
    # Pass any additional messages if present in context
    return render(request, 'auth_page.html', context)


@csrf_exempt  # Remove this if you add CSRF tokens to your forms
def auth_post_view(request):
    """
    Handles POST requests for login and signup without redirecting.
    Re-renders the same page with error or success messages.
    Expects a hidden input 'form_type' with values 'login' or 'signup'.
    """
    context = {}
    if request.user.is_authenticated:
        context['logged_in'] = True
        context['username'] = request.user.username
        context['message'] = "You are already logged in. Please logout first to switch accounts."
        return redirect('/users/profile/')

    if request.method == "POST":
        form_type = request.POST.get('form_type')
        if form_type == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                context['logged_in'] = True
                context['username'] = user.username
                context['message'] = f"Welcome back, {user.username}!"
                return redirect('/users/profile/')
            else:
                context['error'] = "Invalid username or password."
                context['logged_in'] = False
        elif form_type == 'signup':
            username = request.POST.get('username')
            password = request.POST.get('password')
            if User.objects.filter(username=username).exists():
                context['error'] = f"Username '{username}' is already taken. Please choose another."
                context['logged_in'] = False
            else:
                user = User.objects.create_user(
                    username=username, password=password)
                login(request, user)
                context['logged_in'] = True
                context['username'] = user.username
                context['message'] = f"Account created for {user.username}! You are now logged in."
                return redirect('/users/profile/')
        else:
            context['error'] = "Unknown form type submitted."
            context['logged_in'] = False
    else:
        context['error'] = "Invalid request method."
    return render(request, 'auth_page.html', context)


def logout_view(request):
    """
    Logs out the user and re-renders the auth page with a logout message.
    """
    logout(request)
    context = {
        'logged_in': False,
        'message': "You have been logged out."
    }
    return redirect('/users/auth/')


@csrf_exempt
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            return JsonResponse({'status': 'error', 'message': 'Username and password required.'}, status=400)

        user = User.objects.create_user(username=username, password=password)
        login(request, user)

        return JsonResponse({'status': 'success', 'message': 'User registered.'})

    return JsonResponse({'message': 'Please send a POST request to register.'})


@csrf_exempt
def login_view(request):
    """
    Logs in a user with username/password.
    Uses Django's session-based authentication by default.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'status': 'success', 'message': 'Logged in.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid credentials.'}, status=401)

    return JsonResponse({'message': 'Please send a POST request to login.'})


# @csrf_exempt
# def logout_view(request):
#     """
#     Logs out the currently logged-in user.
#     """
#     logout(request)
#     return JsonResponse({'status': 'success', 'message': 'Logged out.'})


@csrf_exempt
@login_required
def profile_view(request):
    """
    Shows the authenticated user's profile info:
    username, role, credits, etc.
    """
    user = request.user  # This is our custom User
    data = {
        'username': user.username,
        'role': user.role,
        'credits': user.credits,
    }
    return JsonResponse({'status': 'success', 'data': data})


@login_required
def admin_dashboard_view(request):
    """
    Example of a protected admin-only view.
    Returns 'Access denied' if role != 'admin'.
    """
    if request.user.role != 'admin':
        return HttpResponseForbidden('Access denied.')

    # Example data you might return for an admin dashboard
    total_users = User.objects.count()
    admins = User.objects.filter(role='admin').count()
    regular_users = User.objects.filter(role='regular').count()

    return JsonResponse({
        'status': 'success',
        'data': {
            'total_users': total_users,
            'admin_users': admins,
            'regular_users': regular_users
        }
    })


@csrf_exempt
@login_required
def request_credits_view(request):
    """
    Endpoint: POST /users/credits/request
    Regular user requests additional credits.
    Body: { "requested_credits": 50 }  (example)
    """
    if request.method == 'POST':
        # If your front-end uses JSON, parse it:
        requested_credits = request.POST.get('requested_credits')
        if not requested_credits:
            return JsonResponse({'status': 'error', 'message': 'requested_credits is required.'}, status=400)

        try:
            requested_credits = int(requested_credits)
        except ValueError:
            return JsonResponse({'status': 'error', 'message': 'requested_credits must be an integer.'}, status=400)

        # Create a pending CreditRequest
        credit_req = CreditRequest.objects.create(
            user=request.user,
            requested_credits=requested_credits
        )

        return JsonResponse({
            'status': 'success',
            'message': 'Credit request submitted.',
            'request_id': credit_req.id
        })

    return JsonResponse({'status': 'error', 'message': 'Use POST to request credits.'}, status=405)


@login_required
def list_credit_requests_view(request):
    """
    Endpoint: GET /users/credits/requests
    Admin user can list all requests. Regular user can list only their own requests.
    """
    # first ensure we reset credits if new day, for a consistent user state
    request.user.reset_credits_if_new_day()

    if request.user.role == 'admin':
        # Admin sees all requests
        all_requests = CreditRequest.objects.all().order_by('-created_at')
    else:
        # Regular user sees only their own
        all_requests = request.user.credit_requests.all().order_by('-created_at')

    data = []
    for req in all_requests:
        data.append({
            'id': req.id,
            'user': req.user.username,
            'requested_credits': req.requested_credits,
            'status': req.status,
            'created_at': req.created_at,
            'reviewed_at': req.reviewed_at
        })

    return JsonResponse({'status': 'success', 'requests': data})


@csrf_exempt
@login_required
def approve_credit_request_view(request, request_id):
    """
    Endpoint: POST /users/credits/requests/<request_id>/approve
    Only admin can approve. This adds the credits to the user.
    """
    request.user.reset_credits_if_new_day()

    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")

    credit_req = get_object_or_404(CreditRequest, id=request_id)
    if credit_req.status != 'pending':
        return JsonResponse({
            'status': 'error',
            'message': 'Request is not in pending state.'
        }, status=400)

    # Approve and add credits
    credit_req.status = 'approved'
    credit_req.reviewed_at = timezone.now()
    credit_req.save()

    user = credit_req.user
    user.reset_credits_if_new_day()
    user.credits += credit_req.requested_credits
    user.save()

    return JsonResponse({
        'status': 'success',
        'message': f'Approved request. User {user.username} now has {user.credits} credits.'
    })


@login_required
def deny_credit_request_view(request, request_id):
    """
    Endpoint: POST /users/credits/requests/<request_id>/deny
    Only admin can deny the request.
    """
    request.user.reset_credits_if_new_day()

    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")

    credit_req = get_object_or_404(CreditRequest, id=request_id)
    if credit_req.status != 'pending':
        return JsonResponse({
            'status': 'error',
            'message': 'Request is not in pending state.'
        }, status=400)

    credit_req.status = 'denied'
    credit_req.reviewed_at = timezone.now()
    credit_req.save()

    return JsonResponse({'status': 'success', 'message': 'Credit request denied.'})

# Example "Scan Document" endpoint that deducts 1 credit:
# (We'll do the full scanning logic in Step 4, but here's how credits might be deducted.)


@csrf_exempt
@login_required
def scan_document_view(request):
    """
    Endpoint: POST /users/scan
    Deducts 1 credit from the logged-in user if available.
    """
    if request.method == 'POST':
        success, error_response = check_and_deduct_credits(
            request.user, cost=1)
        if not success:
            return error_response  # e.g. insufficient credits

        # TODO: handle actual file upload & scanning logic in Step 4
        return JsonResponse({'status': 'success', 'message': 'Document scanned, 1 credit deducted.'})

    return JsonResponse({'status': 'error', 'message': 'Use POST to scan a document.'}, status=405)


@login_required
def analytics_view(request):
    """
    Renders an analytics dashboard using Chart.js with animations.
    Accessible only to admin users.
    Generates:
      - Daily Scans Activity (Line Chart)
      - Top Users by Scans (Bar Chart)
      - Most Common Document Topics (Pie Chart)
      - Credit Request Status Distribution (Pie Chart)
    """
    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")

    # 1) Daily Scans Activity
    scans_per_day_qs = (
        ScanLog.objects
        .extra(select={'day': "DATE(timestamp)"})
        .values('day')
        .order_by('day')
        .annotate(count=Count('id'))
    )
    daily_scans_data = []
    for entry in scans_per_day_qs:
        # entry["day"] is assumed to be a string like "2025-02-27"
        daily_scans_data.append(
            {"date": entry["day"], "scans": entry["count"]})

    # 2) Top Users by Scans
    top_users_qs = (
        ScanLog.objects
        .values('user__username')
        .annotate(total_scans=Count('id'))
        .order_by('-total_scans')[:10]
    )
    top_users_data = []
    for entry in top_users_qs:
        top_users_data.append(
            {"username": entry["user__username"], "total_scans": entry["total_scans"]})

    # 3) Most Common Document Topics (from Document.extracted_text)
    all_texts = Document.objects.values_list('extracted_text', flat=True)
    word_count = collections.Counter()
    for txt in all_texts:
        if txt:
            words = re.findall(r"\w+", txt.lower())
            word_count.update(words)
    top_words = word_count.most_common(10)
    topics_data = [{"word": word, "frequency": freq}
                   for word, freq in top_words]

    # 4) Credit Request Status Distribution
    credit_status_qs = (
        CreditRequest.objects
        .values('status')
        .annotate(total=Count('id'))
    )
    credit_status_data = [{"status": entry['status'].title(
    ), "total": entry['total']} for entry in credit_status_qs]

    context = {
        "daily_scans_data": json.dumps(daily_scans_data),
        "top_users_data": json.dumps(top_users_data),
        "topics_data": json.dumps(topics_data),
        "credit_status_data": json.dumps(credit_status_data),
    }
    return render(request, "analytics.html", context)


@login_required
def user_dashboard_view(request):
    """
    Renders the main dashboard after login.
    Shows user profile, available credits, and role-based options.
    """
    user = request.user
    context = {
        'username': user.username,
        'role': user.role,
        'credits': user.credits,
    }
    return render(request, 'dashboard.html', context)


def auth_page_view(request):
    """
    Renders the Login & Signup UI page.
    If the user is already logged in, redirect them to the dashboard.
    """
    if request.user.is_authenticated:
        # Redirect logged-in users to dashboard
        return redirect('/users/profile/')
    # Ensure the template exists
    return render(request, 'auth_page.html')


# users/views.py

# ... (existing imports and views)

@login_required
def credit_request_ui_view(request):
    """
    Renders a UI page for regular users to submit a credit request
    and view their own credit request history.
    """
    # For regular users, fetch only their own requests.
    credit_requests = request.user.credit_requests.all().order_by('-created_at')
    context = {
        'credit_requests': credit_requests,
    }
    return render(request, 'users/credit_request.html', context)


@login_required
def manage_credit_requests_ui_view(request):
    """
    Renders a UI page for admin users to view and manage all credit requests.
    Only admin users can access this page.
    """
    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")
    credit_requests = CreditRequest.objects.all().order_by('-created_at')
    context = {
        'credit_requests': credit_requests,
    }
    return render(request, 'users/manage_credit_requests.html', context)


@login_required
def credit_request_ui_view(request):
    """
    Renders a UI page for regular users to submit a credit request and view their past requests.
    If a POST is submitted, process the request and redirect to the result page.
    """
    if request.method == "POST":
        requested_credits = request.POST.get('requested_credits')
        if not requested_credits:
            msg = "Requested credits is required."
            return redirect(f'/users/credits/result/?msg={msg}')
        try:
            requested_credits = int(requested_credits)
        except ValueError:
            msg = "Requested credits must be an integer."
            return redirect(f'/users/credits/result/?msg={msg}')

        # Create the credit request
        credit_req = CreditRequest.objects.create(
            user=request.user,
            requested_credits=requested_credits
        )
        msg = f"Credit request submitted successfully (ID: {credit_req.id})."
        return redirect(f'/users/credits/result/?msg={msg}')
    else:
        # GET: Display form and list past requests
        credit_requests = request.user.credit_requests.all().order_by('-created_at')
        context = {'credit_requests': credit_requests}
        return render(request, 'users/credit_request.html', context)


@login_required
def credit_result_view(request):
    """
    Renders a UI page that displays a result message after a credit request action.
    """
    message = request.GET.get('msg', '')
    return render(request, 'users/credit_result.html', {'message': message})


@login_required
def approve_credit_request_ui_view(request, request_id):
    """
    Admin UI view to approve a credit request.
    Redirects to the result page with a message.
    """
    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")
    credit_req = get_object_or_404(CreditRequest, id=request_id)
    if credit_req.status != 'pending':
        msg = "Request is not pending."
        return redirect(f'/users/credits/result/?msg={msg}')

    credit_req.status = 'approved'
    credit_req.reviewed_at = timezone.now()
    credit_req.save()

    user = credit_req.user
    user.reset_credits_if_new_day()
    user.credits += credit_req.requested_credits
    user.save()

    msg = f"Approved request #{credit_req.id}. User {user.username} now has {user.credits} credits."
    return redirect(f'/users/credits/result/?msg={msg}')


@login_required
def deny_credit_request_ui_view(request, request_id):
    """
    Admin UI view to deny a credit request.
    Redirects to the result page with a message.
    """
    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")
    credit_req = get_object_or_404(CreditRequest, id=request_id)
    if credit_req.status != 'pending':
        msg = "Request is not pending."
        return redirect(f'/users/credits/result/?msg={msg}')

    credit_req.status = 'denied'
    credit_req.reviewed_at = timezone.now()
    credit_req.save()

    msg = f"Denied request #{credit_req.id}."
    return redirect(f'/users/credits/result/?msg={msg}')


@login_required
def user_dashboard_view(request):
    """
    Renders the main dashboard after login.
    Shows user profile, available credits, and role-based options.
    Includes notifications for pending credit requests,
    document uploads, and low credit warnings.
    """
    user = request.user
    notifications = []

    # Notification: Low Credits Warning
    if user.credits < 5:
        notifications.append(
            "Your credits are running low. Consider requesting additional credits.")

    # For regular users: Check for any pending credit requests.
    if user.role == 'regular':
        pending_requests = user.credit_requests.filter(status='pending')
        if pending_requests.exists():
            notifications.append(
                f"You have {pending_requests.count()} pending credit request(s).")
        # Notify the number of documents the user has uploaded.
        doc_count = Document.objects.filter(uploaded_by=user).count()
        if doc_count == 0:
            notifications.append(
                "You haven't uploaded any documents yet. Upload one to see matching results.")
        else:
            notifications.append(
                f"You have uploaded {doc_count} document(s) so far.")

    # For admin users: List all pending credit requests and total documents.
    if user.role == 'admin':
        pending_requests = CreditRequest.objects.filter(status='pending')
        if pending_requests.exists():
            notifications.append(
                f"There are {pending_requests.count()} pending credit request(s).")
        total_docs = Document.objects.count()
        notifications.append(f"Total documents in system: {total_docs}.")

    context = {
        'username': user.username,
        'role': user.role,
        'credits': user.credits,
        'notifications': notifications,
    }
    return render(request, 'dashboard.html', context)


@login_required
def export_scan_history(request):
    """
    Exports the current user's scan history as a CSV file.
    """
    # Query scan logs for the logged-in user, ordered by timestamp descending.
    logs = ScanLog.objects.filter(user=request.user).order_by('-timestamp')

    # Create the HttpResponse object with CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan_history_{request.user.username}.csv"'

    writer = csv.writer(response)
    # Write CSV header
    writer.writerow(['Timestamp', 'Document ID', 'Credits Used'])

    for log in logs:
        writer.writerow([
            log.timestamp,
            log.document.id if log.document else 'N/A',
            log.credits_used
        ])

    return response


@login_required
def export_scan_history_ui_view(request):
    return render(request, 'users/export_scan_history.html')


def is_admin(user):
    return user.is_authenticated and user.role == 'admin'


@user_passes_test(is_admin)
def delete_user_account(request, user_id):
    """
    Admin-only view to delete a user account.
    - If the admin tries to delete their own account, returns an error.
    - On POST, deletes the specified user account.
    """
    if request.method == "POST":
        user_to_delete = get_object_or_404(User, id=user_id)
        if user_to_delete == request.user:
            return JsonResponse({
                'status': 'error',
                'message': 'You cannot delete your own account.'
            }, status=400)
        username = user_to_delete.username
        user_to_delete.delete()
        return JsonResponse({
            'status': 'success',
            'message': f'User "{username}" has been deleted.'
        })
    return JsonResponse({'status': 'error', 'message': 'Use POST to delete a user account.'}, status=405)


@login_required
def manage_users_view(request):
    # Only allow admin users to access this page
    if request.user.role != 'admin':
        return HttpResponseForbidden("Access denied. Admins only.")

    # Get all users (you can adjust this query as needed)
    users = User.objects.all().order_by('username')
    context = {'users': users}
    return render(request, 'users/manage_users.html', context)
