# users/urls.py
from django.urls import path
from .views import (
    register_view,
    login_view,
    logout_view,
    profile_view,
    user_dashboard_view,
    admin_dashboard_view,  # if you have this
    request_credits_view,
    list_credit_requests_view,
    approve_credit_request_view,
    deny_credit_request_view,
    scan_document_view,
    analytics_view,
    #     login_page,
    #     signup_page
    auth_post_view,
    auth_page_view,
    credit_request_ui_view,
    manage_credit_requests_ui_view,
    approve_credit_request_ui_view,
    deny_credit_request_ui_view,
    manage_credit_requests_ui_view,
    credit_result_view,
    export_scan_history,
    export_scan_history_ui_view,
    delete_user_account,
    manage_users_view,
)

urlpatterns = [
    path('credits/result/', credit_result_view, name='credit_result'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', user_dashboard_view, name='profile'),

    # Optional admin dashboard route
    path('admin_dashboard/', admin_dashboard_view, name='admin_dashboard'),

    path('credits/request/', request_credits_view, name='request_credits'),
    path('credits/requests/', list_credit_requests_view,
         name='list_credit_requests'),
    path('credits/requests/<int:request_id>/approve',
         approve_credit_request_view, name='approve_credit_request'),
    path('credits/requests/<int:request_id>/deny',
         deny_credit_request_view, name='deny_credit_request'),

    # Example scanning endpoint
    path('scan/', scan_document_view, name='scan_document'),
    path("analytics/", analytics_view, name="analytics_view"),
    #     path('login_page/', login_page, name='login_page'),
    #     path('signup_page/', signup_page, name='signup_page'),
    # GET => Renders the page
    path('auth/', auth_page_view, name='auth_page'),
    # POST => Handles login/signup
    path('auth/post/', auth_post_view, name='auth_post'),
    # UI for credit requests:
    path('credits/request/ui/', credit_request_ui_view, name='credit_request_ui'),
    # Admin UI for managing credit requests:
    path('credits/manage/ui/', manage_credit_requests_ui_view,
         name='manage_credit_requests_ui'),

    path('credits/manage/ui/', manage_credit_requests_ui_view,
         name='manage_credit_requests_ui'),
    path('credits/requests/<int:request_id>/approve/ui/',
         approve_credit_request_ui_view, name='approve_credit_request_ui'),
    path('credits/requests/<int:request_id>/deny/ui/',
         deny_credit_request_ui_view, name='deny_credit_request_ui'),

    path('export/scan_history/', export_scan_history, name='export_scan_history'),
    path('export/scan_history/ui/', export_scan_history_ui_view,
         name='export_scan_history_ui'),
    path('delete/<int:user_id>/', delete_user_account, name='delete_user_account'),
    path('manage/users/', manage_users_view, name='manage_users'),
]
