# users/credit_utils.py

from django.http import JsonResponse
from django.utils import timezone


def check_and_deduct_credits(user, cost=1, action="upload"):
    """
    1) Resets user's credits if it's a new day.
    2) Checks if user has enough credits.
    3) Deducts the cost from their credits.
    Returns a tuple: (success_boolean, response_if_error)
    """
    user.reset_credits_if_new_day()  # ensures daily reset

    if user.credits < cost:
        return (False, JsonResponse({
            'status': 'error',
            'message': 'Insufficient credits.'
        }, status=400))

    user.credits -= cost
    user.save()

    return (True, None)
