import user_agents
from django.contrib.auth import get_user_model, signals
from django.db import transaction
from django.utils.module_loading import import_string

from easyaudit.middleware.easyaudit import get_current_request
from easyaudit.models import LoginEvent
from easyaudit.settings import (
    DATABASE_ALIAS,
    LOGGING_BACKEND,
    REMOTE_ADDR_HEADER,
    WATCH_AUTH_EVENTS,
)

audit_logger = import_string(LOGGING_BACKEND)()


def user_logged_in(sender, request, user, **kwargs):
    user_agent_string = request.META.get("HTTP_USER_AGENT")
    user_agent_info = user_agents.parse(user_agent_string)
    try:
        with transaction.atomic(using=DATABASE_ALIAS):
            login_event = audit_logger.login(
                {
                    "login_type": LoginEvent.LOGIN
                    if not user_agent_info.is_mobile
                    else LoginEvent.LOGIN_MOBILE,
                    "username": getattr(user, user.USERNAME_FIELD),
                    "user_id": getattr(user, "id", None),
                    "remote_ip": request.META[REMOTE_ADDR_HEADER],
                }
            )
    except:
        pass


def user_logged_out(sender, request, user, **kwargs):
    try:
        with transaction.atomic(using=DATABASE_ALIAS):
            login_event = audit_logger.login(
                {
                    "login_type": LoginEvent.LOGOUT,
                    "username": getattr(user, user.USERNAME_FIELD),
                    "user_id": getattr(user, "id", None),
                    "remote_ip": request.META[REMOTE_ADDR_HEADER],
                }
            )
    except:
        pass


def user_login_failed(sender, credentials, **kwargs):
    try:
        with transaction.atomic(using=DATABASE_ALIAS):
            request = (
                get_current_request()
            )  # request argument not available in django < 1.11
            user_model = get_user_model()
            login_event = audit_logger.login(
                {
                    "login_type": LoginEvent.FAILED,
                    "username": credentials[user_model.USERNAME_FIELD],
                    "remote_ip": request.META[REMOTE_ADDR_HEADER],
                }
            )
    except:
        pass


if WATCH_AUTH_EVENTS:
    signals.user_logged_in.connect(
        user_logged_in, dispatch_uid="easy_audit_signals_logged_in"
    )
    signals.user_logged_out.connect(
        user_logged_out, dispatch_uid="easy_audit_signals_logged_out"
    )
    signals.user_login_failed.connect(
        user_login_failed, dispatch_uid="easy_audit_signals_login_failed"
    )
