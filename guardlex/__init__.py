"""What counts as an authorization check, in one place, across five languages.

Every rule records the specific case that forced it, which is the whole
discipline: a rule added "just in case" cannot be checked, cannot be removed
safely, and quietly widens into a filter that silences real findings.

    from guardlex import is_guarded, RULES
    guarded, rule = is_guarded(function_body)
"""

from __future__ import annotations

__version__ = "1.0.0"

from .rules import (ADMIN_GATE, ANON_AUTHED, ANON_CTX, ANON_REG, ANON_RET,
                    AUTHZ_CALL, AUTHZ_PREDICATE, CAP_RANK, CASES,
                    CONTEXT_RULES, HARDENING_COMMIT, INBAND_AUTH, JS_PAIRS,
                    NONCE_GUARD, PRE_AUTH, PUBLIC_SCOPE, RULES, SELF_SCOPE,
                    SERVER_PATH, TEST_PATH, cap_rank, chia_p2p_handlers,
                    chia_transport_authenticated, django_anonymous_views,
                    go_unauthed_handlers, grape_anonymous_routes, is_guarded,
                    is_preauth_endpoint, is_plugin_namespaced_capability,
                    model_validates_invariant, rails_anonymous_actions,
                    rails_callbacks_for, selftest, selftest_js_pairs)

__all__ = [
    "is_guarded", "RULES", "CONTEXT_RULES", "CASES", "JS_PAIRS", "selftest",
    "selftest_js_pairs", "cap_rank", "is_plugin_namespaced_capability",
    "is_preauth_endpoint", "rails_anonymous_actions", "rails_callbacks_for",
    "grape_anonymous_routes", "chia_p2p_handlers",
    "chia_transport_authenticated", "django_anonymous_views",
    "go_unauthed_handlers", "model_validates_invariant",
    "PRE_AUTH", "INBAND_AUTH", "SELF_SCOPE", "PUBLIC_SCOPE", "ADMIN_GATE",
    "AUTHZ_PREDICATE", "AUTHZ_CALL", "SERVER_PATH", "HARDENING_COMMIT",
    "TEST_PATH", "NONCE_GUARD", "CAP_RANK", "ANON_REG", "ANON_AUTHED",
    "ANON_CTX", "ANON_RET", "__version__",
]
