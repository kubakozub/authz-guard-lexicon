#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What counts as an authorization check, in one place, across five languages.

Every rule here records the specific case that forced it. That is the whole
discipline, and it is not decoration: a rule added "just in case" cannot be
checked, cannot be removed safely, and quietly widens into a filter that
silences real findings.

WHY THIS EXISTS, the cause rather than the symptom. Over one working session I
derived a guard recognition rule in ONE analyzer four separate times and never
carried it to the others. Each time it cost a verification cycle on a lead that
had been false from the start. An audit on 2026-08-25 produced a matrix in which
most of seventeen analyzers had NONE of the seven rules that existed.

Copying regular expressions between files is the cause. One imported module is
the cure: a new rule is one change instead of seven.

TWO FAILURE MODES, and the second is the dangerous one.

A rule that is too narrow produces a false lead, which costs a verification
cycle and is annoying. A rule that is too narrow in the OTHER direction, failing
to recognise a guard that is really there, produces a silent zero: the analyzer
reports nothing and the target reads as hardened. That is worse, because a zero
from an analyzer that does not speak the target's dialect is not a result, and
nothing in the output says so. Several rules below exist only because a silent
zero was traced back to a missing idiom.

Languages and frameworks covered: PHP and WordPress, Ruby on Rails, Grape,
Django and DRF, Go, TypeScript and JavaScript, and the Chia peer to peer
protocol. Standard library only.

    from guardlex import is_guarded, rules
"""
import re

#-------------------------------------------------------------------------
# 1. PRE_AUTH: endpoints that are unauthenticated BY NATURE.
#    Forced by: gitea `/user/forgot_password` and `/user/activate`, then the same
#    names turning up again in a WordPress corpus. You cannot require a login
#    from a login form, so flagging one as missing authorization is always wrong.
#    Note the boundary: an underscore OR a change of case. `resetPassword` in
#    camelCase escaped the version that required underscores.
#-------------------------------------------------------------------------
# Extended 2026-09-20: the boundary is also a DOT, a HYPHEN and a SLASH.
# Forced by Rocket.Chat, where an endpoint name is a route string:
# `users.forgotPassword`, `users.register`, `users.verifyEmail`. Before the dot
# there was no `^`, no `_` and no lower case letter, so the registration screen
# passed straight through the pre-auth filter and landed on the candidate list.
PRE_AUTH = re.compile(
    r'(?i)(^|[_./\-]|(?<=[a-z]))'
    r'(login|logout|signin|sign_in|signup|sign_up|register|registration|'
    r'forgot|reset|recover|activate|verify|confirm|subscribe|unsubscribe|newsletter|'
    r'contact|captcha|nonce|heartbeat|ping|health|robots|favicon|well_known)'
    r'(_|$|[_./\-]|(?=[A-Z]))')

#-------------------------------------------------------------------------
# 2. INBAND_AUTH: authentication by a SECRET IN THE REQUEST rather than by a
#    session or a capability. It is still a guard.
#    Forced by: gitea `hmac.Equal` in DownloadArtifactRaw, evergreen
#    `ValidateSignToken`, and the PHP shape
#    `hash_equals($site_key, $_REQUEST['key'])`.
#    The trap: the first version required `===` or `!==`, three characters, while
#    PHP code in the wild compares with a loose `==`. A token guard written that
#    way was read as "no guard at all".
#-------------------------------------------------------------------------
INBAND_AUTH = re.compile(
    r'hash_equals\s*\(|hash_hmac\s*\(|wp_check_password\s*\(|'
    r'hmac\.Equal\s*\(|subtle\.ConstantTimeCompare|ValidateSignToken|'
    # The identifier length is BOUNDED on purpose. With an unbounded \w* this
    # branch is quadratic in the input: 20000 characters of one word took 6.7
    # seconds, and this module is meant to be run over arbitrary source,
    # including minified JavaScript on a single line. Bounding it to 40 takes
    # the same input to 0.007 seconds, and an identifier with more than 40
    # characters before the keyword does not occur in practice.
    r'\$?\w{0,40}(?:key|token|secret|signature|hash)\b[^\n]{0,60}[=!]==?[^\n]{0,60}\$|'
    r'[=!]==?[^\n]{0,60}\$\w*(?:key|token|secret|signature|hash)\b|'
    r'verify_signature|check_signature|validate_token|verify_token|'
    r'\bstatus_key\b|\bsecret_key\b|\baccess_key\b|'
    # JavaScript and TypeScript: the same shape, a different spelling. Measured on a
    # Node codebase whose webhook receivers for ten different providers all verify
    # their input with an HMAC or a JWT. NONE of those idioms was in the dictionary,
    # so the entire family read as "webhooks with no authentication". Ten false
    # leads from one missing spelling.
    r'timingSafeEqual|createHmac\s*\(|crypto\.subtle\.(?:verify|importKey)|'
    r'jwtVerify\s*\(|jwt\.verify\s*\(|verifyIdToken|verifySignedJwt|createRemoteJWKSet|'
    r'verifyToken|validateToken|verifySignature|checkSignature|verifyWebhook|'
    r'validateSignature|verifyKey|verifyRequestSignature|'
    r'x-hub-signature|x-slack-signature|x-twilio-signature|x-signature-ed25519|'
    r'x-line-signature|x-shopify-hmac|x-vercel-signature', re.I)

#-------------------------------------------------------------------------
# 3. SELF_SCOPE: the query scopes ITSELF by the session's identity.
#    Forced by: Mattermost `Session().UserId` used as the target of the
#    operation, Discourse `Category.secured(guardian)`, Pontoon
#    `visible_for(request.user)`.
#    The absence of an explicit capability check is CORRECT in this shape. There
#    is nothing to escalate to: the query cannot return another user's rows.
#-------------------------------------------------------------------------
SELF_SCOPE = re.compile(
    r'Session\(\)\.UserId|rctx\.Session\(\)|SessionUserId|'
    r'\bcurrent_?[Uu]ser\b|request\.user\b|self\.request\.user\b|'
    r'get_current_user_id\s*\(\)|wp_get_current_user\s*\(\)|'
    # Matomo 5.x: `\bcurrent_?[Uu]ser\b` does NOT match `getCurrentUserLogin`,
    # because there is no word boundary after "get". Three dashboard controller
    # methods scope themselves exactly that way and all three landed on the
    # candidate list.
    r'get(?:Current|Logged)\w*User\w*\s*\(|isUserIs[Aa]nonymous\s*\(|'
    r'getCurrentUser(?:Login|Id|Email)\s*\(|'
    # JavaScript and TypeScript. The trap worth stating plainly: a SOURCE and a
    # GUARD cannot be the same expression. `req.query` and `searchParams.get()` are
    # INPUT, and they are deliberately absent from this table. Only expressions that
    # carry SESSION IDENTITY belong here. Confusing the two turns every handler that
    # reads a parameter into a handler that checks one.
    r'getServerSession\s*\(|\bgetSession\s*\(|\bauth\s*\(\s*\)|'
    r'session\??\.user\??\.id|locals\.user\b|ctx\.session\b|ctx\.user\b|'
    r'event\.context\.(?:auth|user|session)\b|'
    r'\b(?:user|owner|author|account)Id\s*[!=]==\s*(?:session|ctx|auth|token|locals|req|viewer)|'
    r'(?:session|ctx|auth|token|locals|req|viewer)[\w.?]*\s*[!=]==\s*\w*(?:user|owner|author)Id\b',
    re.I)

#-------------------------------------------------------------------------
# 4. PUBLIC_SCOPE: the handler restricts itself to PUBLISHED content.
#    Forced by the WordPress shape
#    `'publish' !== get_post_status($id) || post_password_required($id)`.
#    For an endpoint that is meant to be anonymous this is the RIGHT control, and
#    looking only for `current_user_can` produced a false lead on it.
#-------------------------------------------------------------------------
PUBLIC_SCOPE = re.compile(
    r"get_post_status\s*\(|post_password_required\s*\(|"
    r"['\"]publish['\"]\s*[!=]==?|post_status['\"]?\s*=>\s*['\"]publish|"
    r"is_post_publicly_viewable|->post_status|"
    r"\.publish\b|is_public\b|visibility\s*[:=]+\s*['\"]?public", re.I)

#-------------------------------------------------------------------------
# 5. ADMIN_GATE: the sink sits behind an administrative capability.
#    Forced by a WordPress HTTP proxy that forwards a request built from
#    `$_GET['url']`, cookies included, behind `manage_options`. An administrator
#    can already run arbitrary code, so this is NOT an escalation.
#    Do not silence it outright, LOWER ITS WEIGHT. The gate can disappear in a
#    refactor, and then the same code is a finding.
#-------------------------------------------------------------------------
ADMIN_GATE = re.compile(
    r"current_user_can\s*\(\s*['\"](manage_options|activate_plugins|install_plugins|"
    r"edit_files|update_core|manage_network\w*|setup_network)['\"]|"
    r"PermissionManageSystem|IsSystemAdmin\s*\(\)|is_admin\?|"
    r"authenticated_as_admin!|authenticated_with_can_read_all_resources!|"
    r"ensure_staff!|ensure_admin!", re.I)

#-------------------------------------------------------------------------
# 6. AUTHZ_PREDICATE: a request-supplied id INSIDE a permission call is a guard,
#    not a hole.
#    Forced by an early analyzer flagging
#    `SessionHasPermissionToUserOrBot(sess, c.Params.UserId)`: eight false leads
#    at once. The id from the request is the SUBJECT of the check there, not the
#    source of visibility. Reading "request id reaches a call" as a defect
#    inverts the meaning of the line.
#-------------------------------------------------------------------------
AUTHZ_PREDICATE = re.compile(
    r'^(SessionHasPermissionTo\w*|HasPermissionTo\w*|CheckPermission\w*|'
    r'RequirePermission\w*|Authorize\w*|can_\w+\?|ensure_can_\w+!)$')
# The silent zero, measured. These patterns started out WordPress and Django
# shaped. On Matomo 5.13.0 there are 172 occurrences of six authorization idioms
# (`Piwik::checkUserHasViewAccess`, `hasUserSuperUserAccess` and four more) and
# this table matched NONE of them. The effect was that two differential
# analyzers returned a clean zero on that target, which reads as "the target is
# hardened" and actually meant "the analyzer does not speak this dialect".
# A zero from an analyzer that does not recognise the target's conventions is
# not a result.
#
# The added pattern is GENERAL (check/has/ensure/require, an optional user, then
# access/permission/privilege) rather than specific to one product, because most
# PHP and Java frameworks carry that same shape.
# Recognising more guards RAISES differential sensitivity rather than lowering
# it: without a recognised guard there is no cohort to compare against, so a
# genuine gap next to that guard stays invisible.
AUTHZ_CALL = re.compile(
    r'has_perm|has_permission|check_permission|user_passes_test|'
    r'\bcan_\w+\s*\(|is_authorized|assert_perm|current_user_can\s*\(|'
    r'\b(?:check|has|ensure|require|assert)[A-Za-z]{0,24}'
    r'(?:Access|Permission|Privilege|Capability)\b|'
    r'\bensure_can_\w+!|\bguardian\.\w+|\bcan_\w+\?|'
    # JavaScript and TypeScript: the general pattern already caught `hasPermission`
    # and `checkPermission`, but not the forms with neither word in them, and those
    # are the ones that dominate in Node. The negative controls further down exist to
    # keep `canvas(`, `cancelOrder(`, `durability.` and `oauth()` from passing as
    # guards, because `can` and `auth` as substrings match a great deal of ordinary
    # code.
    r'requireUser\s*\(|requireAuth\s*\(|requireSession\s*\(|requireLogin\s*\(|'
    r'assertCan\s*\(|assertUser\s*\(|assertAuth\s*\(|\bcan\s*\(|\bability\.|'
    r'defineAbility\s*\(|withAuth\s*\(|getServerSession\s*\(|isAuthenticated\b|'
    r'isAuthorized\b|checkAuth\s*\(|ensureSignedIn\s*\(|hasRole\s*\(|canAccess\s*\(',
    re.I)

#-------------------------------------------------------------------------
# 7. SERVER_PATH: the path is generated by the SERVER, not taken from input.
#    Forced by `file_get_contents($temp_file)` where `$temp_file` came from
#    `wp_tempnam(...)`. That function was missing from the table, and it is the
#    commonest way WordPress code names a temporary file.
#-------------------------------------------------------------------------
SERVER_PATH = re.compile(
    r"ABSPATH|WP_CONTENT_DIR|WP_PLUGIN_DIR|__DIR__|__FILE__|dirname\s*\(|"
    r"plugin_dir_path|wp_upload_dir|_DIR\b|_PATH\b|sys_get_temp_dir|tmp_name|"
    r"[$]_FILES|get_temp_dir|upload_path|wp_tempnam|[^_a-z]tempnam\s*\(|"
    r"wp_upload_bits|os\.TempDir\(\)|ioutil\.TempFile|"
    # Added after a false lead: `file_get_contents($path)` where
    # `$path = get_attached_file($id)` is a LOCAL file path and not a URL, so there
    # is no outbound request to speak of. An SSRF analyzer saw a variable in the
    # argument and reported SSRF.
    "get_attached_file|get_theme_file_path|get_stylesheet_directory|get_template_directory|"
    "wp_get_original_image_path|get_home_path|wp_normalize_path|"
    # And again: `wp_remote_get(home_url('/' . $key . '.txt'))`. The target is the
    # site's OWN address, assembled by the server. The caller does not choose the
    # host, so there is no SSRF. The analyzer saw a variable in the argument and
    # reported missing protection.
    "home_url|site_url|admin_url|rest_url|network_(home|site)_url|plugins_url|content_url", re.I)

#-------------------------------------------------------------------------
# 8. HARDENING_COMMIT: a commit that TIGHTENS a guard, not a regression.
#    Forced by a Discourse security commit titled "Restrict chat history reads",
#    where a guard was replaced by a stronger one. A drift analyzer saw the old
#    guard string disappear and reported a regression, which is the opposite of
#    what happened.
#-------------------------------------------------------------------------
HARDENING_COMMIT = re.compile(r'^\s*(SECURITY|FIX|DEV|PERF)\b|harden|utwardz', re.I)

#-------------------------------------------------------------------------
# 9. TEST_PATH: a test file is not attack surface.
#    Forced by a measurement: 33 of 97 leads in one run came out of spec and
#    fixture files. A third of the output was noise from one missing rule.
#-------------------------------------------------------------------------
TEST_PATH = re.compile(
    r'(^|/)(spec|specs|test|tests|__tests__|testdata|fixtures?|factories|e2e|cypress|'
    r'acceptance|features)/|_spec\.|_test\.|\.spec\.|\.test\.|^test_|/conftest\.py$', re.I)


#-------------------------------------------------------------------------
# 10. NONCE_GUARD: nonce verification, INCLUDING through a project's own wrapper.
#    Forced by a plugin that wraps the core check in its own function, so looking
#    only for `wp_verify_nonce` and `check_ajax_referer` missed a guard that was
#    plainly there. This is the "custom wrapper" false positive mode, and the
#    answer is to match ANY name ending in check_nonce, verify_nonce or
#    check_referer rather than the core names alone.
#-------------------------------------------------------------------------
NONCE_GUARD = re.compile(
    r'\b\w*(?:check_nonce|verify_nonce|check_referer|check_admin_referer|'
    r'check_ajax_referer|verify_request_signature)\s*\(|'
    # Matomo `$this->checkTokenInUrl()` is the same CSRF mechanism as WordPress's
    # `check_ajax_referer`. It counts as a NONCE and deliberately NOT as
    # authorization: a CSRF token proves the request was intended, not that the
    # caller is allowed to make it.
    r'\bcheckTokenInUrl\s*\(|\bcheckNonce\s*\(', re.I)


#-------------------------------------------------------------------------
# 11. WORDPRESS CAPABILITY RANKING, in one place.
#    Moved here when a second analyzer needed the same table. Copying a table
#    between files is exactly the cause this module exists to remove.
#    THE RULE: never guess a rank. An unrecognised capability returns None and
#    the caller MUST abstain rather than assume.
#    Measured 2026-08-25: 47% of `current_user_can` calls in the corpus name a
#    capability that is not in any fixed table, including ones plugins define
#    themselves. A default rank turned entire administrative cohorts into "weak",
#    which is the shape of a false positive that looks like a finding.
#-------------------------------------------------------------------------
CAP_RANK = {
    'manage_options': 100, 'activate_plugins': 100, 'install_plugins': 100,
    'update_plugins': 100, 'install_themes': 100, 'switch_themes': 100,
    'edit_files': 100, 'unfiltered_upload': 100, 'manage_network': 100,
    'manage_network_options': 100, 'setup_network': 100, 'export': 90, 'import': 90,
    'unfiltered_html': 80, 'edit_users': 90, 'delete_users': 90, 'create_users': 90,
    'list_users': 70, 'promote_users': 90,
    'edit_others_posts': 70, 'delete_others_posts': 70, 'edit_others_pages': 70,
    'moderate_comments': 60, 'manage_categories': 60, 'edit_pages': 60,
    'publish_posts': 55, 'edit_published_posts': 55, 'publish_pages': 55,
    'upload_files': 50, 'edit_posts': 50, 'delete_posts': 50,
    'read': 10, 'exist': 5, 'subscriber': 10,
}
CAP_STRONG_PAT = re.compile(
    r'^(administrator|super_admin|manage_\w+|install_\w+|activate_\w+|update_\w+|switch_\w+|'
    r'delete_\w*others\w*|edit_\w*others\w*|promote_\w+|remove_\w+|create_users|'
    r'edit_files|unfiltered_\w+|export|import|setup_network)$', re.I)
CAP_WEAK_PAT = re.compile(r'^(read|read_\w+|view_\w+|access_\w+|exist|subscriber)$', re.I)


CORE_LOW = re.compile(r'^(read|edit_posts|delete_posts|upload_files|publish_posts|'
                     r'edit_published_posts|level_[0-9]|exist)$', re.I)


def is_plugin_namespaced_capability(c, prefix, slug):
    """Does this capability belong to the plugin's OWN namespace, as in `acme_settings`?

    Measured 2026-08-25 on a plugin with 69 handlers and 26 distinct capabilities,
    where the commonest were all prefixed with the plugin's own name: it had built
    its own permission model. The abstain rule silenced every one of them, because
    a capability nobody has ranked is unrankable in the absolute.

    But that is exactly where this bug class lives: a handler that FALLS OUT of
    the plugin's own model into a weaker CORE capability. Abstaining there means
    abstaining on the interesting case, so a capability inside the plugin's own
    namespace is ranked relative to that namespace rather than skipped.
    """
    c = c.lower()
    for pref in filter(None, (prefix, slug.replace('-', '_'), slug.replace('-', ''))):
        if c.startswith(pref + '_') or c.startswith(pref):
            return True
    return False


def cap_rank(c):
    """The rank of a capability, or None when it cannot be decided.

    None means abstain. It does not mean weak, and a caller that treats it as
    weak will report entire administrative cohorts as unguarded.
    """
    c = c.lower()
    if c in CAP_RANK:
        return CAP_RANK[c]
    if CAP_STRONG_PAT.match(c):
        return 90
    if CAP_WEAK_PAT.match(c):
        return 10
    return None



#-------------------------------------------------------------------------
# 13. ANON_REG: handler registrations reachable WITHOUT authentication, by language
#
#     Forced by a one line bug in a caller, which had
#         lang = "php" if fn.endswith(".php") else "rb"
#     so EVERY .ts, .go and .py file was parsed with the Ruby rules, while the
#     registration list held four patterns, all of them PHP shaped (wp_ajax_nopriv,
#     permission_callback => __return_true, #[PublicPage], authz:{enabled:false}).
#     On Rails, Grape, Go, Django and Chia targets the check therefore NEVER
#     fired, so the analyzer returned a silent zero across the whole corpus.
#
#     One source of truth: a caller dispatches on language, the rules live here.
#-------------------------------------------------------------------------
ANON_REG = {
    # 13a. PHP. Order AND content must stay as they are: the positive control
    #      for two real projects is calibrated against this exact list, so an
    #      pozytywna (jetpack=1, nextcloud-server=3, reszta 0).
    "php": [
        ("WP_AJAX_NOPRIV", re.compile(
            r"""add_action\(\s*['"]wp_ajax_nopriv_(\w+)['"]\s*,\s*(?:array\s*\(\s*\$this\s*,\s*)?['"]?([\w:]+)?""",
            re.I)),
        ("REST_RETURN_TRUE", re.compile(
            r"""['"]permission_callback['"]\s*=>\s*['"]__return_true['"]""")),
        ("NC_PUBLIC_PAGE", re.compile(r"""#\[PublicPage\]|@PublicPage""")),
        ("AUTHZ_DISABLED", re.compile(r"""authz:\s*\{\s*enabled:\s*false""")),
    ],

    # 13b. Ruby. TWO families share one file extension:
    #      (1) Rails/Discourse: kontroler bez `requires_login` (filtr klasowy
    #          `block_if_requires_login`, application_controller.rb:762),
    #          plus jawne `skip_before_action`.
    #      (2) Grape and GitLab: an API class with no `before { authenticate! }`, or
    #          one using `authenticate_non_get!`, where GET is therefore anonymous.
    "rb": [
        ("RAILS_SKIP_CSRF", re.compile(
            r"^[ \t]*skip_before_action\b[^\n]*:verify_authenticity_token", re.M)),
        ("RAILS_SKIP_LOGIN", re.compile(
            r"^[ \t]*skip_before_action\b[^\n]*"
            r":(?:ensure_logged_in|authenticate_user!|block_if_requires_login|"
            r"redirect_to_login_if_required|verify_authenticated_user|require_login)", re.M)),
        ("RAILS_CONTROLLER", re.compile(
            r"^[ \t]*class\s+([\w:]+Controller)\s*<\s*([\w:]+)", re.M)),
        ("GRAPE_CLASS", re.compile(
            r"^[ \t]*class\s+(\w+)\s*<\s*::?(?:API::Base|Grape::API)", re.M)),
    ],

    # 13c. Python: Django and DRF, plus the Chia peer to peer protocol.
    #      Chia: `@metadata.request(...)` (chia/server/api_protocol.py:61) rejestruje
    #      a method as a protocol message handler. The caller is ANY peer that
    #      completed a TLS handshake, and the certificate is self signed and carries
    #      no role, so the handler is unauthenticated surface by definition.
    "py": [
        ("DJANGO_CSRF_EXEMPT", re.compile(r"^[ \t]*@csrf_exempt\b", re.M)),
        ("DRF_ALLOW_ANY", re.compile(
            r"permission_classes\s*=\s*[\[\(][^\]\)]*AllowAny|"
            r"authentication_classes\s*=\s*[\[\(]\s*[\]\)]")),
        ("DRF_PERM_DECORATOR", re.compile(
            r"^[ \t]*@permission_classes\s*\(\s*[\[\(][^\]\)]*AllowAny", re.M)),
        ("CHIA_P2P_REQUEST", re.compile(
            r"^[ \t]*@(?:metadata|api)\.request\s*\(|^[ \t]*@api_request\s*\(", re.M)),
    ],

    # 13d. Go: a handler registered OUTSIDE the group carrying auth middleware.
    #      Idiom Mattermosta: `APIHandler(h)` (anonim) kontra `APISessionRequired(h)`.
    #      Idiom gitei: `m.Group("/x", func(){...}, reqSignIn)`.
    "go": [
        ("GO_ROUTE_WRAPPED", re.compile(
            r"""\.(?:Handle|HandleFunc|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Any)\s*\(\s*"""
            r"""(?:"[^"]*"\s*,\s*)?(?P<wrap>[\w\.]+)\s*\(\s*(?P<h>[\w\.]+)\s*[\),]""")),
        ("GO_ROUTE_BARE", re.compile(
            r"""\.(?:Handle|HandleFunc|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Any)\s*\(\s*"""
            r""""(?P<path>[^"]*)"\s*,\s*(?P<h>[\w\.]+)\s*[\),]""")),
        ("GO_PUBLIC_COMMENT", re.compile(r"(?i)//\s*(?:no auth|unauthenticated|public endpoint)")),
    ],

    # 13e. TypeScript and JavaScript: decorators and route flags.
    "ts": [
        ("TS_AUTHZ_DISABLED", re.compile(r"authz:\s*\{\s*enabled:\s*false")),
        ("TS_PUBLIC_DECORATOR", re.compile(r"@Public\s*\(\s*\)|@AllowAnonymous\b|@SkipAuth\b")),
        ("TS_UNAUTH_FLAG", re.compile(
            r"(?:requireAuth|authRequired|requiresAuth|authenticated)\s*:\s*false\b")),
    ],
}

# Markers that CONTRADICT anonymity, checked against the body of the handler or
# its class. This is the "the guard lives one layer down" rule, as a table per
# language: a registration can look open while the body, the class, the
# middleware or the transport does the checking.
ANON_AUTHED = {
    "rb": re.compile(
        r"^[ \t]*requires_login\b|"
        r"^[ \t]*before_action\s+:(?:ensure_logged_in|ensure_staff|ensure_admin|"
        r"authenticate_user!|verify_authenticated_user|require_login)|"
        r"\bauthenticate!|\bauthenticate_non_get!|\bauthorize!|\bensure_logged_in\b|"
        r"\bcurrent_user\b|\bguardian\b|\bGuardian\.new\b", re.M),
    "py": re.compile(
        r"@login_required|@staff_member_required|@permission_required|"
        r"IsAuthenticated|IsAdminUser|request\.user\b|self\.request\.user\b|"
        r"\bhas_perm\s*\(|raise\s+PermissionDenied"),
    "go": re.compile(
        r"APISessionRequired|ApiSessionRequired|SessionRequired|RequireSession|"
        r"reqSignIn|reqToken|reqAdmin|mustLogin|RequireSignIn|"
        r"c\.AppContext\.Session\(\)|ctx\.IsSigned|HasPermissionTo"),
    "ts": re.compile(
        r"requireAuth\s*\(|isAuthenticated|assertAuthenticated|ctx\.session|"
        r"req\.session\.user|getServerSession|currentUser\b"),
    "php": re.compile(r"current_user_can|is_user_logged_in|getUID", re.I),
}

# Reading CALLER CONTROLLED context, per language.
ANON_CTX = {
    "php": re.compile(
        r"\$_(GET|POST|REQUEST)\[|params\[|\$request->get|request\.(query|body|params)|"
        r"getParam|->getParam", re.I),
    "rb": re.compile(
        r"\bparams\s*\[|\bparams\.require\b|\bparams\.fetch\b|\bparams\.permit\b|"
        r"\bdeclared_params\b|\bdeclared\(params\)|request\.(?:query_parameters|params)"),
    "py": re.compile(
        r"request\.(?:GET|POST|data|query_params|body)\b|request\.(?:GET|POST|data)\.get|"
        r"\bself\.kwargs\b|\bkwargs\s*\[|\brequest\.\w+\b"),
    # Measured on gitea, which uses NEITHER `mux.Vars` NOR `r.URL.Query()`. It reads
    # through its own context (`ctx.PathParam`, `ctx.FormString`), so
    # 133 rejestracji anonimowych spadalo do 0 na etapie "kontekst z requestu".
    "go": re.compile(
        r"mux\.Vars\s*\(|r\.URL\.Query\s*\(\)|req\.URL\.Query\s*\(\)|c\.Params\b|"
        r"ctx\.Params\b|chi\.URLParam\s*\(|r\.FormValue\s*\(|json\.NewDecoder\s*\(\s*r\.Body|"
        r"\bctx\.(?:PathParam|PathParamInt64|FormString|FormInt|FormInt64|FormBool|FormTrim|"
        r"FormOptionalBool|Req\.URL|Query)\b|\bc\.(?:Params|Query|Param)\b|"
        r"\br\.PathValue\s*\(|\breq\.PathValue\s*\(|\bvars\s*\[|\bweb\.Params\b"),
    # Same shape on Rocket.Chat, which reads `this.queryParams` and
    # `this.bodyParams` rather than `req.query`. Without those names the context
    # stage matched nothing, so the whole platform came back as a silent zero.
    "ts": re.compile(
        r"req\.(?:query|params|body)\b|request\.(?:query|params|body)\b|"
        r"searchParams\.get\s*\(|ctx\.query\b|"
        r"\bthis\.(?:queryParams|bodyParams|urlParams|queryOperations|requestParams)\b|"
        r"\brequestParams\s*\(|\bgetPaginationItems\s*\(|\bc\.req\.(?:query|param|json)\b"),
}

# Returning DATA to the caller, per language.
ANON_RET = {
    "php": re.compile(
        r"wp_send_json|json_encode|render json|->json\(|DataResponse|JSONResponse|"
        r"new JsonResponse|return \$data|wp_die\(json", re.I),
    "rb": re.compile(
        r"\brender\s+json:|\brender_serialized\b|\brender_json_dump\b|\bpresent\s+\w|"
        r"\bMultiJson\.dump\b|\.to_json\b|\brespond_with\b|\brender\s+[^\n]*serializer|"
        r"\bsend_data\b|\bsend_file\b|\brender\s+plain:|\brender\s+body:"),
    "py": re.compile(
        r"\bJsonResponse\s*\(|\bHttpResponse\s*\(|\bResponse\s*\(|\bmake_msg\s*\(|"
        r"\bMessage\s*\(|\bjson\.dumps\s*\(|serializer\.data|\breturn\s+msg\b"),
    "go": re.compile(
        r"\bw\.Write\s*\(|json\.NewEncoder\s*\(\s*w\s*\)|\bctx\.JSON\s*\(|\bc\.JSON\s*\(|"
        r"\bWriteHeader\s*\(|ToJson\s*\(\s*w|\.EncodeJSON|"
        r"\bctx\.(?:HTML|PlainText|PlainTextBytes|ServeContent|ServeFile|RespHeader|Redirect|"
        r"JSONRedirect|Data|Render)\s*\(|\bctx\.Resp\.Write"),
    "ts": re.compile(
        r"res\.json\s*\(|res\.send\s*\(|NextResponse\.json\s*\(|\breturn\s+json\s*\(|"
        r"\bctx\.body\s*=|\bAPI\.v1\.success\s*\(|\bAPI\.v1\.(?:failure|unauthorized)\s*\(|"
        r"\breturn\s*\{\s*(?:statusCode|body)\b|\bc\.json\s*\("),
}

# ---- Pre-authentication paths-------------------------------------------
# Negative control: a login screen is NOT a finding.
# PRE_AUTH patrzy na NAZWE metody i przepuszcza `SessionController#create`,
# because the name `create` contains no hint of a login. A second layer looks at
# the PATH instead.
PREAUTH_PATH = re.compile(
    r"(?:^|/)(?:"
    r"session|sessions|login|logins|logout|signup|sign_up|registration|registrations|"
    r"omniauth|omniauth_callbacks|oauth|oidc|saml|sso|password|passwords|forgot_password|"
    r"invite|invites|activation|activate|confirm|confirmation|email_change|second_factor|"
    r"webauthn|user_api_key|user_api_keys|csrf|static|robots|bootstrap|health|healthcheck|"
    r"metrics|status|manifest|offline|safe_mode|wizard|auth|about|forgot"
    r")(?:_controller|_api|s)?\.(?:rb|py|go|ts|tsx|js|php)$", re.I)


def is_preauth_endpoint(name, path=""):
    """Is this endpoint anonymous BY INTENT: a login, a registration, a health check?

    Two layers, because each one alone let false leads through:
      * the method NAME, as in `forgot_password` or `resetPassword` (PRE_AUTH)
      * the file PATH, as in `app/controllers/session_controller.rb#create`, where
        the method is called plainly `create` and nothing in the name says login.
    """
    if name and PRE_AUTH.search(str(name)):
        return True
    if path and PREAUTH_PATH.search(str(path).replace("\\", "/")):
        return True
    return False


# ---- Rails: who is logged in and who is not-----------------------------
_RAILS_SYMS = re.compile(r"%i\[([^\]]*)\]|%i\(([^\)]*)\)|:(\w+)")
_RAILS_ACTION = re.compile(r"^[ \t]{2,}def\s+(\w[\w?!]*)", re.M)
_RAILS_PRIVATE = re.compile(r"^[ \t]*(?:private|protected)[ \t]*$", re.M)
_RAILS_DECL = re.compile(
    r"^([ \t]*)(module|class)[ \t]+([\w:]+)(?:[ \t]*<[ \t]*([:\w]+))?", re.M)

# Every filter that REQUIRES a logged in user, or a higher role. `requires_login`
# to idiom Discourse'a (application_controller.rb:756), reszta to zwykly Rails.
_RAILS_DIRECTIVE = re.compile(
    r"^[ \t]*(?:(requires_login)|"
    r"(?:prepend_)?before_action[ \t]+:(ensure_logged_in|ensure_admin|ensure_staff|"
    r"authenticate_user!|require_login|verify_authenticated_user|ensure_can_\w+|"
    r"ensure_staff_writes_enabled|ensure_admin_or_self|ensure_owner|"
    r"authorize_\w+!|authenticate_\w+!|require_\w*(?:permission|access|admin|owner)\w*!|"
    r"check_\w*permission\w*!|verify_\w*(?:signature|secret|token)\w*!?|"
    r"validate_\w*(?:token|secret|signature)\w*!?))"
    r"(?P<arg>[^\n]*)$", re.M)


def rails_class_decl(txt):
    """[(fully qualified class, superclass)], honouring `module` nesting.

    Forced by Discourse. Without qualification,
    `Chat::Admin::IncomingWebhooksController` was indexed under the bare key
    `IncomingWebhooksController`, where `Chat::IncomingWebhooksController <
    ApplicationController` already sat. The first entry won, and four actions of
    the ADMIN controller came out as anonymous.
    """
    stack, out = [], []
    for m in _RAILS_DECL.finditer(txt):
        ind = len(m.group(1).expandtabs(4))
        while stack and stack[-1][0] >= ind:
            stack.pop()
        kind, name, sup = m.group(2), m.group(3), m.group(4)
        prefix = "::".join(n for _i, n in stack)
        fq = f"{prefix}::{name}" if prefix else name
        if kind == "class":
            out.append((fq, (sup or "").lstrip(":")))
        stack.append((ind, name))
    return out


def _logical_stmt(txt, start, max_lines=200):
    """One LOGICAL Ruby expression from `start`, which may span several lines.

    Forced by a directive written across multiple lines, as in
    `requires_login only: %i[\n  username\n  update\n]`. A regex anchored on `$`
    saw only `requires_login only: %i[`, read the argument list as empty,
    concluded the whole controller was closed, and lost 38 anonymous actions.

    This is the same failure as a fixed length window: the boundary of the match
    did not coincide with the boundary of the construct.
    """
    depth, i, n, out = 0, start, len(txt), []
    while i < n and len(out) < max_lines:
        j = txt.find("\n", i)
        if j < 0:
            j = n
        line = txt[i:j]
        out.append(line)
        depth += line.count("[") + line.count("(") + line.count("{")
        depth -= line.count("]") + line.count(")") + line.count("}")
        if depth <= 0 and not line.rstrip().endswith(","):
            break
        i = j + 1
    return "\n".join(out)


def rails_guard_directives(txt):
    """[(filter_name, mode, {actions})], where mode is 'all', 'only' or 'except'."""
    out = []
    for m in _RAILS_DIRECTIVE.finditer(txt):
        name = m.group(1) or m.group(2)
        stmt = _logical_stmt(txt, m.start())
        if "only:" in stmt:
            out.append((name, "only", _rails_syms(stmt.split("only:", 1)[1])))
        elif "except:" in stmt:
            out.append((name, "except", _rails_syms(stmt.split("except:", 1)[1])))
        else:
            out.append((name, "all", set()))
    return out


def rails_guarded_actions(all_acts, directives, skips=()):
    """Guarded actions, AFTER subtracting whatever the controller skips.

    Counted PER FILTER rather than globally: `skip_before_action
    :authenticate_user!, only: [:show]` removes that one filter and only for
    `show`, so treating a skip as global closes actions that are still open.
    """
    A = set(all_acts)
    per = {}
    for n, mode, acts in directives:
        cur = per.setdefault(n, set())
        if mode == "all":
            cur |= A
        elif mode == "only":
            cur |= (set(acts) & A)
        elif mode == "except":
            cur |= (A - set(acts))
    for n, mode, acts in skips:
        if n not in per:
            continue
        if mode == "all":
            per[n] = set()
        elif mode == "only":
            per[n] -= set(acts)
        elif mode == "except":
            per[n] &= set(acts)
    g = set()
    for v in per.values():
        g |= v
    return g


def _rails_syms(blob):
    stop = blob.find("]")
    if stop < 0:
        stop = blob.find(")")
    if stop < 0:
        stop = min(len(blob), 3000)
    seg = blob[:stop + 1]
    out = set()
    for a, b, c in _RAILS_SYMS.findall(seg):
        body = a or b or ""
        if body:
            out.update(w for w in body.replace(",", " ").split() if w.isidentifier())
        elif c:
            out.add(c)
    out.discard("only")
    out.discard("except")
    return out


# `skip_before_action :authenticate_user!`. GitLab inverts the default policy:
# ApplicationController ma `before_action :authenticate_user!`, a kontrolery
# and the PUBLIC controllers remove it. Without this branch GitLab's whole
# controller tree read as "everything is guarded", which is zero candidates: the
# silent zero again, arrived at from the opposite direction.
_RAILS_SKIP = re.compile(r"^[ \t]*skip_before_action[ \t]+:(\w+!?)(?P<arg>[^\n]*)$", re.M)
_SKIP_ALIAS = {"block_if_requires_login": "requires_login",
               "redirect_to_login_if_required": "requires_login"}


def rails_skip_directives(txt):
    """[(skipped_filter_name, mode, {actions})]."""
    out = []
    for m in _RAILS_SKIP.finditer(txt):
        name = _SKIP_ALIAS.get(m.group(1), m.group(1))
        stmt = _logical_stmt(txt, m.start())
        if "only:" in stmt:
            out.append((name, "only", _rails_syms(stmt.split("only:", 1)[1])))
        elif "except:" in stmt:
            out.append((name, "except", _rails_syms(stmt.split("except:", 1)[1])))
        else:
            out.append((name, "all", set()))
    return out


# Every controller callback, NOT only the ones that require a login.
# Forced by a Discourse controller where the guard on `show` is
# `before_action :find_topic_with_topic_view`, whose body ends in
# `guardian.ensure_can_see!(@topic)`. The body of the ACTION says nothing about
# permissions at all, so an analyzer that reads only the action sees no guard.
_RAILS_CALLBACK = re.compile(
    r"^[ \t]*(?:prepend_)?(?:before|around)_action[ \t]+:(\w[\w?!]*)(?P<arg>[^\n]*)$", re.M)


def rails_callbacks(txt):
    """[(method_name, mode, {actions})] for callbacks and their only/except scope."""
    out = []
    for m in _RAILS_CALLBACK.finditer(txt):
        name = m.group(1)
        stmt = _logical_stmt(txt, m.start())
        if "only:" in stmt:
            out.append((name, "only", _rails_syms(stmt.split("only:", 1)[1])))
        elif "except:" in stmt:
            out.append((name, "except", _rails_syms(stmt.split("except:", 1)[1])))
        else:
            out.append((name, "all", set()))
    return out


def rails_callbacks_for(txt, action):
    """The callbacks that ACTUALLY apply to this action, after only/except."""
    out = []
    for name, mode, acts in rails_callbacks(txt):
        if mode == "all" or (mode == "only" and action in acts) or \
           (mode == "except" and action not in acts):
            out.append(name)
    return out


def rails_actions(txt):
    """A controller's public actions: every `def` BEFORE `private` or `protected`."""
    cut = _RAILS_PRIVATE.search(txt)
    head = txt[:cut.start()] if cut else txt
    return [m.group(1) for m in _RAILS_ACTION.finditer(head)]


def rails_login_scope(txt):
    """Kept for backward compatibility: ('all'|'only'|'except'|'none', {actions})."""
    dirs = rails_guard_directives(txt)
    if not dirs:
        return "none", set()
    for name, mode, acts in dirs:
        if mode == "all":
            return "all", set()
    return dirs[0][1], dirs[0][2]


def rails_anonymous_actions(txt, inherited=()):
    """Actions reachable WITHOUT a login, given this file plus INHERITED filters.

    `inherited` carries the directives from superclasses, for example an admin
    base controller holding `requires_login` and `before_action :ensure_admin`.
    The caller has to supply them, because resolving the chain needs an index of
    every file. That is the "the guard lives one layer down" rule again.

    A THIRD layer, a constraint on the ROUTE such as
    `constraints: AdminConstraint.new`, is deliberately out of scope here: it
    needs the routing configuration, which this module does not read.
    """
    acts = rails_actions(txt)
    dirs = list(rails_guard_directives(txt)) + list(inherited)
    guarded = rails_guarded_actions(acts, dirs, rails_skip_directives(txt))
    return [a for a in acts if a not in guarded]


# ---- Grape (GitLab lib/api/*.rb)----------------------------------------
# FOUR LEVELS of guard, measured on GitLab 19.x:
#   1. klasowy `before { authenticate! }` / `authenticated_as_admin!`
#   2. helper w ciele trasy (`authorize!`, `find_project!`, `user_project`)
#   3. `route_setting :authorization, permissions: ...` W PREAMBULE trasy
#   4. dziedziczenie po ::API::Base + mount w api.rb
# Level 3 sits BEFORE the word `get`, so a version that cut the body from one
# `get` to the next attributed it to the PREVIOUS route. Same class of mistake
# the window boundary did not coincide with the boundary of the construct.
_GRAPE_BEFORE = re.compile(r"^[ \t]*before[ \t]+do(.*?)^[ \t]*end", re.M | re.S)
_GRAPE_BEFORE_BRACE = re.compile(r"^[ \t]*before[ \t]*\{([^}]*)\}", re.M)
_GRAPE_ROUTE = re.compile(
    r"^([ \t]*)(get|post|put|patch|delete|head)[ \t]+(?P<path>'[^']*'|\"[^\"]*\"|:\w+)?", re.M)
_GRAPE_AUTH_ALL = re.compile(
    r"\bauthenticate!|\bauthenticated_as_admin!|\bauthenticated_with_[\w]*!|"
    r"\bauthorize_admin[\w]*!|\bauthorize!|\badmin_mode\b")
_GRAPE_ROUTE_AUTH = re.compile(
    r"\bauthenticate!|\bauthenticated_as_admin!|\bauthorize!|\bauthorize_\w+!|\bcurrent_user\b|"
    r"\bfind_project!|\buser_project\b|\bfind_group!|\buser_group\b|\bforbidden!|\bnot_found!|"
    r"\bcheck_rate_limit!|\baccess_denied!|\bfind_namespace!|\bauthenticated_with_\w+|"
    r"^[ \t]*route_setting[ \t]+:authorization\b|\bunauthorized!|\bfind_user\b|"
    r"\bGitlab::Shell\b|\bverify_workhorse_api!|\bauthenticate_by_gitlab_shell_or_workhorse_token!|"
    r"\bauthenticate_gitlab_\w+_request!", re.M)


def grape_class_auth(txt):
    """'all', 'get_anon' or 'none': the guard declared at CLASS level."""
    blocks = [m.group(1) for m in _GRAPE_BEFORE.finditer(txt)]
    blocks += [m.group(1) for m in _GRAPE_BEFORE_BRACE.finditer(txt)]
    got_all = False
    for blk in blocks:
        if "authenticate_non_get!" in blk:
            return "get_anon"
        if _GRAPE_AUTH_ALL.search(blk):
            got_all = True
    return "all" if got_all else "none"


def _indent_of(line):
    e = line.expandtabs(4)
    return len(e) - len(e.lstrip())


def grape_anonymous_routes(txt):
    """[(label, preamble plus body)] for Grape routes reachable without a token.

    The route body is cut by matching `do` against `end` on indentation, and the
    PREAMBLE (desc, params, route_setting) back to the end of the previous route
    is included in the window. Without the preamble, `route_setting
    :authorization` was attributed to the NEIGHBOURING route, and nine admin
    routes looked open.
    """
    mode = grape_class_auth(txt)
    if mode == "all":
        return []
    lines = txt.split("\n")
    line_start = []
    pos = 0
    for ln in lines:
        line_start.append(pos)
        pos += len(ln) + 1
    out = []
    prev_end = 0
    for m in _GRAPE_ROUTE.finditer(txt):
        li = txt.count("\n", 0, m.start())
        if li < prev_end:
            continue                      # nested inside the previous route's body
        ind = _indent_of(lines[li])
        j = li + 1
        while j < len(lines):
            s = lines[j]
            if s.strip() and _indent_of(s) <= ind:
                if s.strip() == "end":
                    break
                if _GRAPE_ROUTE.match(s):
                    j -= 1
                    break
            j += 1
        body = "\n".join(lines[li:min(j + 1, len(lines))])
        preamble = "\n".join(lines[prev_end:li])
        prev_end = j + 1
        verb = m.group(2)
        if mode == "get_anon" and verb not in ("get", "head"):
            continue
        window = preamble + "\n" + body
        if _GRAPE_ROUTE_AUTH.search(window):
            continue
        path = (m.group("path") or "").strip("'\"")
        out.append((f"{verb.upper()} {path or '/'}", window))
    return out


# ---- Chia peer to peer--------------------------------------------------
_CHIA_DEC = re.compile(
    r"^[ \t]*@(?:metadata|api)\.request\s*\((?P<args>[^)]*)\)[ \t]*\n"
    r"(?:[ \t]*@[^\n]*\n)*"
    r"[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>\w+)", re.M)


def chia_p2p_handlers(txt):
    """[(name, peer_required)] for peer to peer protocol message handlers.

    The caller is any peer that completed TLS. The certificate is self signed and
    carries NO role, so every such handler is unauthenticated surface by
    definition, whatever the handler body says.
    """
    return [(m.group("name"), "peer_required=True" in (m.group("args") or ""))
            for m in _CHIA_DEC.finditer(txt)]



# The TRANSPORT as the guard (Chia, chia/server/server.py around line 170):
#   authenticated_server_types = {HARVESTER, FARMER, WALLET, DATA_LAYER}
# Those listeners demand a certificate signed by the node's PRIVATE CA, so their
# @metadata.request handlers are NOT anonymous surface. The remaining services
# (FULL_NODE, INTRODUCER, TIMELORD, SOLVER, CRAWLER) stoja na CA "chia", ktorego
# whose key is in the repository, so there every peer is unauthenticated.
# This is the clearest case of the rule: the guard is not in the handler code
# but one layer below it, in the TLS context.
CHIA_PRIVATE_CA_API = re.compile(r"/(?:harvester|farmer|wallet|data_layer)/[\w_]*api\w*\.py$")


def chia_transport_authenticated(path):
    return bool(CHIA_PRIVATE_CA_API.search(str(path).replace("\\", "/")))


# ---- Django and DRF-----------------------------------------------------
# The whole STACK of decorators above the `def`, not just the nearest one.
# Forced by a view in kitsune where the order is
#     @group_required("Staff")
#     @require_POST
#     @csrf_exempt
#     def create_test_user(request)
# A pattern anchored on @csrf_exempt saw only the decorators BELOW it, so the
# group requirement above was invisible and the false lead sorted to the top.
_DJ_DECSTACK = re.compile(
    r"(?P<decs>(?:^[ \t]*@[^\n]*\n)+)[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>\w+)", re.M)
DJ_AUTH_DECORATOR = re.compile(
    r"@login_required|@group_required|@permission_required|@staff_member_required|"
    r"@user_passes_test|@api_view|@authentication_classes|@permission_classes\s*\(\s*\[\s*Is|"
    r"@require_\w*permission|@mobile_template|@waffle_\w+|@ratelimit")
_DJ_CLS = re.compile(r"^[ \t]*class[ \t]+(\w+)\b[^\n]*:[ \t]*\n(?P<body>(?:(?:[ \t]+[^\n]*)?\n)*)", re.M)


def django_anonymous_views(txt):
    """[(name, reason)] for views explicitly open to an anonymous caller."""
    out = []
    for m in _DJ_DECSTACK.finditer(txt):
        decs = m.group("decs")
        if "@csrf_exempt" not in decs:
            continue
        if DJ_AUTH_DECORATOR.search(decs):
            continue
        out.append((m.group("name"), "csrf_exempt"))
    for m in _DJ_CLS.finditer(txt):
        body = m.group("body") or ""
        if ANON_REG["py"][1][1].search(body):
            out.append((m.group(1), "AllowAny"))
    return out


# ---- Go-----------------------------------------------------------------
# Measured on gitea: 38 of 133 "registrations" had as their wrapper
# `reqPackageAccess`, and others `reqRepoReader` or `reqRepoWriter`: GUARDS
# which this list did not know. gitea spells them `req*`, in lower case.
_GO_AUTH_WRAP = re.compile(
    r"SessionRequired|RequireSession|RequireSignIn|RequireAuth|Authenticated|Secure|"
    r"mustLogin|\breq[A-Z]\w*|\breqSignIn\b|\breqToken\b|\breqAdmin\b|"
    r"reqPackageAccess|reqRepoReader|reqRepoWriter|reqOrgMembership|reqSelfOrAdmin|"
    r"reqSiteAdmin|reqExploreSignIn|tokenRequiresScopes|verifyAuth|checkTokenPublicOnly|"
    # Mattermost: `APILocal` to API gniazda uniksowego trybu --local (dostep do
    # so reaching the socket already means root on the host, which is NOT anonymous
    # `RemoteClusterTokenRequired` weryfikuje token zdalnego klastra.
    # Bez tych dwoch 29 z 31 "kandydatow" Mattermosta to byly wlasnie one.
    r"\bAPILocal\b|\w*TokenRequired\b|\w+Required\b|CloudAPIKeyRequired",
    re.I)


def go_unauthed_handlers(txt):
    """[(handler_name, wrapper)] for registrations with NO authenticating wrapper."""
    out = []
    for m in ANON_REG["go"][0][1].finditer(txt):
        wrap, h = m.group("wrap"), m.group("h")
        if _GO_AUTH_WRAP.search(wrap or ""):
            continue
        out.append((h.split(".")[-1], wrap))
    return out


# ---- Fixtures, and the adapter the selftest drives them through---------
class _Probe:
    """Adapter: wpina KONTROLE STRUKTURALNA w istniejaca petle selftest(),
    which only knows how to do `rx.search(txt) -> bool`."""

    def __init__(self, fn, label):
        self.fn, self.label = fn, label

    def search(self, txt):
        return True if self.fn(txt) else None

    def __repr__(self):
        return f"<probe {self.label}>"


RAILS_ANON_PROBE = _Probe(rails_anonymous_actions, "rails_anonymous_actions")
GRAPE_ANON_PROBE = _Probe(grape_anonymous_routes, "grape_anonymous_routes")
PREAUTH_PATH_PROBE = _Probe(lambda t: is_preauth_endpoint("create", t), "is_preauth_endpoint(path)")
CHIA_PROBE = _Probe(chia_p2p_handlers, "chia_p2p_handlers")
GO_ANON_PROBE = _Probe(go_unauthed_handlers, "go_unauthed_handlers")

_FIX_RB_GUARDED = (
    "class Admin::SecretsController < Admin::AdminController\n"
    "  requires_login\n"
    "\n"
    "  def index\n"
    "    render json: Secret.all\n"
    "  end\n"
    "end\n")
_FIX_RB_OPEN = (
    "class LeakController < ApplicationController\n"
    "  skip_before_action :verify_authenticity_token\n"
    "\n"
    "  def index\n"
    "    render json: Secret.all\n"
    "  end\n"
    "end\n")
_FIX_RB_ONLY = (
    "class MixedController < ApplicationController\n"
    "  requires_login only: %i[update]\n"
    "\n"
    "  def show\n"
    "    render json: Thing.all\n"
    "  end\n"
    "\n"
    "  def update\n"
    "    head :ok\n"
    "  end\n"
    "end\n")
_FIX_RB_HARD = (
    "class StaffController < ApplicationController\n"
    "  before_action :ensure_staff\n"
    "\n"
    "  def index\n"
    "    render json: Secret.all\n"
    "  end\n"
    "end\n")
_FIX_RB_MINIPROFILER = (
    "class OpenController < ApplicationController\n"
    "  before_action :authorize_mini_profiler\n"
    "\n"
    "  def index\n"
    "    render json: Secret.all\n"
    "  end\n"
    "end\n")
_FIX_RB_AUTHORIZE_BANG = (
    "class ProfileController < ApplicationController\n"
    "  before_action :authorize_read_user_profile!\n"
    "\n"
    "  def index\n"
    "    render json: Secret.all\n"
    "  end\n"
    "end\n")

_FIX_RB_CHAOS = (
    "class ChaosController < BaseActionController\n"
    "  before_action :validate_chaos_secret, unless: :development_or_test?\n"
    "\n"
    "  def gc\n"
    "    render json: { worker_id: 1 }\n"
    "  end\n"
    "end\n")

_FIX_GRAPE_GUARDED = (
    "module API\n"
    "  class Widgets < ::API::Base\n"
    "    before do\n"
    "      authenticate!\n"
    "    end\n"
    "\n"
    "    get ':id' do\n"
    "      present Widget.find(params[:id])\n"
    "    end\n"
    "  end\n"
    "end\n")
_FIX_GRAPE_OPEN = (
    "module API\n"
    "  class Widgets < ::API::Base\n"
    "    get ':id' do\n"
    "      present Widget.find(params[:id])\n"
    "    end\n"
    "  end\n"
    "end\n")
_FIX_CHIA_OPEN = (
    "    @metadata.request(peer_required=True)\n"
    "    async def request_peers(self, _request: RequestPeers, peer: WSChiaConnection):\n"
    "        return make_msg(ProtocolMessageTypes.respond_peers, msg)\n")
_FIX_CHIA_PLAIN = (
    "    async def request_peers(self, _request: RequestPeers, peer: WSChiaConnection):\n"
    "        return None\n")


#: The rules `is_guarded` consults, in the order it consults them, each with the
#: one line version of why it exists. The long version is the comment above each
#: pattern, and that is the part worth reading.
RULES = [
    ("AUTHZ_CALL", AUTHZ_CALL,
     "an explicit permission call: check/has/ensure/require plus "
     "access/permission/privilege, across PHP, Ruby, Python, Go and JS"),
    ("INBAND_AUTH", INBAND_AUTH,
     "authentication by a secret in the request: HMAC, signature or JWT "
     "verification, including PHP's loose == and the Node webhook idioms"),
    ("SELF_SCOPE", SELF_SCOPE,
     "the query scopes itself by session identity, so there is nothing to "
     "escalate to and no explicit capability check is needed"),
    ("PUBLIC_SCOPE", PUBLIC_SCOPE,
     "the handler restricts itself to published, non password protected "
     "content, which is the right control on an anonymous endpoint"),
    ("ADMIN_GATE", ADMIN_GATE,
     "the sink sits behind an administrative capability: not an escalation, "
     "but lower the weight rather than silencing it"),
]

#: Rules that are NOT guards, kept separate because confusing them with guards
#: is the mistake each one was added to prevent.
CONTEXT_RULES = [
    ("PRE_AUTH", PRE_AUTH,
     "the endpoint is unauthenticated by nature: a login, a password reset, a "
     "health check. Flagging one as missing authorization is always wrong"),
    ("NONCE_GUARD", NONCE_GUARD,
     "a CSRF token or nonce, including a project's own wrapper. It proves the "
     "request was intended, NOT that the caller is allowed to make it"),
    ("SERVER_PATH", SERVER_PATH,
     "the path or URL is built by the server, so there is no caller "
     "controlled target and no SSRF"),
    ("HARDENING_COMMIT", HARDENING_COMMIT,
     "a commit that tightens a guard, which a drift check otherwise reports "
     "as a regression"),
    ("TEST_PATH", TEST_PATH, "a test or fixture file is not attack surface"),
]


def is_guarded(body, *, admin_counts=True):
    """Does this function body carry ANY acceptable guard?

    Returns (bool, rule_name), so a caller can report WHICH rule decided it.

    Pass `admin_counts=False` to ask the narrower question: is there a guard
    other than an administrative gate? A LIMITATION worth knowing, because the
    parameter's name promises more than it delivers: AUTHZ_CALL is consulted
    first and matches `current_user_can(...)` whatever capability is named, so
    on WordPress code this flag changes nothing. It works as intended on the
    admin markers that AUTHZ_CALL does not match, such as Go's `IsSystemAdmin()`
    or Ruby's `is_admin?`. Narrowing it properly means ranking the capability,
    which is what `cap_rank` is for.
    """
    for name, rx in (("AUTHZ_CALL", AUTHZ_CALL), ("INBAND_AUTH", INBAND_AUTH),
                     ("SELF_SCOPE", SELF_SCOPE), ("PUBLIC_SCOPE", PUBLIC_SCOPE)):
        if rx.search(body):
            return True, name
    if admin_counts and ADMIN_GATE.search(body):
        return True, "ADMIN_GATE"
    return False, None


#-------------------------------------------------------------------------
# A two sided control pair that exercises the WHOLE path through is_guarded,
# not a single regex. A rule that fires on a snippet and stays silent on a real
# handler is worth nothing. A handler WITH a guard must stay silent
# (is_guarded returns True, so there is nothing to report), and a handler
# WITHOUT one must speak up.
#-------------------------------------------------------------------------
HANDLER_JS_GUARDED = """
export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const id = new URL(req.url).searchParams.get("id");
  const row = await prisma.invoice.findUnique({
    where: { id, userId: session.user.id },
  });
  return Response.json(row);
}
"""

HANDLER_JS_UNGUARDED = """
export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const row = await prisma.invoice.findUnique({ where: { id } });
  return Response.json(row);
}
"""

WEBHOOK_JS_GUARDED = """
export async function POST(request: Request) {
  const body = await request.text();
  const mac = createHmac("sha256", secret).update(body).digest();
  const sent = Buffer.from(request.headers.get("x-hub-signature-256") ?? "", "hex");
  if (!timingSafeEqual(mac, sent)) return new Response("no", { status: 401 });
  return handle(JSON.parse(body));
}
"""

WEBHOOK_JS_UNGUARDED = """
export async function POST(request: Request) {
  const body = await request.text();
  return handle(JSON.parse(body));
}
"""

JS_PAIRS = [
    ("handler z sesja", HANDLER_JS_GUARDED, True),
    ("handler bez sesji", HANDLER_JS_UNGUARDED, False),
    ("webhook z HMAC", WEBHOOK_JS_GUARDED, True),
    ("webhook bez HMAC", WEBHOOK_JS_UNGUARDED, False),
]


def selftest_js_pairs():
    """Mismatches on the JavaScript control pairs, as (label, want, got)."""
    mismatches = []
    for label, code, want in JS_PAIRS:
        got = is_guarded(code)[0]
        if got != want:
            mismatches.append((label, want, got))
    return mismatches




#: Every rule paired with the case that forced it and the opposite case that
#: must stay silent. Exposed at module level so a test can name each one:
#: a failure then says WHICH rule and WHICH text, rather than "selftest failed".
CASES = [
    # (rule, text, expected)
    (PRE_AUTH, "acme_forgot_password", True),
    (PRE_AUTH, "resetPassword", True),              # camelCase, an early miss
    (PRE_AUTH, "get_user_bookmarks", False),
    (PRE_AUTH, "users.forgotPassword", True),   # a Rocket.Chat route, where the boundary is a dot
    (PRE_AUTH, "users.register", True),
    (PRE_AUTH, "chat.getMessage", False),
    (INBAND_AUTH, "if (!hash_equals($stored, $provided))", True),
    (INBAND_AUTH, "if(urldecode($request_key) == $status_key)", True),  # a loose ==
    (INBAND_AUTH, "if ($a == $b)", False),
    (SELF_SCOPE, "userID := c.AppContext.Session().UserId", True),
    (SELF_SCOPE, "Project.objects.visible_for(request.user)", True),
    (SELF_SCOPE, "userID := c.Params.UserId", False),
    (PUBLIC_SCOPE, "if ('publish' !== get_post_status($id))", True),
    (PUBLIC_SCOPE, "$x = get_option('foo');", False),
    (ADMIN_GATE, "if (!current_user_can('manage_options'))", True),
    (ADMIN_GATE, "if (!current_user_can('read'))", False),
    (SERVER_PATH, "$f = wp_tempnam($name);", True),
    (SERVER_PATH, "$path = get_attached_file($id);", True),
    (SERVER_PATH, "$f = $_GET['path'];", False),
    (HARDENING_COMMIT, "SECURITY: Restrict chat history reads", True),
    (HARDENING_COMMIT, "Add new dashboard widget", False),
    (TEST_PATH, "spec/requests/foo_spec.rb", True),
    (TEST_PATH, "app/controllers/foo.rb", False),
    (CAP_STRONG_PAT, "manage_woocommerce", True),
    (CAP_STRONG_PAT, "administrator", True),
    (CAP_STRONG_PAT, "edit_posts", False),
    (CAP_WEAK_PAT, "read", True),
    (NONCE_GUARD, "acme_check_nonce('acme_rpc_'.$id, 'n')", True),
    (NONCE_GUARD, "wp_verify_nonce($n, 'a')", True),
    (NONCE_GUARD, "check_the_nonsense($x)", False),
    # 2026-09-20 Matomo
    (NONCE_GUARD, "$this->checkTokenInUrl();", True),
    (SELF_SCOPE, "$login = Piwik::getCurrentUserLogin();", True),
    (SELF_SCOPE, "if (Piwik::isUserIsAnonymous()) { return '[]'; }", True),
    (SELF_SCOPE, "$x = getUserAgent();", False),
    (SELF_SCOPE, "$n = getCurrentUserCountCached();", True),
    # a Matomo and PHP idiom: without these rules, a silent ZERO over 4096 files
    (AUTHZ_CALL, "Piwik::checkUserHasSuperUserAccess();", True),
    (AUTHZ_CALL, "Piwik::checkUserHasViewAccess($idSite);", True),
    (AUTHZ_CALL, "Piwik::checkUserHasWriteAccess($idSite);", True),
    (AUTHZ_CALL, "Piwik::hasUserSuperUserAccess()", True),
    (AUTHZ_CALL, "$this->checkUserHasSomeViewAccess();", True),
    # idiom Rails/Discourse
    (AUTHZ_CALL, "guardian.ensure_can_see!(post)", True),
    (AUTHZ_CALL, "raise unless guardian.can_see_profile?(user)", True),
    # NEGATIVE CONTROL: must not match everything containing "check" or "access"
    (AUTHZ_CALL, "$this->checkFileExists($path);", False),
    (AUTHZ_CALL, "accessLog($request);", False),
    (AUTHZ_CALL, "hasAccessToken($token)", False),
    # ---- JavaScript and TypeScript family, positive cases-------------------
    (AUTHZ_CALL, "await requireUser(req);", True),
    (AUTHZ_CALL, "if (!ability.can('read', post)) throw new Error();", True),
    (AUTHZ_CALL, "export default withAuth(handler);", True),
    (SELF_SCOPE, "where: { userId: session.user.id }", True),
    (SELF_SCOPE, "const s = await getServerSession(authOptions);", True),
    (SELF_SCOPE, "if (post.ownerId !== session.user.id) return deny();", True),
    (INBAND_AUTH, "if (!timingSafeEqual(mac, sent)) return bad();", True),
    (INBAND_AUTH, "const { payload } = await jwtVerify(token, key);", True),
    # ---- NEGATIVE CONTROL: a source is NOT a guard, and names that
    #    merely look similar must not pass
    (SELF_SCOPE, "const id = searchParams.get('id');", False),
    (SELF_SCOPE, "const id = req.query.id;", False),
    (AUTHZ_CALL, "const c = canvas(el);", False),
    (AUTHZ_CALL, "await cancelOrder(id);", False),
    (AUTHZ_CALL, "const d = durability.check;", False),
    (SELF_SCOPE, "const token = await oauth();", False),
    # ---- ANON_REG, per language---------------------------------------------
    (ANON_REG["rb"][0][1], "  skip_before_action :verify_authenticity_token, only: [:x]", True),
    (ANON_REG["rb"][0][1], "  before_action :verify_authenticity_token", False),
    (ANON_REG["rb"][3][1], "  class Widgets < ::API::Base", True),
    (ANON_REG["py"][0][1], "@csrf_exempt", True),
    (ANON_REG["py"][1][1], "    permission_classes = [AllowAny]", True),
    (ANON_REG["py"][1][1], "    permission_classes = [IsAuthenticated]", False),
    (ANON_REG["py"][3][1], "    @metadata.request(peer_required=True)", True),
    (ANON_REG["py"][3][1], "    @metadata.response()", False),
    (ANON_REG["ts"][1][1], "  @Public()", True),
    (ANON_REG["ts"][1][1], "  @UseGuards(AuthGuard)", False),
    # NEGATIVE CONTROL: a controller WITH requires_login must stay silent
    (RAILS_ANON_PROBE, _FIX_RB_GUARDED, False),
    (RAILS_ANON_PROBE, _FIX_RB_HARD, False),
    (RAILS_ANON_PROBE, _FIX_RB_OPEN, True),
    (RAILS_ANON_PROBE, _FIX_RB_ONLY, True),
    # NEGATIVE CONTROL: a pre-authentication endpoint must stay silent,
    # inaczej caly wynik to ekran logowania (session/omniauth/password).
    (PREAUTH_PATH_PROBE, "app/controllers/session_controller.rb", True),
    (PREAUTH_PATH_PROBE, "app/controllers/users/omniauth_callbacks_controller.rb", True),
    (PREAUTH_PATH_PROBE, "app/controllers/admin/reports_controller.rb", False),
    (PREAUTH_PATH_PROBE, "app/controllers/topics_controller.rb", False),
    # Grape
    (GRAPE_ANON_PROBE, _FIX_GRAPE_GUARDED, False),
    (GRAPE_ANON_PROBE, _FIX_GRAPE_OPEN, True),
    # Chia P2P
    (CHIA_PROBE, _FIX_CHIA_OPEN, True),
    (CHIA_PROBE, _FIX_CHIA_PLAIN, False),
    # The trap: `before_action :authorize_mini_profiler` lives in Discourse's
    # ApplicationController Discourse'a. Wersja bez WYMAGANEGO wykrzyknika
    # treated it as an authorization guard and silenced 467 of 477 actions, taking
    # the candidate list from 38 to 8. A fix had turned into a silent failure.
    # The exclamation mark is part of the Rails authorization idiom: `authorize_x!`
    # raises, while `authorize_x` without it may be an ordinary method.
    (RAILS_ANON_PROBE, _FIX_RB_MINIPROFILER, True),
    (RAILS_ANON_PROBE, _FIX_RB_AUTHORIZE_BANG, False),
    (RAILS_ANON_PROBE, _FIX_RB_CHAOS, False),
    (_Probe(chia_transport_authenticated, "chia_transport"),
     "chia/harvester/harvester_api.py", True),
    (_Probe(chia_transport_authenticated, "chia_transport"),
     "chia/full_node/full_node_api.py", False),
    # Go
    (GO_ANON_PROBE, 'r.Handle("/x", api.APISessionRequired(getUser)).Methods("GET")', False),
    (GO_ANON_PROBE, 'r.Handle("/x", api.APIHandler(getUser)).Methods("GET")', True),
]

def selftest():
    """Every rule must fire on the case that forced it, and stay silent on its opposite.

    The second half is the one that matters. A rule that fires on everything
    passes the first half perfectly.
    """
    cases = CASES
    bad = []
    for rx, txt, want in cases:
        got = bool(rx.search(txt))
        if got != want:
            bad.append((txt, want, got))
    # The two sided pair: guarded stays silent, unguarded speaks up
    for label, want, got in selftest_js_pairs():
        bad.append(("JS pair: " + label, want, got))
    return bad


if __name__ == "__main__":
    import sys
    bad = selftest()
    if bad:
        print("SELFTEST FAILED: %d cases" % len(bad))
        for t, w, g in bad:
            print("   %r: expected %s, got %s" % (t, w, g))
        sys.exit(1)
    print("selftest OK: every rule fired on its own case and stayed silent on "
          "its opposite")


#-------------------------------------------------------------------------
# 12. MODEL_VALIDATION: the guard is in the MODEL, not in a policy or controller
#     Forced by GitLab CE 19.2.0, and this one is worth reading in full.
#     The source reading was correct and still led to a false lead:
#       * update.rb autoryzuje :update_organization
#       * polityka definiuje :update_organization_user jako
#         `can?(:update_organization) & ~last_owner`
#       * the sibling operation uses the right capability
#       * neither the mutation nor the service mentions last_owner at all
#     Wszystko wskazywalo na obejscie ochrony ostatniego wlasciciela. Lab odpowiedzial:
#       "You cannot change the access of the last owner from the organization"
#     bo niezmiennika pilnuje `validate :last_owner_access_level_change` w modelu
#     (app/models/organizations/organization_user.rb:13).
#     EVERY differential analyzer here reads policies, `authorize` calls and
#     controller filters. NONE of them looks at model validations, so this class
#     of false lead will keep coming back
#     na kazdym celu w Rails (GitLab, Discourse, Mastodon).
#-------------------------------------------------------------------------
MODEL_VALIDATION = re.compile(
    r"^\s*validates?\s+[:'\"]", re.M)


def model_validates_invariant(model_sources, resource, concepts):
    """Does this resource's model defend the invariant, using one of `concepts`?

    model_sources: {path: contents} for the files under app/models
    resource:      for example 'organization_user', so organization_user.rb
    concepts:      for example ['last_owner'], the idea the suspected gap is about
    Returns (True, description) when the model validates something about it.
    """
    for path, contents in model_sources.items():
        if not path.endswith(f"{resource}.rb"):
            continue
        for m in MODEL_VALIDATION.finditer(contents):
            linia = contents[m.start():contents.find("\n", m.start())]
            if any(s in linia for s in concepts):
                return True, linia.strip()
        # A validation may call a method whose NAME does not carry the concept, so also
        # look through the file body for the concept alongside an errors.add call.
        for s in concepts:
            if s in contents and re.search(r"errors\.add", contents):
                return True, ("the model mentions %r next to an errors.add call"
                              % s)
    return False, ""
