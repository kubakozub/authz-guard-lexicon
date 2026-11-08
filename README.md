# authz-guard-lexicon

[![tests](https://github.com/kubakozub/authz-guard-lexicon/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/authz-guard-lexicon/actions/workflows/tests.yml)

What counts as an authorization check, in one place, across five languages. Every
rule records the specific case that forced it.

```console
$ authz-guard-lexicon rules
GUARDS, in the order is_guarded consults them

  AUTHZ_CALL       an explicit permission call: check/has/ensure/require plus access/permission/privilege, across PHP, Ruby, Python, Go and JS
  INBAND_AUTH      authentication by a secret in the request: HMAC, signature or JWT verification, including PHP's loose == and the Node webhook idioms
  SELF_SCOPE       the query scopes itself by session identity, so there is nothing to escalate to and no explicit capability check is needed
  PUBLIC_SCOPE     the handler restricts itself to published, non password protected content, which is the right control on an anonymous endpoint
  ADMIN_GATE       the sink sits behind an administrative capability: not an escalation, but lower the weight rather than silencing it

NOT GUARDS, kept separate because confusing them with guards is the
mistake each one was added to prevent

  PRE_AUTH         the endpoint is unauthenticated by nature: a login, a password reset, a health check. Flagging one as missing authorization is always wrong
  NONCE_GUARD      a CSRF token or nonce, including a project's own wrapper. It proves the request was intended, NOT that the caller is allowed to make it
  SERVER_PATH      the path or URL is built by the server, so there is no caller controlled target and no SSRF
  HARDENING_COMMIT a commit that tightens a guard, which a drift check otherwise reports as a regression
  TEST_PATH        a test or fixture file is not attack surface
```

```console
$ echo "if (!current_user_can('edit_posts')) return;" | authz-guard-lexicon check -
guarded by AUTHZ_CALL
$ echo 'echo $_GET["x"];' | authz-guard-lexicon check - ; echo $?
no recognised guard
1
```

Python 3.9+, standard library only, 1368 lines, 67 compiled patterns, 22 public
functions. PHP and WordPress, Ruby on Rails, Grape, Django and DRF, Go,
TypeScript and JavaScript, and the Chia peer to peer protocol.

## Two failure modes, and the second is the dangerous one

A rule that is too narrow produces a false lead. That costs a verification cycle
and it is annoying.

A rule that fails to recognise a guard that is really there produces a **silent
zero**: the analyzer reports nothing, and the target reads as hardened. That is
worse, because a zero from an analyzer that does not speak the target's dialect
is not a result, and nothing in the output says so.

Most of the rules here exist because a silent zero was traced back to one missing
idiom. Three measured examples, each in the comments above its pattern:

- **Matomo 5.13.0** contains 172 occurrences of six authorization idioms. The
  pattern table matched **none** of them, so two differential analyzers returned
  a clean zero on that target. It read as "hardened" and meant "wrong dialect".
- **gitea** uses neither `mux.Vars` nor `r.URL.Query()`. It reads request context
  through its own accessors, so 133 anonymous registrations collapsed to zero at
  the context stage.
- **GitLab** inverts the Rails default: the base controller requires
  authentication and the public controllers remove it. Without a branch for
  `skip_before_action`, the whole controller tree read as "everything is
  guarded", which is zero candidates: the same silent zero from the other side.

The one that cost the most was a *fix* that became a silent failure. A guard
pattern written without the required exclamation mark treated Discourse's
`before_action :authorize_mini_profiler` as an authorization guard and silenced
467 of 477 actions, taking a candidate list from 38 to 8. The exclamation mark is
part of the Rails idiom: `authorize_x!` raises, `authorize_x` may be any method.

## Why one module

Over one working session the same guard recognition rule was derived in **one**
analyzer four separate times and never carried to the others. Each time it cost a
verification cycle on a lead that had been false from the start. An audit produced
a matrix in which most of seventeen analyzers had **none** of the seven rules that
existed.

Copying regular expressions between files is the cause. One imported module is
the cure: a new rule is one change instead of seven.

## The guard is usually one layer down

Half the work here is not pattern matching. A registration can look wide open
while the checking happens somewhere else entirely:

| where the guard actually lives | example |
|---|---|
| in a callback, not the action | a Discourse `before_action` whose body ends in `guardian.ensure_can_see!`, while the action says nothing about permissions |
| in a superclass | an admin base controller holding `requires_login` plus `before_action :ensure_admin` |
| above the decorator you anchored on | `@group_required("Staff")` sits ABOVE `@csrf_exempt`, and a pattern anchored on the latter sees only what is below it |
| in the route preamble | Grape's `route_setting :authorization` comes BEFORE the word `get`, so a window cut from one `get` to the next attributes it to the previous route |
| in the TLS transport | Chia services whose listener demands a certificate signed by the node's private CA are not anonymous surface, whatever the handler body says |

That last one is the clearest case: the guard is not in the code at all.

## The corpus is the contract

```console
$ python3 -m unittest discover -s tests
Ran 37 tests in 0.193s
OK
```

**88 controls: 53 positive and 35 negative**, plus 4 whole-path pairs that run a
realistic handler through the entire decision rather than one pattern. The
negative half is the half that matters, because a rule that fires on everything
passes the positive half perfectly.

The controls live in `guardlex.CASES` rather than inside a test, so a failure
names which rule and which text instead of saying "selftest failed". A rule with
no control is a rule nobody can change safely, and a test asserts that every
rule has one.

## Two things found by writing those tests

**A quadratic pattern.** One branch of `INBAND_AUTH` had an unbounded `\w*`
before a keyword alternation, so it was quadratic in the input: 20000 characters
of a single word took **6.7 seconds**, and the whole suite took 13. This module
is meant to run over arbitrary source, including minified JavaScript on one line,
so that is a denial of service in whatever runs it. Bounding the identifier to 40
characters took the same input to **0.03 seconds** and the suite to 0.098, with
all 88 control outcomes byte for byte identical. A loose timing bound now guards
against its return.

**A parameter that promised more than it delivered.** `is_guarded(body,
admin_counts=False)` is meant to ask the narrower question: is there a guard
other than an administrative gate? It works on Go's `IsSystemAdmin()` and Ruby's
`is_admin?`, and it does **nothing** on WordPress code, because `AUTHZ_CALL` is
consulted first and matches `current_user_can(...)` whatever capability is named.
That limitation is documented where the function is defined and pinned by a test,
rather than left for a caller to discover.

## What this is not

**It is not a scanner.** There is no traversal, no reporting and no ranking. It
answers one question about a piece of text, and the caller decides what that
means.

**It has no measured precision rate.** There is no labelled corpus of handlers to
measure one against, and a number computed on a handful of projects would be
decoration. What it has instead is a two sided corpus where a false alarm fails
the suite exactly like a miss, and a rule set where every entry names the case
that forced it. Read `guardlex/rules.py`: that is the evidence.

**It abstains rather than guessing.** `cap_rank` returns `None` for a capability
it has not ranked. A caller that reads `None` as "weak" will report whole
administrative cohorts as unguarded. 47% of `current_user_can` calls in one
corpus named a capability outside any fixed table, so this case is the common one
and not the edge.

## On the project names in the comments

Rules cite the project whose idiom forced them: gitea, Discourse, GitLab,
Mattermost, Matomo, Rocket.Chat, Chia, Pontoon. Every one of those citations is
of a guard that project implements **correctly** and that this dictionary was
missing, so they are attribution rather than findings.

Individual plugin names have been removed in favour of the idiom. The teaching
content is the shape of the code, and a list of named plugins next to request
handling detail reads as a target list whatever the intent.

## Where it sits

| | |
|---|---|
| **authz-guard-lexicon** | what counts as a guard, in five languages |
| [wp-hook-guard](https://github.com/kubakozub/wp-hook-guard) | what a request can reach in a WordPress plugin |
| [wp-authz-audit](https://github.com/kubakozub/wp-authz-audit) | which guard dominates each path, and who gets past it |
| [sink-class](https://github.com/kubakozub/sink-class) | whether what it reaches is worth reporting |
| [finding-forge](https://github.com/kubakozub/finding-forge) | write and score the report |

MIT.
