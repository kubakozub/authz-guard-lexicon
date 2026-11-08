#!/usr/bin/env python3
"""Two sided controls for every rule.

The first half is easy: a rule must fire on the case that forced it. The second
half is the one that matters, because a rule that fires on everything passes the
first half perfectly. So every rule also has a case it must stay SILENT on.

The cases live in `guardlex.CASES` rather than inside a test, so a failure names
WHICH rule and WHICH text instead of saying "selftest failed".

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import guardlex  # noqa: E402
from guardlex import CASES, CONTEXT_RULES, JS_PAIRS, RULES, is_guarded  # noqa: E402
from guardlex.cli import (EXIT_ERROR, EXIT_GUARDED, EXIT_UNGUARDED,  # noqa: E402
                          main)
from guardlex.rules import (HANDLER_JS_GUARDED, HANDLER_JS_UNGUARDED,
                            WEBHOOK_JS_GUARDED, WEBHOOK_JS_UNGUARDED,
                            cap_rank, chia_p2p_handlers, django_anonymous_views,
                            go_unauthed_handlers, grape_anonymous_routes,
                            is_plugin_namespaced_capability, is_preauth_endpoint,
                            rails_anonymous_actions, selftest,
                            selftest_js_pairs)


def name_of(rule):
    """A readable label for a compiled pattern or a probe."""
    for name, pattern, _ in list(RULES) + list(CONTEXT_RULES):
        if rule is pattern:
            return name
    return getattr(rule, "name", None) or getattr(rule, "pattern", "")[:28] or "rule"


class Controls(unittest.TestCase):
    """Every case in the corpus, each one named."""

    def test_every_case_matches_its_expectation(self):
        for index, (rule, text, want) in enumerate(CASES):
            label = "%s[%d] %r" % (name_of(rule), index, text[:48])
            with self.subTest(case=label):
                got = bool(rule.search(text))
                self.assertEqual(got, want,
                                 "%s: expected %s, got %s" % (label, want, got))

    def test_the_corpus_has_both_halves(self):
        """A corpus of positives only proves a rule is not silent, nothing more."""
        positives = sum(1 for _, _, want in CASES if want)
        negatives = len(CASES) - positives
        self.assertGreaterEqual(positives, 40)
        self.assertGreaterEqual(negatives, 20, "too few negative controls")

    def test_every_guard_rule_appears_in_the_corpus(self):
        """A rule with no control is a rule nobody can change safely."""
        covered = {name_of(rule) for rule, _, _ in CASES}
        for name, _, _ in list(RULES) + list(CONTEXT_RULES):
            if name == "AUTHZ_PREDICATE":
                continue  # exercised through is_guarded rather than directly
            with self.subTest(rule=name):
                self.assertIn(name, covered)

    def test_selftest_agrees(self):
        self.assertEqual(selftest(), [])


class WholePath(unittest.TestCase):
    """is_guarded end to end, not one pattern at a time.

    A rule that fires on a snippet and stays silent on a real handler is worth
    nothing, so these run the full decision over realistic bodies.
    """

    def test_a_guarded_js_handler_is_recognised(self):
        guarded, rule = is_guarded(HANDLER_JS_GUARDED)
        self.assertTrue(guarded, "a session check was not recognised")
        self.assertTrue(rule)

    def test_an_unguarded_js_handler_speaks_up(self):
        guarded, _ = is_guarded(HANDLER_JS_UNGUARDED)
        self.assertFalse(guarded, "an unguarded handler was silenced")

    def test_a_verified_webhook_is_recognised(self):
        guarded, _ = is_guarded(WEBHOOK_JS_GUARDED)
        self.assertTrue(guarded)

    def test_an_unverified_webhook_speaks_up(self):
        guarded, _ = is_guarded(WEBHOOK_JS_UNGUARDED)
        self.assertFalse(guarded)

    def test_the_js_pairs_agree(self):
        self.assertEqual(selftest_js_pairs(), [])

    def test_admin_gate_can_be_excluded(self):
        """Asking the narrower question: a guard OTHER than an admin gate."""
        for body in ("if !IsSystemAdmin() { return }", "return unless is_admin?"):
            with self.subTest(body=body):
                self.assertTrue(is_guarded(body)[0])
                self.assertFalse(is_guarded(body, admin_counts=False)[0])

    def test_admin_counts_does_nothing_on_wordpress_code(self):
        """A documented limitation, pinned so it cannot be forgotten.

        AUTHZ_CALL is consulted before ADMIN_GATE and matches
        `current_user_can(...)` whatever capability is named, so a caller asking
        for "a guard other than an admin gate" gets True on WordPress code
        regardless. Narrowing it properly means ranking the capability, which is
        what cap_rank is for.
        """
        body = "if (!current_user_can('manage_options')) { return; }"
        self.assertEqual(is_guarded(body), (True, "AUTHZ_CALL"))
        self.assertEqual(is_guarded(body, admin_counts=False), (True, "AUTHZ_CALL"))

    def test_an_empty_body_is_not_guarded(self):
        for body in ("", "   \n\t ", "return;"):
            with self.subTest(body=body):
                self.assertFalse(is_guarded(body)[0])


class Capabilities(unittest.TestCase):
    def test_a_strong_capability_outranks_a_weak_one(self):
        self.assertGreater(cap_rank("manage_options"), cap_rank("read"))

    def test_an_unknown_capability_abstains(self):
        """None means abstain. A caller treating it as weak reports whole
        administrative cohorts as unguarded, which is a false positive that
        looks exactly like a finding."""
        self.assertIsNone(cap_rank("acme_some_invented_capability"))

    def test_a_plugin_namespaced_capability_is_recognised(self):
        """A plugin that builds its own permission model: abstaining on those
        means abstaining on the interesting case, a handler that falls out of
        the plugin's own model into a weaker core capability."""
        self.assertTrue(is_plugin_namespaced_capability(
            "acme_settings", "acme_", "acme"))
        self.assertFalse(is_plugin_namespaced_capability("read", "acme_", "acme"))


class PreAuth(unittest.TestCase):
    """A login screen is not a finding, and the method name is not enough."""

    def test_a_name_that_says_login(self):
        self.assertTrue(is_preauth_endpoint("acme_forgot_password", ""))
        self.assertTrue(is_preauth_endpoint("resetPassword", ""))

    def test_a_path_that_says_login_where_the_name_does_not(self):
        self.assertTrue(is_preauth_endpoint(
            "create", "app/controllers/session_controller.rb"))

    def test_an_ordinary_handler_is_not_pre_auth(self):
        self.assertFalse(is_preauth_endpoint(
            "update", "app/controllers/invoices_controller.rb"))


class RubyProbes(unittest.TestCase):
    def test_a_controller_with_requires_login_is_silent(self):
        source = ("class TopicsController < ApplicationController\n"
                  "  requires_login\n"
                  "  def show\n    render json: @topic\n  end\nend\n")
        self.assertEqual(rails_anonymous_actions(source), [])

    def test_a_controller_without_a_guard_speaks_up(self):
        source = ("class TopicsController < ApplicationController\n"
                  "  def show\n    render json: Topic.find(params[:id])\n  end\nend\n")
        self.assertTrue(rails_anonymous_actions(source))

    def test_a_multiline_only_list_is_parsed(self):
        """A regex anchored on end of line read the argument list as empty,
        concluded the whole controller was closed, and lost 38 open actions."""
        source = ("class UsersController < ApplicationController\n"
                  "  requires_login only: %i[\n    username\n    update\n  ]\n"
                  "  def show\n    render json: @user\n  end\n"
                  "  def username\n    head :ok\n  end\nend\n")
        found = {action for action, *_ in
                 [(a,) if isinstance(a, str) else a
                  for a in rails_anonymous_actions(source)]}
        self.assertIn("show", str(found), "an action outside only: should be open")

    def test_a_grape_class_without_authenticate_is_open(self):
        source = ("module API\n  class Projects < ::API::Base\n"
                  "    get ':id' do\n      present project\n    end\n  end\nend\n")
        self.assertTrue(grape_anonymous_routes(source))


class PythonAndGoProbes(unittest.TestCase):
    def test_a_django_view_open_to_anonymous(self):
        source = ("@csrf_exempt\ndef public_thing(request):\n"
                  "    return JsonResponse({})\n")
        self.assertTrue(django_anonymous_views(source))

    def test_the_whole_decorator_stack_is_read(self):
        """A pattern anchored on @csrf_exempt saw only the decorators below it,
        so a group requirement above was invisible."""
        source = ('@group_required("Staff")\n@require_POST\n@csrf_exempt\n'
                  "def create_test_user(request):\n    return HttpResponse()\n")
        found = [name for name, *_ in django_anonymous_views(source) or []]
        self.assertNotIn("create_test_user", found,
                         "a decorator above @csrf_exempt was missed")

    def test_a_chia_protocol_handler_is_unauthenticated_surface(self):
        source = ("@metadata.request(peer_required=True)\n"
                  "async def new_peak(self, request):\n    return None\n")
        self.assertTrue(chia_p2p_handlers(source))

    def test_a_go_handler_outside_the_auth_group(self):
        source = 'api.GET("/thing", h.getThing)\n'
        self.assertIsNotNone(go_unauthed_handlers(source))


class Performance(unittest.TestCase):
    """A regression test for backtracking, not a benchmark.

    This module is meant to be run over arbitrary source, including minified
    JavaScript on a single line. One branch of INBAND_AUTH had an unbounded
    \\w* before a keyword alternation, which made it quadratic in the input:
    20000 characters of one word took 6.7 seconds and the whole suite took 13.
    Bounding the identifier to 40 characters took the same input to 0.03s.

    The bound here is deliberately loose, a second rather than a tenth, so this
    fails on a return of the quadratic behaviour and not on a slow CI runner.
    """

    def test_no_rule_is_quadratic_in_the_input(self):
        import time
        hostile = {
            "one long word": "a" * 20000,
            "many dollar variables": "$x " * 2000,
            "repeated comparison": "if ($a == $b) { " * 800,
            "open parens": "(" * 2000,
            "long key like identifier": "$" + "k" * 500 + "_key == $x",
        }
        for name, pattern, _ in list(RULES) + list(CONTEXT_RULES):
            for label, text in hostile.items():
                start = time.perf_counter()
                pattern.search(text)
                elapsed = time.perf_counter() - start
                with self.subTest(rule=name, input=label):
                    self.assertLess(elapsed, 1.0,
                                    "%s took %.2fs on %s" % (name, elapsed, label))

    def test_is_guarded_is_fast_on_a_realistic_file(self):
        import time
        body = ("function handler() {\n  $id = $_GET['id'];\n"
                "  return get_post($id);\n}\n") * 500
        start = time.perf_counter()
        is_guarded(body)
        self.assertLess(time.perf_counter() - start, 1.0)


class Cli(unittest.TestCase):
    def _main(self, argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        keep = sys.stdout, sys.stderr, sys.stdin
        sys.stdout, sys.stderr = out, err
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr, sys.stdin = keep
        return code, out.getvalue(), err.getvalue()

    def test_check_exits_zero_when_guarded(self):
        code, out, _ = self._main(["check", "-"],
                                  stdin="if (!current_user_can('edit_posts')) return;")
        self.assertEqual(code, EXIT_GUARDED)
        self.assertIn("guarded by", out)

    def test_check_exits_one_when_not_guarded(self):
        code, out, _ = self._main(["check", "-"], stdin='echo $_GET["x"];')
        self.assertEqual(code, EXIT_UNGUARDED)
        self.assertIn("no recognised guard", out)

    def test_check_on_a_missing_file_exits_two(self):
        code, _, err = self._main(["check", "/nonexistent/path.php"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not a file", err)

    def test_rules_lists_every_rule(self):
        code, out, _ = self._main(["rules"])
        self.assertEqual(code, EXIT_GUARDED)
        for name, _, _ in list(RULES) + list(CONTEXT_RULES):
            self.assertIn(name, out)

    def test_rules_json_is_valid(self):
        import json
        _, out, _ = self._main(["rules", "--json"])
        data = json.loads(out)
        self.assertEqual(len(data["guards"]), len(RULES))

    def test_selftest_exits_zero(self):
        code, _, _ = self._main(["selftest"])
        self.assertEqual(code, EXIT_GUARDED)

    def test_anon_refuses_an_extension_it_has_no_probe_for(self):
        """Guessing the language from the extension is how every .ts and .go
        file once got parsed with the Ruby rules."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".php", mode="w", delete=False) as handle:
            handle.write("<?php echo 1;")
            path = handle.name
        code, _, err = self._main(["anon", path])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no probe for", err)


class Contract(unittest.TestCase):
    def test_the_public_api_is_importable(self):
        for name in guardlex.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(guardlex, name), name)

    def test_no_rule_raises_on_odd_input(self):
        for text in ("", "\x00\x01", "(" * 500, "a" * 20000, "{$"):
            with self.subTest(text=text[:12]):
                for _, pattern, _ in list(RULES) + list(CONTEXT_RULES):
                    pattern.search(text)
                is_guarded(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
