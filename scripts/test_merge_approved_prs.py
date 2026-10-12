import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import merge_approved_prs as merger


def comment(body="merge", author="carlospolop"):
    return {"body": body, "user": {"login": author}}


def pr(number):
    return {"number": number, "title": "Documentation update", "user": {"login": "contributor"}}


def details(number, **changes):
    return dict(state="OPEN", isDraft=False, mergeable="MERGEABLE", headRefOid=f"head-{number}", **changes)


class ApprovalTests(unittest.TestCase):
    def test_only_the_authorized_whole_comment_approves(self):
        self.assertTrue(merger.is_merge_comment(comment(" MERGE\n")))
        for item in (comment(author="outsider"), comment("please merge"), comment("do not\nmerge")):
            with self.subTest(comment=item):
                self.assertFalse(merger.is_merge_comment(item))

    def test_comments_on_issues_do_not_trigger_merging(self):
        self.assertFalse(merger.should_handle_event("issue_comment", {"issue": {}, "comment": comment()}))
        event = {"issue": {"pull_request": {"url": "https://example.test/pr/1"}}, "comment": comment()}
        self.assertTrue(merger.should_handle_event("issue_comment", event))
        event["comment"] = comment("ordinary discussion")
        self.assertFalse(merger.should_handle_event("issue_comment", event))

    def test_completion_wakes_the_merger_but_its_own_completion_does_not(self):
        self.assertTrue(merger.should_handle_event("workflow_run", {
            "workflow_run": {"name": "Build Master", "status": "completed", "conclusion": "cancelled"},
        }))
        self.assertFalse(merger.should_handle_event("workflow_run", {
            "workflow_run": {"name": merger.WORKFLOW_NAME, "status": "completed"},
        }))
        self.assertTrue(merger.should_handle_event("pull_request_target", {}))
        self.assertTrue(merger.should_handle_event("workflow_dispatch", {}))
        self.assertTrue(merger.should_handle_event("schedule", {}))
        self.assertFalse(merger.should_handle_event("push", {}))

    def test_research_title_exception_is_limited_to_the_authorized_author(self):
        item = {"title": "Research Update Enhanced: topic", "user": {"login": "carlospolop"}}
        self.assertTrue(merger.approved_by_title(item))
        item["user"]["login"] = "outsider"
        self.assertFalse(merger.approved_by_title(item))


class WorkflowActivityTests(unittest.TestCase):
    def test_translator_capacity_allows_one_running_and_no_waiting(self):
        def response(arguments):
            status = arguments[1].split("status=")[1].split("&")[0]
            return {"total_count": 1 if status == "in_progress" else 0}
        with patch.object(merger, "gh_json", side_effect=response):
            self.assertTrue(merger.translator_has_capacity("owner/book"))

    def test_translator_capacity_blocks_any_queued_run_or_two_running(self):
        for blocked_status in ("queued", "waiting", "pending", "requested", "two_running"):
            def response(arguments):
                status = arguments[1].split("status=")[1].split("&")[0]
                count = 2 if status == "in_progress" and blocked_status == "two_running" else int(status == blocked_status)
                return {"total_count": count}
            with self.subTest(status=blocked_status), patch.object(merger, "gh_json", side_effect=response), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(merger.translator_has_capacity("owner/book"))

    def test_translator_capacity_fails_closed_on_bad_api_response(self):
        with patch.object(merger, "gh_json", return_value={"workflow_runs": []}):
            with self.assertRaisesRegex(RuntimeError, "Cannot verify translator"):
                merger.translator_has_capacity("owner/book")

    def test_failed_reads_and_invalid_json_are_not_treated_as_idle(self):
        failed = SimpleNamespace(returncode=1, stderr="API unavailable", stdout="")
        with patch.object(merger.subprocess, "run", return_value=failed), patch.object(merger.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "API unavailable"):
                merger.gh_json(["api", "example"])
        invalid = SimpleNamespace(returncode=0, stderr="", stdout="not JSON")
        with patch.object(merger.subprocess, "run", return_value=invalid):
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                merger.gh_json(["api", "example"])


class MergeFlowTests(unittest.TestCase):
    def run_flow(self, prs, *, snapshots=None, comments=None, target_number=None, max_merges=1, capacity=True):
        def items(endpoint):
            if "/pulls?" in endpoint:
                return prs
            number = int(endpoint.split("/issues/")[1].split("/")[0])
            return (comments or {}).get(number, [comment()])

        def snapshot(repo, number):
            return (snapshots or {}).get(number, details(number))

        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch.object(merger, "api_items", side_effect=items),
            patch.object(merger, "gh_json", return_value=next((item for item in prs if item["number"] == target_number), None)),
            patch.object(merger, "merge_details", side_effect=snapshot),
            patch.object(merger, "translator_has_capacity", return_value=capacity),
            patch.object(merger, "merge_pr", return_value=True) as merge,
        ):
            count = merger.merge_approved("owner/book", max_merges=max_merges, target_number=target_number)
        return count, merge

    def test_comment_event_handles_its_pr_without_scanning_the_queue(self):
        count, merge = self.run_flow([pr(1), pr(2)], target_number=2)
        self.assertEqual(count, 1)
        merge.assert_called_once_with("owner/book", 2, "head-2")

    def test_batch_limit_is_respected(self):
        count, merge = self.run_flow([pr(1), pr(2), pr(3)], max_merges=2)
        self.assertEqual(count, 2)
        self.assertEqual([c.args[1] for c in merge.call_args_list], [1, 2])

    def test_busy_translator_prevents_merge(self):
        count, merge = self.run_flow([pr(1)], capacity=False)
        self.assertEqual(count, 0)
        merge.assert_not_called()

    def test_closed_draft_and_conflicting_prs_are_skipped(self):
        snapshots = {n: details(n) for n in (1, 2, 3)}
        snapshots[1]["state"] = "CLOSED"
        snapshots[2]["isDraft"] = True
        snapshots[3]["mergeable"] = "CONFLICTING"
        count, merge = self.run_flow([pr(1), pr(2), pr(3)], snapshots=snapshots)
        self.assertEqual(count, 0)
        merge.assert_not_called()

    def test_unknown_mergeability_uses_server_side_merge_guard(self):
        unknown = details(1)
        unknown["mergeable"] = "UNKNOWN"
        count, merge = self.run_flow([pr(1)], snapshots={1: unknown})
        self.assertEqual(count, 1)
        merge.assert_called_once_with("owner/book", 1, "head-1")

    def test_comment_verification_failure_never_merges(self):
        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch.object(merger, "api_items", side_effect=[[pr(1)], RuntimeError("API unavailable")]),
            patch.object(merger, "merge_pr") as merge,
        ):
            self.assertEqual(merger.merge_approved("owner/book"), 0)
        merge.assert_not_called()

    def test_paginated_comments_can_authorize_a_pr(self):
        with patch.object(merger, "gh_json", return_value=[[comment(author="outsider")], [comment()]]):
            comments = merger.api_items("example")
        count, merge = self.run_flow([pr(1)], comments={1: comments})
        self.assertEqual(count, 1)
        merge.assert_called_once()

    def test_approval_queue_is_requested_oldest_first_on_every_page(self):
        with patch.object(merger, "api_items", return_value=[]) as request, contextlib.redirect_stdout(io.StringIO()):
            merger.merge_approved("owner/book")
        self.assertIn("sort=created&direction=asc", request.call_args.args[0])

    def test_unknown_mergeability_is_rechecked(self):
        unknown = details(1)
        unknown["mergeable"] = "UNKNOWN"
        ready = details(1)
        with patch.object(merger, "gh_json", side_effect=[unknown, ready]), patch.object(merger.time, "sleep"):
            self.assertEqual(merger.merge_details("owner/book", 1), ready)

    def test_head_change_during_merge_is_rejected(self):
        def server(arguments, **kwargs):
            supplied = arguments[arguments.index("--match-head-commit") + 1] if "--match-head-commit" in arguments else "new-head"
            return SimpleNamespace(returncode=0 if supplied == "new-head" else 1, stderr="Head changed")
        with patch.object(merger.subprocess, "run", side_effect=server), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(merger.merge_pr("owner/book", 1, "old-head"))


if __name__ == "__main__":
    unittest.main()
