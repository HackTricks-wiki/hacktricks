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
    def test_a_busy_workflow_on_a_later_page_is_detected(self):
        pages = [
            {"workflow_runs": [{"workflow_id": 7, "status": "in_progress"}] * 100},
            {"workflow_runs": [{"workflow_id": 8, "status": "in_progress", "name": "Build"}]},
        ]
        with patch.object(merger, "gh_json", return_value=pages) as request, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(merger.other_workflows_active("owner/book", 7))
        self.assertIn("--paginate", request.call_args.args[0])
        self.assertIn("--slurp", request.call_args.args[0])

    def test_pending_merger_instances_do_not_block_the_merger(self):
        pages = [{"workflow_runs": [{"workflow_id": 7, "status": "queued"}]}]
        with patch.object(merger, "api_pages", return_value=pages) as request:
            self.assertFalse(merger.other_workflows_active("owner/book", 7))
        self.assertEqual(request.call_count, 2 * len(merger.ACTIVE_STATUSES))

    def test_each_active_status_blocks_merging(self):
        for status in merger.ACTIVE_STATUSES:
            def pages(endpoint):
                runs = [{"workflow_id": 8, "status": status, "name": "Other"}] if f"status={status}&" in endpoint else []
                return [{"workflow_runs": runs}]
            with self.subTest(status=status), patch.object(merger, "api_pages", side_effect=pages), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(merger.other_workflows_active("owner/book", 7))

    def test_running_feed_maintenance_keeps_the_base_stable_without_disabling(self):
        def pages(endpoint):
            if "HackTricks-Feed" in endpoint and "status=in_progress&" in endpoint:
                return [{"workflow_runs": [{"name": "Saturday HackTricks conflict repair", "status": "in_progress"}]}]
            return [{"workflow_runs": []}]
        with patch.object(merger, "api_pages", side_effect=pages), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(merger.other_workflows_active("owner/book", 7))

    def test_unrelated_feed_jobs_do_not_stop_merging(self):
        def pages(endpoint):
            runs = [{"name": "Daily updater", "status": "in_progress"}] if "HackTricks-Feed" in endpoint else []
            return [{"workflow_runs": runs}]
        with patch.object(merger, "api_pages", side_effect=pages):
            self.assertFalse(merger.other_workflows_active("owner/book", 7))

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
    def run_flow(self, prs, *, activity=(False, False, False), snapshots=None, comments=None):
        def items(endpoint):
            if "/pulls?" in endpoint:
                return prs
            number = int(endpoint.split("/issues/")[1].split("/")[0])
            return (comments or {}).get(number, [comment()])

        def snapshot(repo, number):
            return (snapshots or {}).get(number, details(number))

        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch.object(merger, "other_workflows_active", side_effect=activity),
            patch.object(merger, "api_items", side_effect=items),
            patch.object(merger, "merge_details", side_effect=snapshot),
            patch.object(merger, "merge_pr", return_value=True) as merge,
        ):
            count = merger.merge_approved("owner/book", 7)
        return count, merge

    def test_an_initially_busy_repository_does_not_merge(self):
        count, merge = self.run_flow([pr(1)], activity=(True,))
        self.assertEqual(count, 0)
        merge.assert_not_called()

    def test_a_workflow_starting_during_approval_collection_blocks_the_merge(self):
        count, merge = self.run_flow([pr(1)], activity=(False, True))
        self.assertEqual(count, 0)
        merge.assert_not_called()

    def test_a_build_queued_by_the_first_merge_stops_the_batch(self):
        count, merge = self.run_flow([pr(1), pr(2)], activity=(False, False, True))
        self.assertEqual(count, 1)
        merge.assert_called_once_with("owner/book", 1, "head-1")

    def test_no_more_than_two_prs_are_merged_per_batch(self):
        count, merge = self.run_flow([pr(1), pr(2), pr(3)])
        self.assertEqual(count, 2)
        self.assertEqual([c.args[1] for c in merge.call_args_list], [1, 2])

    def test_closed_draft_and_conflicting_prs_are_skipped(self):
        snapshots = {n: details(n) for n in (1, 2, 3)}
        snapshots[1]["state"] = "CLOSED"
        snapshots[2]["isDraft"] = True
        snapshots[3]["mergeable"] = "CONFLICTING"
        count, merge = self.run_flow([pr(1), pr(2), pr(3)], activity=(False,), snapshots=snapshots)
        self.assertEqual(count, 0)
        merge.assert_not_called()

    def test_comment_verification_failure_never_merges(self):
        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch.object(merger, "other_workflows_active", return_value=False),
            patch.object(merger, "api_items", side_effect=[[pr(1)], RuntimeError("API unavailable")]),
            patch.object(merger, "merge_pr") as merge,
        ):
            self.assertEqual(merger.merge_approved("owner/book", 7), 0)
        merge.assert_not_called()

    def test_paginated_comments_can_authorize_a_pr(self):
        with patch.object(merger, "gh_json", return_value=[[comment(author="outsider")], [comment()]]):
            comments = merger.api_items("example")
        count, merge = self.run_flow([pr(1)], comments={1: comments})
        self.assertEqual(count, 1)
        merge.assert_called_once()

    def test_approval_queue_is_requested_oldest_first_on_every_page(self):
        with patch.object(merger, "other_workflows_active", return_value=False), patch.object(merger, "api_items", return_value=[]) as request, contextlib.redirect_stdout(io.StringIO()):
            merger.merge_approved("owner/book", 7)
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
