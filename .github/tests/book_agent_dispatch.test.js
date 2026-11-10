const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const workflow = fs.readFileSync(path.join(__dirname, '../workflows/book_agent_dispatch.yml'), 'utf8');
const script = workflow.split('          script: |\n')[1].split('\n').map(line => line.slice(12)).join('\n');
const run = new AsyncFunction('github', 'context', 'core', script);

async function dispatch({ author = 'sarrus1811', mergeable = false, event = 'pull_request_target', probe = false } = {}) {
  const calls = [];
  const pr = { number: 3300, state: 'open', user: { login: author }, mergeable, draft: false, body: '', head: { ref: 'proposal' }, created_at: new Date().toISOString() };
  const github = {
    rest: {
      pulls: { get: async () => ({ data: pr }), list: 'pulls', listFiles: 'files' },
      issues: { listComments: 'comments' },
      repos: { compareCommits: async () => ({ data: { files: [{ filename: 'src/page.md' }] } }) },
      actions: { createWorkflowDispatch: async args => calls.push(args) },
    },
    paginate: async endpoint => {
      if (endpoint === 'pulls') return [pr];
      if (endpoint === 'files') { calls.push('inspect-files'); return [{ filename: 'src/page.md' }]; }
      return [];
    },
  };
  const context = { repo: { owner: 'HackTricks-wiki', repo: 'hacktricks' }, eventName: event, payload: { inputs: { pr: '3300', probe: String(probe) }, pull_request: { number: 3300 }, before: 'a'.repeat(40), after: 'b'.repeat(40) } };
  await run(github, context, { info() {}, warning() {} });
  return calls;
}

for (const event of ['pull_request_target', 'push', 'schedule', 'workflow_dispatch']) {
  test(`${event}: skip other authors before file inspection or dispatch`, async () => {
    assert.deepEqual(await dispatch({ event }), []);
  });
}
test('unknown mergeability does not delay or dispatch another author', async () => {
  assert.deepEqual(await dispatch({ mergeable: null }), []);
});
test('manual connection probes cannot dispatch another author', async () => {
  assert.deepEqual(await dispatch({ event: 'workflow_dispatch', probe: true }), []);
});
test('owner conflicts still dispatch the fixer', async () => {
  const calls = await dispatch({ author: 'Carlospolop' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].workflow_id, 'book-conflict-fix.yml');
});
test('clean owner PRs still dispatch review', async () => {
  const calls = await dispatch({ author: 'carlospolop', mergeable: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].workflow_id, 'book-pr-review.yml');
});
