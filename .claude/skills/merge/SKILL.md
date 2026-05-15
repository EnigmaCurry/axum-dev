---
name: merge
description: Squash-merge the open PR, pull master, and reset dev branch
disable-model-invocation: true
allowed-tools: Bash(git *, gh *)
---

# Merge PR and Reset

## Instructions

1. Check the current branch with `git branch --show-current`. If not on `dev`, abort.

2. Find the open PR for dev → master:
   ```bash
   gh pr list --head dev --base master --state open --json number,title,url
   ```
   If no open PR exists, abort with an error message.

3. Squash-merge the PR:
   ```bash
   gh pr merge NUMBER --squash --delete-branch
   ```
   This will also delete the remote `dev` branch.

4. Switch to master and pull:
   ```bash
   git checkout master
   git pull
   ```

5. Delete the local dev branch if it still exists:
   ```bash
   git branch -D dev 2>/dev/null || true
   ```

6. Report success with the merged PR URL and the new commit on master.
