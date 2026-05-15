---
name: pr-draft
description: Push dev branch and create a draft GitHub PR to master (auto-generates title/body from commits)
disable-model-invocation: true
allowed-tools: Bash(git *, gh *)
---

# Create Draft Pull Request

## Current state

!`git branch --show-current`
!`git status --short`
!`git log master..HEAD --oneline 2>/dev/null`

## Instructions

1. Verify we are on the `dev` branch. If not, abort with an error.
2. If there are uncommitted changes, commit them with an appropriate message first.
3. Push the dev branch: `git push -u origin dev`
4. Check if a PR already exists for dev → master:
   ```bash
   gh pr list --head dev --base master --state open --json number,title,url
   ```
   - If a PR exists, show its URL and stop (don't create a duplicate).
5. Auto-generate the PR title and body from commit history:
   - Title: A concise summary of the changes (under 70 characters).
   - Body: Summary bullet points derived from `git log master..dev --oneline`.
6. Create the draft PR:
   ```bash
   gh pr create --draft --base master --head dev --title "THE TITLE" --body "THE BODY"
   ```
7. Show the PR URL when done.
