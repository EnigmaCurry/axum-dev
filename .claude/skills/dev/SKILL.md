---
name: dev
description: Switch to the dev branch, creating or resetting it from master as needed
disable-model-invocation: true
allowed-tools: Bash(git *)
---

# Switch to dev branch

## Current state

!`git branch --show-current`
!`git status --short`

## Instructions

1. If there are uncommitted changes, warn the user and stop.
2. If already on `dev` and it's up to date with `master`, say so and stop.
3. If a local `dev` branch exists:
   - Check if it has unmerged commits vs `master`. If yes, just switch to it.
   - If it's already merged (i.e. no commits ahead of master), reset it from master.
4. If no local `dev` branch exists, create it from `master`:
   ```bash
   git checkout -b dev master
   git push -u origin dev
   ```
5. Confirm the branch switch.
