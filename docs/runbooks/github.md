# GitHub: pull requests, auto-merge and repository settings

For maintainers. `main` is protected; every change goes through a pull request that merges itself once the
**CI ok** check passes ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), described in the
[README](../../README.md#pull-requests-and-ci)).

## Every pull request

Open the pull request and turn on auto-merge; it merges once CI is green:

```
gh pr create --fill && gh pr merge --auto --squash --delete-branch
```

Enable auto-merge from your own account (as above), not from a workflow: a merge made by the workflow token does not
start other workflows, so the TestFlight upload on `main` would not run.

## One-time repository settings (admin)

```
gh api -X PATCH repos/vfilby/interpose -F allow_auto_merge=true -F delete_branch_on_merge=true
gh api -X PUT repos/vfilby/interpose/private-vulnerability-reporting    # SECURITY.md's reporting channel
gh api -X PUT repos/vfilby/interpose/branches/main/protection --input - <<'EOF'
{"required_status_checks": {"strict": false, "checks": [{"context": "CI ok"}]},
 "required_pull_request_reviews": {"required_approving_review_count": 0},
 "enforce_admins": true, "restrictions": null,
 "required_linear_history": true, "allow_force_pushes": false, "allow_deletions": false}
EOF
```

What that protection means for `main`:
- every change arrives through a pull request (no approving review needed, so you can merge your own);
- the pull request merges only once **CI ok** has passed; `strict: false` means it need not be rebased on the latest
  `main` first;
- the rules bind admins too (`enforce_admins`): no direct pushes, not even by the owner;
- history stays linear (squash merges), and `main` cannot be force-pushed or deleted. To allow force pushes later, set
  `allow_force_pushes` to `true` and run the same command again.

Tags are not covered, so the TestFlight workflow can still push its `ios/v*` tags.

## The hub image on GHCR (once, after the first publish)

[`.github/workflows/docker-publish.yml`](../../.github/workflows/docker-publish.yml) creates the
`ghcr.io/vfilby/interpose-hub` package on its first run, and GHCR makes new packages private. Make it public so hosts
can `docker compose pull` without logging in: on GitHub, your profile → **Packages** → `interpose-hub` → **Package
settings** → **Change visibility** → Public. The image's source label already links it to this repository.
