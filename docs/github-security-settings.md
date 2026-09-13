# GitHub security settings

Three of this repository's security controls are configured on GitHub
rather than in the checkout: Dependabot security updates, secret
scanning, and secret scanning push protection. They are written down
here because nothing in the repository records them. The daily
`export-repo-config.yml` run exports merge and feature settings into
`.github/exported-config/repository-settings.json`, but that export
does not include `security_and_analysis`, so turning one of these off
leaves no diff for anyone to notice.

The shared audit that requires them is
[development/docs/audits/github-security.md](https://github.com/shakenfist/development/blob/main/docs/audits/github-security.md).

## What is enabled, and why each one

### Secret scanning and push protection

These are not a duplicate of `secret-scan.yml`, which runs gitleaks
over the full history on pull requests and on pushes to `develop`.
They sit at a different point in the timeline, and the difference is
the whole point:

* **Push protection** rejects the push. The credential never reaches
  GitHub, so there is nothing to rotate.
* **gitleaks in CI** tells you a credential is already in the history.
  By then the only safe response is to rotate it, because rewriting
  the history does not un-publish what a public repository served in
  the meantime.

Keep both. Push protection only knows GitHub's provider patterns and
only sees the push; gitleaks reads every file including docs and plans,
and `tools/gitleaks-scan.sh` plants a credential and fails if the
scanner misses it, so a green run means the scanner actually looked.

### Dependabot security updates

This is the advisory-driven half of Dependabot, not its version
updates, and it coexists with Renovate rather than competing with it.
Renovate proposes routine bumps on the schedule in `renovate.json`,
which sets `minimumReleaseAge` to three days — a deliberate soak that
a security fix should not have to wait out. Dependabot security
updates open a pull request as soon as an advisory lands.

Do **not** enable Dependabot *version* updates (a
`.github/dependabot.yml` with an `updates:` block). That is the part
that would duplicate Renovate, and two bots proposing the same bump is
how a dependency dashboard stops being read.

Security updates sit on top of Dependabot *alerts* and cannot be
turned on without them. Enabling only the fixes fails with a 422 and
"Vulnerability alerts must be enabled to configure automated security
fixes", which is easy to misread as a permissions problem. Alerts are
a separate endpoint, and `GET` on it answers 404 rather than a body
when they are off:

```bash
gh api -X PUT repos/shakenfist/library-utilities/vulnerability-alerts
gh api -X PUT repos/shakenfist/library-utilities/automated-security-fixes
```

## CodeQL

`.github/workflows/codeql-analysis.yml` is a copy of
`development/templates/codeql/codeql-analysis.yml`, unmodified — the
template already targets `develop`. It belongs here only because this
repository is public: CodeQL needs a paid Advanced Security licence on
private repositories, so a private repository that adds this workflow
gets a permanently failing job rather than scanning.

The job-level `actions: read` permission is load bearing. Without it
CodeQL cannot read workflow run telemetry and fails with "Resource not
accessible by integration".

## Verifying the settings

The settings have no local representation, so check them against the
API:

```bash
gh api repos/shakenfist/library-utilities \
    --jq '.security_and_analysis'
```

All of `dependabot_security_updates`, `secret_scanning` and
`secret_scanning_push_protection` should report `"status": "enabled"`.
The consistency audit checks the latter two every morning and files an
issue when they regress; it does not check the first, so that one is
only caught by looking.

In the web UI the same settings live under **Settings** > **Advanced
Security**.
