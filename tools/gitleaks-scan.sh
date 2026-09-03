#!/bin/bash

# Scan this repository's git history for leaked credentials.
#
# Two things happen here, and the second is the more important one:
#
# 1. gitleaks scans every commit reachable from HEAD -- which on a pull
#    request means the whole of develop plus the branch under test --
#    and the script fails if anything is found.
#
# 2. A positive control proves the scanner can still fire. A detector
#    which reports nothing is indistinguishable from a detector which is
#    broken -- a bad config, a shallow clone, an allowlist which grew
#    until it forgave everything. So we plant a credential in a scratch
#    directory and fail if gitleaks does not report it. Green here means
#    "scanned and found nothing", not "did nothing".
#
# There is no .gitleaks.toml. This library mints no credential of its
# own, so there is no project-specific rule to add and nothing yet to
# allowlist; gitleaks' default ruleset is the whole configuration. If a
# finding ever needs accepting, read the "Accepting a finding" section
# of development/docs/audits/secret-handling.md first -- the choice
# between an allowlist regex and a .gitleaksignore fingerprint is not
# a matter of taste.
#
# Reachability from HEAD, rather than gitleaks' default of every ref, is
# deliberate: scanning every ref is not what anyone means by "scan this
# project's history", and gitleaks 8.16 misattributes the findings it
# produces that way to unrelated merge commits, so they cannot be
# triaged by commit either. On a pull request HEAD reaches the branch
# under test and all of the default branch, so nothing is given up.
#
# The version this was written and tested against is 8.16.0, which is
# what Debian 13 packages and therefore what secret-scan.yml installs.
# Newer 8.x releases supersede `detect` with `gitleaks git` and
# `gitleaks dir`; 8.16 has neither, so `detect` is not merely the older
# spelling here, it is the only one. When the packaged version moves,
# the positive control below is what will notice.
#
# Usage:
#   tools/gitleaks-scan.sh [--gitleaks PATH]
#
# Runs from anywhere inside the working tree -- it changes to the top
# itself -- but the clone must be a full one, not shallow.

set -e

GITLEAKS=gitleaks
while [ $# -gt 0 ]; do
    case "$1" in
        --gitleaks)
            if [ -z "$2" ]; then
                echo "--gitleaks needs a path."
                exit 1
            fi
            GITLEAKS="$2"
            shift 2
            ;;
        *)
            # Refuse rather than ignore. A silently discarded flag would
            # leave the caller believing they had changed the scan.
            echo "Unrecognised argument: $1"
            echo "Usage: tools/gitleaks-scan.sh [--gitleaks PATH]"
            exit 1
            ;;
    esac
done

# A path-like argument is resolved before the cd to the top of the tree
# below, because otherwise `--gitleaks ./gitleaks` passes the check here
# -- which runs in the caller's directory -- and then fails at the first
# real invocation. A bare command name is left alone for $PATH to find.
case "$GITLEAKS" in
    */*) GITLEAKS=$(readlink -f "$GITLEAKS") ;;
esac

if ! command -v "$GITLEAKS" >/dev/null 2>&1 && [ ! -x "$GITLEAKS" ]; then
    echo "gitleaks not found. Install it, or pass --gitleaks PATH."
    echo "It is packaged from Debian 13 (trixie) onward: apt install gitleaks"
    exit 1
fi

# The positive control plants a generated key, so this is a real
# dependency and not just a convenience. secret-scan.yml installs
# gitleaks and assumes the rest of the image, so say which part of the
# rest we mean.
if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ssh-keygen not found; the positive control cannot plant a key."
    echo "Install openssh-client."
    exit 1
fi

echo "Using $("$GITLEAKS" version) from $GITLEAKS"

# A secret committed and then reverted is still in the history and still
# needs rotating. A shallow clone would report a clean history it never
# looked at, which is worse than not running at all.
if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    echo "This is a shallow clone, so most of history cannot be scanned."
    echo "Check out with fetch-depth: 0."
    exit 1
fi

cd "$(git rev-parse --show-toplevel)"

# The positive control. The key is generated here rather than written
# into this file, because a literal one would be found by the real scan
# below -- correctly, since a credential in a committed file is exactly
# what we are looking for.
CONTROL=$(mktemp -d)
trap 'rm -rf "$CONTROL"' EXIT

ssh-keygen -q -t rsa -b 2048 -N '' -C control@example.com \
    -f "$CONTROL/id_rsa"

echo
echo "Positive control: a private key planted in a scratch directory."
set +e
"$GITLEAKS" detect --source "$CONTROL" --no-git \
    --redact --no-banner --report-path "$CONTROL/report.json" \
    --report-format json
control_status=$?
set -e

# gitleaks may have exited before writing a report at all -- an
# unrecognised flag, a permissions error, a subcommand that has been
# retired under us. Reading the file regardless turns that into a
# FileNotFoundError traceback, which fails closed but buries the one
# message the reader actually needs under a Python stack.
if [ ! -f "$CONTROL/report.json" ]; then
    echo
    echo "The positive control failed: gitleaks wrote no report (it"
    echo "exited $control_status). It did not decline to find the planted"
    echo "key -- it never got as far as looking."
    echo
    echo "Do not trust a clean scan until this passes."
    exit 1
fi

found=$(python3 -c "
import json

with open('$CONTROL/report.json') as f:
    print(' '.join(sorted({x['RuleID'] for x in json.load(f)})), end='')
")

case " $found " in
    *" private-key "*) ;;
    *)
        echo
        echo "The positive control failed: gitleaks did not report the"
        echo "private-key rule against a key planted for it to find."
        echo "Rules which did fire: ${found:-none}."
        echo
        echo "Do not trust a clean scan until this passes."
        exit 1
        ;;
esac

if [ $control_status -eq 0 ]; then
    echo "The positive control did not set a failure exit code."
    exit 1
fi

echo "Positive control passed: the planted credential was reported."
echo

# The real scan.
echo "Scanning every commit reachable from HEAD."
"$GITLEAKS" detect --source . --log-opts="HEAD" --redact --verbose \
    --no-banner
