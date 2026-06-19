#!/bin/sh
#
# A simple wrapper around flake8 which makes it possible
# to ask it to only verify files changed in the current
# git HEAD patch.
#
# Intended to be invoked via tox:
#
#   tox -eflake8 -- -HEAD
#
# Originally from the OpenStack project.

FLAKE_COMMAND="flake8 --max-line-length=120"

if test "x$1" = "x-HEAD" ; then
    shift
    # Only the Python files changed since HEAD~1. flake8 removed the --diff
    # option in 6.0, so run flake8 directly on the changed files instead of
    # piping a diff through it.
    files=$(git diff --name-only HEAD~1 | grep '\.py$' | tr '\n' ' ')
    if test -z "$(echo ${files} | tr -d ' ')" ; then
        echo "No changed Python files to check"
        exit 0
    fi
    echo "Running flake8 on ${files}"
    exec $FLAKE_COMMAND ${files} "$@"
else
    echo "Running flake8 on all files"
    exec $FLAKE_COMMAND "$@"
fi
