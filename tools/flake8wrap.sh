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
    # Check only the Python files changed since HEAD~1. flake8 removed the
    # --diff option in 6.0, so run flake8 directly on the changed files. We
    # use --diff-filter=d to exclude deleted files (which no longer exist on
    # disk and would make flake8 error), and skip generated *_pb2.py protobuf
    # stubs.
    filtered_files=$(git diff --name-only --diff-filter=d HEAD~1 \
        | grep '\.py$' | grep -v '_pb2' | tr '\n' ' ')
    if test -z "$(echo ${filtered_files} | tr -d ' ')" ; then
        echo "No changed Python files to check"
        exit 0
    fi
    echo "Running flake8 on ${filtered_files}"
    # Intentionally unquoted so the shell splits the list into separate
    # arguments for flake8.
    # shellcheck disable=SC2086
    exec $FLAKE_COMMAND ${filtered_files} "$@"
else
    echo "Running flake8 on all files"
    exec $FLAKE_COMMAND "$@"
fi
