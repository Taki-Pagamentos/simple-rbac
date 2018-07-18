#!/usr/bin/env bash

MYPY=$(which mypy)

ROOT_DIR=$(git rev-parse --show-toplevel)

${MYPY} ${ROOT_DIR} ${@}
