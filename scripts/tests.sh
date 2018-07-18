#!/usr/bin/env bash

PYTEST=$(which pytest)

ROOT_DIR=$(git rev-parse --show-toplevel)

${PYTEST} -vv ${ROOT_DIR} ${@}
