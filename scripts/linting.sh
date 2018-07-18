#!/usr/bin/env bash

FLAKE8=$(which flake8)

ROOT_DIR=$(git rev-parse --show-toplevel)

${FLAKE8} ${ROOT_DIR} ${@}
