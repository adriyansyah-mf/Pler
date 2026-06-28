#!/bin/sh
set -e
mkdir -p /var/log/pler /run/pler
systemctl daemon-reload
systemctl enable --now pler
