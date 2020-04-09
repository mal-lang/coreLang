#!/bin/sh

set -e

mkdir -p "$HOME/.aws"

if [ -v FORESEETI_USERNAME ] && [ -v FORESEETI_PASSWORD ]; then
  cat << EOF > "$HOME/.aws/credentials"
[default]
aws_access_key_id=$FORESEETI_USERNAME
aws_secret_access_key=$FORESEETI_PASSWORD
EOF

  mvn -B -V -PsecuriCAD clean verify site
else
  mvn -B -V clean verify site
fi
