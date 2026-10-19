#!/usr/bin/env bash
# Encrypts one value for a SopsSecret's encryptedData and prints it as one base64 line: the binary
# age file of the line "<namespace>/<name>/<key>" followed by the value. The value is read from
# value-file, from stdin, or from a hidden prompt, never from the command line.
#
#   hack/encrypt-value.sh team-a.pub team-a-foo/db-credentials password
#   hack/encrypt-value.sh team-a.pub team-a-foo/tls tls.crt tls.crt
#
# recipients-file holds the tenant's public key (status.publicKey), one recipient per line.
# AGE overrides the age binary.
set -euo pipefail

usage() {
	echo "usage: $0 <recipients-file> <namespace>/<name> <key> [value-file]" >&2
	exit 2
}
[ $# -ge 3 ] && [ $# -le 4 ] || usage
recipients=$1 target=$2 key=$3 file=${4:-}
if ! [[ $target =~ ^[^/]+/[^/]+$ ]]; then
	echo "$0: expected <namespace>/<name>, got '$target'" >&2
	exit 2
fi
if ! [[ $key =~ ^[-._a-zA-Z0-9]+$ ]]; then
	echo "$0: '$key' is not a valid Secret key" >&2
	exit 2
fi

value() {
	if [ -n "$file" ]; then
		cat -- "$file"
	elif [ -t 0 ]; then
		IFS= read -r -s -p "Value for $key: " v
		echo >&2
		printf '%s' "$v"
	else
		cat
	fi
}

{ printf '%s/%s\n' "$target" "$key"; value; } | "${AGE:-age}" -R "$recipients" | base64 | tr -d '\n'
echo
