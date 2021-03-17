#!/usr/bin/env bash

# Copyright The CrowdStrike Community
# See License for more info

set -o errexit
set -o nounset
set -o pipefail

parse_args() {
  local opts=""
  while (( "$#" )); do
    case "$1" in
      -u|--clientid)
        if [[ -n ${2:-} ]] ; then
             opts="$opts $1 $2"
             shift
        fi
        ;;
      -r|--repo)
        if [[ -n ${2:-} ]]; then
            opts="$opts $1 $2"
            shift
        fi
        ;;
      -t|--tag)
        if [[ -n ${2:-} ]]; then
            opts="$opts $1 $2"
            shift
        fi
        ;;
      -c|--cloud)
        if [[ -n ${2:-} ]]; then
            opts="$opts $1 $2"
            shift
        fi
        ;;
      --) # end argument parsing
        shift
        break
        ;;
      -*) # unsupported flags
        >&2 echo "ERROR: Unsupported flag: '$1'"
        exit 1
        ;;
    esac
    shift
  done

  # set remaining positional arguments (if any) in their proper place
  eval set -- "$opts"

  echo "${opts/ /}"
  return 0
}

main() {
    local opts

    if [ "$#" -gt 1 ]; then
        opts=$(parse_args "$@" || exit 1)

        python3 cs_scanimage.py $opts
    else
        python3 cs_scanimage.py
    fi
}

main "$@"
