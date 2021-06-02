#!/usr/bin/env bash

# Copyright The CrowdStrike Community
# See License for more info

# set -o errexit
set -o nounset
# set -o pipefail

install_image_scan() {
    local cs_py="cs_scanimage.py"
    if [[ ! -f "$GITHUB_ACTION_PATH/$cs_py" ]]; then
        echo "Installing container-image-scan..."
        local latest_pkg=$(curl -s https://api.github.com/repos/crowdstrike/container-image-scan/releases/latest | jq -r '.assets[0].browser_download_url')
        curl -sSLo scan.tar.gz ${latest_pkg}
        tar -xzf scan.tar.gz
        rm -f scan.tar.gz
    fi
}

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
      -s|--score_threshold)
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

    install_image_scan

    if [ "$#" -gt 1 ]; then
        opts=$(parse_args "$@" || exit 1)

        python3 cs_scanimage.py $opts
        EXIT_CODE=$?
        echo "::set-output name=exit-code::$EXIT_CODE"
        exit $EXIT_CODE
    else
        python3 cs_scanimage.py
        EXIT_CODE=$?
        echo "::set-output name=exit-code::$EXIT_CODE"
        exit $EXIT_CODE
    fi
}

main "$@"
