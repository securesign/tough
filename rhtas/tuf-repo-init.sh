#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat << EOF
Usage: $(basename "${BASH_SOURCE[0]}") [OPTION] [TUF_REPO_PATH]

Initialize a TUF repository with given targets in TUF_REPO_PATH.

Options:
  -h, --help
    Display this help message

  --export-keys
    Where to save keys - either a file:///path/to/dir or a string - k8s secret name

  --fulcio-cert
    Fulcio certificate chain file

  --tsa-cert
    TSA certificate chain file

  --ctlog-key
    CTLog public key file

  --rekor-key
    Rekor public key file

  --metadata-expiration
    Tuftool-compatible tetadata expiration time; defaults to 56 weeks
EOF
}

export TUF_REPO_PATH=""
export EXPORT_KEYS=""
export FULCIO_CERT=""
export TSA_CERT=""
export CTLOG_KEY=""
export REKOR_KEY=""
export METADATA_EXPIRATION="in 52 weeks"

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      shift
      usage
      exit
      ;;
    --export-keys)
      EXPORT_KEYS="$2"
      shift
      shift
      ;;
    --fulcio-cert)
      FULCIO_CERT="$2"
      shift
      shift
      ;;
    --tsa-cert)
      TSA_CERT="$2"
      shift
      shift
      ;;
    --ctlog-key)
      CTLOG_KEY="$2"
      shift
      shift
      ;;
    --rekor-key)
      REKOR_KEY="$2"
      shift
      shift
      ;;
    --metadata-expiration)
      METADATA_EXPIRATION="$2"
      shift
      shift
      ;;
    -*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      if [ -n "${TUF_REPO_PATH}" ]; then
        echo "Only expected one positional argument"
        usage
        exit 1
      fi
      TUF_REPO_PATH="$1"
      shift
      ;;
  esac
done

if [ -z "${TUF_REPO_PATH}" ]; then
  echo "TUF repo path not specified"
  usage
  exit 1
fi

if [ -e "${TUF_REPO_PATH}/root.json" ]; then
  echo "Repo seems to already be initialized (${TUF_REPO_PATH}/root.json exists)"
  exit 1
fi

export WORKDIR=""
WORKDIR=$(mktemp -d /tmp/tuf.XXXX)

echo "Initializing TUF repository in ${WORKDIR} ..."

export ROOT="${WORKDIR}/root/root.json"
export INPUTDIR="${WORKDIR}/input"
export KEYDIR="${WORKDIR}/keys"
export ROOTDIR="${WORKDIR}/root"
export OUTDIR="${WORKDIR}/tuf-repo"
mkdir -p "${ROOTDIR}" "${KEYDIR}" "${INPUTDIR}" "${OUTDIR}"

# init the root
tuftool root init "${ROOT}"
tuftool root expire "${ROOT}" "${METADATA_EXPIRATION}"

# set thresholds
tuftool root set-threshold "${ROOT}" root 1
tuftool root set-threshold "${ROOT}" snapshot 1
tuftool root set-threshold "${ROOT}" targets 1
tuftool root set-threshold "${ROOT}" timestamp 1

echo "Generating signing keys in ${KEYDIR} ..."

# generate keys
tuftool root gen-rsa-key "${ROOT}" "${KEYDIR}/root.pem" --role root
tuftool root gen-rsa-key "${ROOT}" "${KEYDIR}/snapshot.pem" --role snapshot
tuftool root gen-rsa-key "${ROOT}" "${KEYDIR}/targets.pem" --role targets
tuftool root gen-rsa-key "${ROOT}" "${KEYDIR}/timestamp.pem" --role timestamp

echo "Signing the root file ${ROOT} ..."

# sign root
tuftool root sign "${ROOT}" -k "${KEYDIR}/root.pem"

echo "Initializing empty repository in ${OUTDIR} ..."

# create the repo
tuftool create \
  --root "${ROOT}" \
  --key "${KEYDIR}/root.pem" \
  --key "${KEYDIR}/snapshot.pem" \
  --key "${KEYDIR}/targets.pem" \
  --key "${KEYDIR}/timestamp.pem" \
  --add-targets "${INPUTDIR}" \
  --targets-expires "${METADATA_EXPIRATION}" \
  --targets-version 1 \
  --snapshot-expires "${METADATA_EXPIRATION}" \
  --snapshot-version 1 \
  --timestamp-expires "${METADATA_EXPIRATION}" \
  --timestamp-version 1 \
  --force-version \
  --outdir "${OUTDIR}"

echo "Adding trust root targets ..."

# prepare targets
if [ -n "${FULCIO_CERT}" ]; then
  echo "Adding Fulcio certificate chain ${FULCIO_CERT} ..."
  tuftool rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-fulcio-target "${FULCIO_CERT}" \
    --fulcio-uri "https://fulcio.rhtas" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${TSA_CERT}" ]; then
  echo "Adding TSA certificate chain ${TSA_CERT} ..."
  tuftool rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-tsa-target "${TSA_CERT}" \
    --tsa-uri "https://tsa.rhtas" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${CTLOG_KEY}" ]; then
  echo "Adding CTLog public key ${CTLOG_KEY} ..."
  tuftool rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-ctlog-target "${CTLOG_KEY}" \
    --ctlog-uri "https://ctlog.rhtas" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${REKOR_KEY}" ]; then
  echo "Adding Rekor public key ${REKOR_KEY} ..."
  tuftool rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-rekor-target "${REKOR_KEY}" \
    --fulcio-uri "https://rekor.rhtas" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ "${EXPORT_KEYS:0:7}" = "file://" ]; then
  export EXPORT_DIR=${EXPORT_KEYS:7}
  echo "Exporting keys to directory ${EXPORT_DIR} ..."
  mkdir -p "${EXPORT_DIR}"
  cp "${KEYDIR}/"* "${EXPORT_DIR}"
elif [ -n "${EXPORT_KEYS}" ]; then
  echo "Exporting keys to k8s secret ${EXPORT_KEYS} ..."

  export AUTHDIR="/var/run/secrets/kubernetes.io/serviceaccount"
  export K8SCACERT="${AUTHDIR}/ca.crt"
  export K8SSECRETS="https://kubernetes.default.svc/api/v1/namespaces/${NAMESPACE}/secrets"
  export K8SAUTH=""
  export SECRET_CONTENT=""

  K8SAUTH="Authorization: Bearer $(cat ${AUTHDIR}/token)"
  SECRET_CONTENT=$(cat <<EOF
{
 "apiVersion":"v1",
 "kind" :"Secret",
 "metadata" :{"namespace": "${NAMESPACE}", "name": "${EXPORT_KEYS}"},
 "type": "Opaque",
 "data": {
   "root.pem": "$(base64 -w0 < "${KEYDIR}/root.pem")",
   "snapshot.pem": "$(base64 -w0 < "${KEYDIR}/snapshot.pem")",
   "targets.pem": "$(base64 -w0 < "${KEYDIR}/targets.pem")",
   "timestamp.pem": "$(base64 -w0 < "${KEYDIR}/timestamp.pem")"
  }
}
EOF
)
  export KEYS_CREATE_HTTP_STATUS="-1"
  # if the secret exists, replace it with the content, otherwise create it
  KEYS_CREATE_HTTP_STATUS=$(curl -X POST \
    --silent \
    --output /dev/null \
    --write-out "%{http_code}" \
    --cacert "${K8SCACERT}" \
    -H "${K8SAUTH}" \
    --header 'Content-Type: application/json' \
    --data @- \
    "${K8SSECRETS}" <<EOF
${SECRET_CONTENT}
EOF
    )

  if [ "${KEYS_CREATE_HTTP_STATUS}" = "409" ]; then
    curl --fail -X PUT \
      --output /dev/null \
      --cacert "${K8SCACERT}" \
      -H "${K8SAUTH}" \
      --header 'Content-Type: application/json' \
      --data @- \
      "${K8SSECRETS}/${EXPORT_KEYS}" <<EOF
${SECRET_CONTENT}
EOF
  elif [ "${KEYS_CREATE_HTTP_STATUS:0:1}" != "2" ]; then
    echo "Bad HTTP status when creating K8S secret ${EXPORT_KEYS}: ${KEYS_CREATE_HTTP_STATUS}"
    exit 1
  fi
else
  echo "Key export location not specified, not exporting keys"
fi

echo "Copying the TUF repository to final location ${TUF_REPO_PATH} ..."
# TODO: fix this based on changes in layout of tuftool output
cp -R "${OUTDIR}/." "${TUF_REPO_PATH}"

echo "Finished successfully!"
