#!/bin/bash -ex
#
# Verify a PGP signature on a downloaded file, generally a software download.
# This script uses a Trust On First Use (TOFU) model. If it's never seen a given
# package before, it downloads the appropriate key and automatically trusts it.
# This step is unsafe. For subsequent downloads of the same package, this script
# will only trust the first key it saw. A 'package' is defined by the first part
# of the filename, split up by any non-alphanumeric characters.
#
# Takes as argument the name of the file to be verified. Will look for
# foo.sig, foo.asc, SHA512SUM*, SHA256SUM*, SHA1SUM*, MD5SUM* for verification.
#
# Download the target file and any necessary signatures and/or
# sumfiles to the same directory. If the file you're attempting to verify comes
# with a sumfile instead of a per-file signature, make sure to grab both the
# sumfile and its signature (e.g. SHA512SUM.asc).
#
# Example usage:
#   wget ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/SHA512SUMS \
#     ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/SHA512SUMS.asc \
#     ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/linux-x86_64/en-US/firefox-34.0.tar.bz2
#   verify.sh firefox-34.0.tar.bz2
#
# Prerequisite: You must have gnupg-curl installed to fetch keys over HKPS.
TARGET_FILE="$1"
TARGET_DIR="`dirname $TARGET_FILE`"
TARGET_BASE="`basename $TARGET_FILE`"
PACKAGE_NAME="`echo "$TARGET_FILE" | perl -pe 's+.*/++; s+[^[:alnum:]].*++'`"

if [[ "$TARGET_FILE" =~ .(asc|sig) ]] ; then
  echo "Call this with the filename of a download, not a signature file."
  exit 1
fi

# Given the name of a hash function (e.g. SHA512), a sumfile containing hashes
# of that type, and a file to be verified, run that hash function over the file
# and see if the result exists in the sumfile.
verify_hash() {
  HASH="$1"
  SUMFILE="$2"
  TARGET_FILE="$3"
  HASH_COMMAND="`echo $HASH | tr A-Z a-z`"
  OUTPUT="`${HASH_COMMAND}sum $TARGET_FILE | cut -d' ' -f1`"
  grep "$OUTPUT" "$SUMFILE"
}

# Look for all types of signature: Direct signature or various sumfiles.
if [ -f "${TARGET_FILE}.sig" ] ; then
  TARGET_SIG="${TARGET_FILE}.sig"
elif [ -f "${TARGET_FILE}.asc" ] ; then
  TARGET_SIG="${TARGET_FILE}.asc"
else
  for HASH in SHA512 SHA256 SHA1 MD5 ; do
    for SUMFILE in "$TARGET_DIR"/"$HASH"* ; do
      # If our file is listed by name in the sumfile, and its appropriate hash
      # matches the sumfile contents, we can move on to verifying the signature
      # on the sumfile.
      if grep -q "$TARGET_BASE" "$SUMFILE" && \
        verify_hash "$HASH" "$SUMFILE" "$TARGET_FILE"; then
        TARGET_FILE="${SUMFILE}"
        for SIG in "${SUMFILE}.sig" "${SUMFILE}.asc" \
          "$(basename $SUMFILE .txt).sig" "$(basename $SUMFILE .txt).asc" ; do
          if [ -f "$SIG" ] ; then
            TARGET_SIG="$SIG"
            break 3
          fi
        done
      fi
    done
  done
fi

if [ -z "$TARGET_SIG" ] ; then
  echo "Didn't find signature file or SHA*SUMS (+SHA*SUMS.asc). Need to download?"
  exit 1
fi

# Options common to all invocations of gpg. Use a specific keyserver rather than
# the entire sks-keyservers.net pool to be slightly more robust against a purely
# local network attack.
OPTIONS="
  --keyserver hkps://sks.openpgp-keyserver.de \
  --keyserver-options ca-cert-file="`dirname $0`/sks-keyservers.netCA.pem" \
  --keyserver-options no-honor-keyserver-url \
"

export GNUPGHOME=~/.gpg-download-verifier/$PACKAGE_NAME
if [ ! -d $GNUPGHOME ] ; then
  # First invocation for this package. Create GNUPGHOME and fetch the key.
  mkdir -p $GNUPGHOME
  chmod 0700 $GNUPGHOME

  EXTRA_OPTIONS="--keyserver-options auto-key-retrieve"
else
  EXTRA_OPTIONS="--trust-model=always"
fi

if gpg $OPTIONS $EXTRA_OPTIONS --verify "$TARGET_SIG" "$TARGET_FILE" ; then
  echo VERIFIED
  exit 0
else
  echo NOT VERIFIED
  exit 1
fi
