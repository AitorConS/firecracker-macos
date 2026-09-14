#!/bin/sh
# Optional credentialed release step. Never invoked by the local build/package scripts.
set -eu
if [ "$#" -ne 2 ]; then
    echo "Usage: APPLICATION_IDENTITY=... INSTALLER_IDENTITY=... NOTARY_PROFILE=... $0 PACKAGE NEW_OUTPUT.pkg" >&2
    exit 2
fi
: "${APPLICATION_IDENTITY:?Developer ID Application identity required}"
: "${INSTALLER_IDENTITY:?Developer ID Installer identity required}"
: "${NOTARY_PROFILE:?Existing notarytool keychain profile required}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
package=$(CDPATH= cd -- "$1" && pwd)
output=$2
[ ! -e "$output" ] || { echo "Output already exists" >&2; exit 2; }
stage=$(mktemp -d "${TMPDIR:-/tmp}/hvf-sign.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
# Only this private copy is changed; keep unsigned/ad-hoc evidence intact.
/usr/bin/ditto "$package" "$stage/package"
for library in "$stage"/package/lib/*.dylib; do
    /usr/bin/codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$library"
done
/usr/bin/codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" \
    --entitlements "$root/experiments/hvf/entitlements.plist" "$stage/package/bin/firecracker"
/usr/bin/codesign --verify --strict "$stage/package/bin/firecracker"
# Signing changes file hashes. Keep build provenance and regenerate final checksums.
/usr/bin/python3 - "$stage/package" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
p=root/'manifest.json';manifest=json.loads(p.read_text())
manifest['signing']='Developer ID';manifest['notarized']=False
p.write_text(json.dumps(manifest,indent=2)+'\n')
(root/'SHA256SUMS').write_text(''.join(
    hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root))+'\n'
    for p in sorted(root.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
PY
/usr/bin/pkgbuild --root "$stage/package" --identifier org.firecracker.hvf.experimental \
    --version 1.0.0 --install-location /usr/local/libexec/firecracker-hvf \
    --sign "$INSTALLER_IDENTITY" "$output"
/usr/bin/xcrun notarytool submit "$output" --keychain-profile "$NOTARY_PROFILE" --wait
/usr/bin/xcrun stapler staple "$output"
/usr/bin/xcrun stapler validate "$output"
# Notarization attests the installer; embedded build manifest remains pre-submission.
/usr/bin/shasum -a 256 "$output" > "$output.sha256"
