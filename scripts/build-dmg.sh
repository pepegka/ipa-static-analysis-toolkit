#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="dev-$(date +%Y%m%d)"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

DIST_DIR="dist"
APP_NAME="ISAT"
APP_BUNDLE="${DIST_DIR}/${APP_NAME}.app"
DMG_PATH="${DIST_DIR}/${APP_NAME}-${VERSION}.dmg"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "==> swift build -c release"
swift build -c release --arch arm64 --arch x86_64

BIN_PATH="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/${APP_NAME}"
if [ ! -f "$BIN_PATH" ]; then
  BIN_PATH="$(find .build -maxdepth 6 -type f -name "${APP_NAME}" -path '*release*' | head -1)"
fi
[ -f "$BIN_PATH" ] || { echo "Could not locate built binary"; exit 1; }

echo "==> assembling ${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "$BIN_PATH" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"
chmod +x "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

BUNDLE_DIR="$(dirname "$BIN_PATH")"
for b in "${BUNDLE_DIR}"/*.bundle; do
  [ -e "$b" ] || continue
  cp -R "$b" "${APP_BUNDLE}/Contents/Resources/" 2>/dev/null || true
done

cat > "${APP_BUNDLE}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key><string>IPA Static Analysis Toolkit (ISAT)</string>
  <key>CFBundleIdentifier</key><string>local.isat.app</string>
  <key>CFBundleExecutable</key><string>${APP_NAME}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
EOF

echo "==> creating ${DMG_PATH}"
STAGING="${DIST_DIR}/dmg-staging"
rm -rf "$STAGING"; mkdir "$STAGING"
cp -R "${APP_BUNDLE}" "${STAGING}/"
ln -s /Applications "${STAGING}/Applications"

hdiutil create -volname "${APP_NAME} ${VERSION}" \
  -srcfolder "$STAGING" \
  -ov -format UDZO \
  "${DMG_PATH}" >/dev/null

rm -rf "$STAGING"

echo
echo "Built unsigned DMG: ${DMG_PATH}"
echo "Note: not signed or notarized. To launch on another Mac:"
echo "  xattr -dr com.apple.quarantine /Applications/${APP_NAME}.app"
