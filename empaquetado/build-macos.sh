#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=1.6.0
ARCH=$(uname -m)
BUILD_DIR=${SUAYA_BUILD_DIR:-build}
APP="$BUILD_DIR/SUAYA.app"
# Cualquier fallo aborta antes de crear el paquete. Nunca se genera un stub.
cargo build --release --locked -p suaya -p suaya-api
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -swift-version 5 -O -parse-as-library -framework SwiftUI -framework AppKit \
    macos/SuayaApp.swift -o "$APP/Contents/MacOS/SUAYA"
cp "${CARGO_TARGET_DIR:-target}/release/suaya" "$APP/Contents/MacOS/suaya-engine"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleName</key><string>SUAYA</string>
<key>CFBundleIdentifier</key><string>com.joserangel.suaya</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleExecutable</key><string>SUAYA</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -lint "$APP/Contents/Info.plist"
"$APP/Contents/MacOS/suaya-engine" --version
file "$APP/Contents/MacOS/SUAYA"
# Firma local ad-hoc: no sustituye Developer ID ni notarización para distribución pública.
xattr -cr "$APP"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
if [ "${SUAYA_DMG:-0}" = 1 ]; then
    STAGE=$(mktemp -d)
    trap 'rm -rf "$STAGE"' EXIT
    ditto --norsrc --noextattr "$APP" "$STAGE/SUAYA.app"
    codesign --verify --deep --strict "$STAGE/SUAYA.app"
    ln -s /Applications "$STAGE/Applications"
    hdiutil create -volname SUAYA -srcfolder "$STAGE" -ov -format UDZO "$BUILD_DIR/SUAYA-$VERSION-macos-$ARCH.dmg"
    hdiutil verify "$BUILD_DIR/SUAYA-$VERSION-macos-$ARCH.dmg"
fi
