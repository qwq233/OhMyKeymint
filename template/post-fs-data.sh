MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/omk
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
STATE_DIR=/data/adb/omk


mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint-daemon.pid" "$STATE_DIR/injector-daemon.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"

if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp "$MODDIR/keybox.xml" "$TARGET_KEYBOX"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi
