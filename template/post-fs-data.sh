MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/omk
TARGET_KEYMINT=$TARGET_DIR/keymint
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
STATE_DIR=/data/adb/omk
TARGET_INJECTOR=$STATE_DIR/inject

find_module_binary() {
  name=$1
  if [ -f "$MODDIR/$name" ]; then
    echo "$MODDIR/$name"
    return 0
  fi
  if [ -f "$MODDIR/libs/arm64-v8a/$name" ]; then
    echo "$MODDIR/libs/arm64-v8a/$name"
    return 0
  fi
  if [ -f "$MODDIR/libs/x86_64/$name" ]; then
    echo "$MODDIR/libs/x86_64/$name"
    return 0
  fi
  return 1
}

clear_restart_props() {
  if command -v resetprop >/dev/null 2>&1; then
    resetprop persist.sys.omk.restart.keymint ""
    resetprop persist.sys.omk.restart.injector ""
    resetprop persist.sys.omk.restart.all ""
    return
  fi
  if command -v ksud >/dev/null 2>&1; then
    ksud resetprop persist.sys.omk.restart.keymint ""
    ksud resetprop persist.sys.omk.restart.injector ""
    ksud resetprop persist.sys.omk.restart.all ""
  fi
}

mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint-daemon.pid" "$STATE_DIR/injector-daemon.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all" \
  "$STATE_DIR/restart.all.keymint" "$STATE_DIR/restart.all.injector"
clear_restart_props

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

MODULE_KEYMINT=$(find_module_binary keymint)
if [ -n "$MODULE_KEYMINT" ]; then
  if [ ! -f "$TARGET_KEYMINT" ] || ! cmp -s "$MODULE_KEYMINT" "$TARGET_KEYMINT"; then
    cp "$MODULE_KEYMINT" "$TARGET_KEYMINT"
  fi
  chmod 0755 "$TARGET_KEYMINT"
  chown 1017:1017 "$TARGET_KEYMINT"
fi

MODULE_INJECTOR=$(find_module_binary inject)
if [ -n "$MODULE_INJECTOR" ]; then
  if [ ! -f "$TARGET_INJECTOR" ] || ! cmp -s "$MODULE_INJECTOR" "$TARGET_INJECTOR"; then
    cp "$MODULE_INJECTOR" "$TARGET_INJECTOR"
  fi
  chmod 0755 "$TARGET_INJECTOR"
  chown 0:0 "$TARGET_INJECTOR"
  chcon u:object_r:system_file:s0 "$TARGET_INJECTOR"
fi
