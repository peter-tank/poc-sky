#!/system/bin/sh
# 把系统配置里的默认桌面改成 Aerial
# 备份：/data/local/tmp/general_config.xml.bak
SRC=/dev/block/platform/mstar_mci.0/by-name/system
CFG=/system/pcfg/9S60_G60/config/general_config.xml
BAK=/data/local/tmp/general_config.xml.bak

mount -o rw,remount "$SRC" /system || { echo "REMOUNT_FAIL"; exit 1; }
echo "RW_OK"

sed 's#<config name="DEFAULT_HOMEPAGE" value="[^"]*"#<config name="DEFAULT_HOMEPAGE" value="app.orchard.tv/app.orchard.tv.MainActivity"#' "$BAK" > /data/local/tmp/gc.new
echo "NEW_BYTES=$(wc -c < /data/local/tmp/gc.new)"

cat /data/local/tmp/gc.new > "$CFG"
sync
echo "CFG_BYTES=$(wc -c < $CFG)"
grep DEFAULT_HOMEPAGE "$CFG"
grep -c "<config" "$CFG"

mount -o ro,remount "$SRC" /system && echo "RO_OK"
grep -E " /system " /proc/mounts
