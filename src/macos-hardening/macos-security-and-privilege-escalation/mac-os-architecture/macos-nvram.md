# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**NVRAM**（Non-Volatile Random-Access Memory）は、Mac ハードウェア上で**起動時およびファームウェアレベルの設定**を保存します。セキュリティ上、特に重要な変数には次のものがあります。

| 変数 | 目的 |
|---|---|
| `boot-args` | カーネル起動引数（デバッグフラグ、詳細な起動、AMFI bypass） |
| `csr-active-config` | **SIP 設定ビットマスク** — 有効な保護機能を制御 |
| `SystemAudioVolume` | 起動時の音量 |
| `prev-lang:kbd` | 優先言語 / キーボードレイアウト |
| `efi-boot-device-data` | 起動デバイスの選択 |

最新の Mac では、NVRAM 変数は **Secure Boot によって保護される** **system** 変数と、**non-system** 変数に分けられています。Apple Silicon Mac は、NVRAM の状態をブートチェーンに暗号学的にバインドする **Secure Storage Component (SSC)** を使用します。<sup>[[1]](#references)</sup>

## ユーザー空間からの NVRAM へのアクセス

### NVRAM の読み取り
```bash
# List all NVRAM variables
nvram -p

# Read a specific variable
nvram boot-args

# Export all NVRAM as XML plist
nvram -xp

# Read SIP configuration
nvram csr-active-config
csrutil status
```
### NVRAMへの書き込み

NVRAM変数への書き込みには**root権限**が必要であり、`csr-active-config`のようなシステムにとって重要な変数の場合、プロセスには特定のコード署名フラグまたはentitlementsが必要です。
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

**`CS_NVRAM_UNRESTRICTED`** code-signing flag を持つ Binaries は、通常は root からも保護されている NVRAM variables を変更できます。

### NVRAM-Unrestricted Binaries の検索
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## セキュリティへの影響

### NVRAM による SIP の弱体化

攻撃者が NVRAM に書き込める場合（NVRAM-unrestricted バイナリの侵害、または脆弱性の悪用によって）、`csr-active-config` を変更して、**次回の起動時に SIP 保護を無効化**できます：
```bash
# SIP configuration is a bitmask stored in NVRAM
# Each bit controls a different SIP protection:
#   Bit 0 (0x1):  Filesystem protection
#   Bit 1 (0x2):  Kext signing
#   Bit 2 (0x4):  Task-for-pid restriction
#   Bit 3 (0x8):  Unrestricted filesystem
#   Bit 4 (0x10): Apple Internal (debug)
#   Bit 5 (0x20): Unrestricted DTrace
#   Bit 6 (0x40): Unrestricted NVRAM
#   Bit 7 (0x80): Device configuration

# Current SIP configuration
nvram csr-active-config | xxd

# On older hardware, a compromised NVRAM-unrestricted binary could:
# nvram csr-active-config=%7f%00%00%00   # Disable most SIP protections
```
> [!WARNING]
> 最新の Apple Silicon Mac では、**Secure Boot chain が NVRAM** の変更を検証し、実行時の SIP 変更を防止します。`csr-active-config` の変更は recoveryOS 経由でのみ有効になります。ただし、**Intel Mac** または **reduced security mode** のシステムでは、NVRAM の操作によって SIP が弱体化する可能性があります。

### Kernel Debugging の有効化
```bash
# Enable kernel debug flags via boot-args
sudo nvram boot-args="debug=0x144"

# Common debug flags:
#   0x01  DB_HALT      — Wait for debugger at boot
#   0x04  DB_KPRT      — Send kernel printf to serial
#   0x40  DB_KERN_DUMP — Dump kernel core on NMI
#   0x100 DB_REBOOT_POST_PANIC — Reboot after panic

# Use development kernel
sudo nvram boot-args="kcsuffix=development"
```
### ファームウェア永続化

NVRAMの変更は**OSの再インストール後も維持される**—ファームウェアレベルで永続化されます。攻撃者は、boot時に永続化メカニズムが読み取るカスタムNVRAM変数を書き込むことができます：
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence はディスクのワイプや OS の再インストール後も存続します。クリアするには **PRAM/NVRAM reset**（Intel Mac では Command+Option+P+R）または **DFU restore**（Apple Silicon）が必要です。

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument は **Apple Mobile File Integrity** を無効化し、unsigned code の実行を可能にします：
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 実際のCVE

| CVE | 説明 |
|---|---|
| CVE-2020-9839 | 永続的なSIP bypassを可能にするNVRAM manipulation <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | T2 MacにおけるFirmware-level NVRAM persistence <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | PackageKitに関連するNVRAM privilege escalation |
| CVE-2020-10004 | system modificationを可能にするNVRAM handlingのlogic issue |

## 列挙スクリプト
```bash
#!/bin/bash
echo "=== NVRAM Security Audit ==="

# Current SIP status
echo -e "\n[*] SIP Status:"
csrutil status

# Current boot-args
echo -e "\n[*] Boot Arguments:"
nvram boot-args 2>/dev/null || echo "  (none set)"

# All NVRAM variables
echo -e "\n[*] All NVRAM Variables:"
nvram -p | grep -v "^$" | wc -l
echo "  variables total"

# Security-relevant variables
echo -e "\n[*] Security-Relevant Variables:"
for var in csr-active-config boot-args StartupMute SystemAudioVolume efi-boot-device; do
echo "  $var: $(nvram "$var" 2>/dev/null || echo 'not set')"
done

# Check for custom (non-Apple) variables
echo -e "\n[*] Non-Standard Variables (potential persistence):"
nvram -p | grep -v "^$" | grep -vE "^(SystemAudioVolume|boot-args|csr-active-config|prev-lang|LocationServicesEnabled|fmm-mobileme-token|bluetoothInternalControllerAddress|bluetoothActiveControllerInfo|SystemAudioVolumeExtension|efi-)" | head -20
```
## 参考資料

- [1] [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
