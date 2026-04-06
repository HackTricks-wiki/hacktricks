# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**NVRAM**（不揮発性ランダムアクセスメモリ）は、Mac ハードウェア上の**ブート時およびファームウェアレベルの設定**を格納します。特にセキュリティ上重要な変数は次のとおりです：

| 変数 | 目的 |
|---|---|
| `boot-args` | カーネルのブート引数（デバッグフラグ、verbose ブート、AMFI バイパス） |
| `csr-active-config` | **SIP の設定ビットマスク** — どの保護が有効かを制御します |
| `SystemAudioVolume` | 起動時のオーディオ音量 |
| `prev-lang:kbd` | 優先言語 / キーボードレイアウト |
| `efi-boot-device-data` | ブートデバイスの選択 |

最新の Macs では、NVRAM 変数は **system** 変数（Secure Boot によって保護）と **non-system** 変数に分かれています。Apple Silicon Macs は **Secure Storage Component (SSC)** を使用して、NVRAM の状態をブートチェーンに暗号的に結び付けます。

## ユーザー空間からのNVRAMアクセス

### NVRAMの読み取り
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
### NVRAMの書き込み

NVRAM変数の書き込みには **root privileges** が必要で、システム重要な変数（`csr-active-config` のようなもの）については、プロセスが特定のコード署名フラグまたはエンタイトルメントを持っている必要があります:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED フラグ

コード署名フラグ **`CS_NVRAM_UNRESTRICTED`** を持つバイナリは、通常 root でさえ保護されている NVRAM 変数を変更できます。

### NVRAM-Unrestricted バイナリの検出
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## セキュリティへの影響

### NVRAM による SIP の弱体化

攻撃者が NVRAM に書き込める場合（NVRAM 制限のないバイナリが侵害されているか、脆弱性を悪用した場合）、`csr-active-config` を変更して **次回起動時に SIP 保護を無効化する** ことができます：
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
> 現代の Apple Silicon Macs では、**Secure Boot chain は NVRAM の変更を検証し、ランタイムでの SIP の変更を防ぎます**。`csr-active-config` の変更は recoveryOS 経由でのみ有効になります。ただし、**Intel Macs** や **reduced security mode** のシステムでは、NVRAM の操作によって SIP を弱体化させる可能性があります。

### カーネルデバッグの有効化
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
### ファームウェアの永続性

NVRAMの変更は**OSの再インストール後も残る** — ファームウェアレベルで永続化される。攻撃者は、起動時に永続化機構が読み取るカスタムNVRAM変数を書き込むことができる：
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM の永続性はディスクのワイプや OS の再インストールでも維持されます。消去するには **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) または **DFU restore** (Apple Silicon) が必要です。

### AMFI Bypass

`amfi_get_out_of_my_way=1` ブート引数は **Apple Mobile File Integrity** を無効化し、署名されていないコードの実行を可能にします:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 実際のCVE

| CVE | 説明 |
|---|---|
| CVE-2020-9839 | 永続的なSIPバイパスを可能にするNVRAMの操作 |
| CVE-2019-8779 | T2搭載MacでのファームウェアレベルのNVRAM永続化 |
| CVE-2022-22583 | PackageKitのNVRAM関連の権限昇格 |
| CVE-2020-10004 | システム改変を可能にするNVRAM処理のロジックの問題 |

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

* [Apple Platform Security Guide — 起動プロセス](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM 関連の CVE](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 セキュリティ](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
