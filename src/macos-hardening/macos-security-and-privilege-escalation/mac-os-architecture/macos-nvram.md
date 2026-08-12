# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**NVRAM**（Non-Volatile Random-Access Memory）は、通常の macOS ファイルシステムの外部にファームウェアおよび初期ブート状態を保存します。その security への影響は、変数と boot architecture の両方に依存します。

| 変数 | 用途 / security 上の関連性 |
|---|---|
| `boot-args` | kernel に渡される引数。Debug 用または security を低下させる引数は、boot policy が許可しない限りフィルタリングされます。 |
| `csr-active-config` | Intel Mac における SIP のビットマスク。Apple silicon では、同等の policy は volume ごとの `LocalPolicy` に格納され、この変数から直接信頼されることはありません。 |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI の boot target。 |
| `boot-volume` | Apple silicon における boot-volume 選択状態。 |
| `SystemAudioVolume`、`prev-lang:kbd` | 通常の永続設定の例。 |

重要なのは、**NVRAM に保存されたデータ**と、**boot chain が受け入れる security policy**を区別することです。Apple silicon では、Secure Enclave が boot-volume-group ごとの `LocalPolicy` に署名し、Secure Storage Component に保持された nonce が replay 攻撃を防止します。したがって、同様の名前を持つ NVRAM property を変更しても、それだけで受け入れられる boot policy が書き換えられるわけではありません。<sup>[[1]](#references)[[4]](#references)</sup>

## User Space からの NVRAM Access

### 読み取りとベースライン収集
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
すべての見慣れないキーを malicious と分類しないでください。Hardware、recoveryOS、updates、Find My、boot failures は、model と version に依存する変数を生成します。キャプチャを**同じ Mac**から取得した以前の baseline と比較し、予期しない binary blobs、変更された boot selection、または security を低下させる arguments は、compromise の証拠ではなく手がかりとして扱ってください。

### Writing NVRAM

Root は多くの通常の変数を作成または変更できますが、protected variables はさらに variable namespace、SIP、per-variable kernel rules、restricted Apple entitlements に依存します。したがって、無害な custom key に対して `sudo` が成功しても、その process が `boot-args`、SIP、または system-region variables を変更できることの証明にはなりません。
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> テスト中は `nvram -c` を避けてください。これは削除可能なすべての変数の削除を要求し、boot/recovery の動作を変更する可能性があります。一部の変数は kernel 専用、entitlement によって保護、読み取り時に非表示、または NVRAM reset 中にのみ削除可能です。

## NVRAM の Entitlements と `CS_NVRAM_UNRESTRICTED`

exec time に XNU は `com.apple.rootless.restricted-nvram-variables.heritable` をプロセスフラグ **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`) にマッピングします。これは通常の effective UID 0 のチェックと同等ではありません。特定の変数や操作を対象とする、より限定的な private entitlements も存在します。

`codesign` が出力する汎用的な flags 行に頼るのではなく、entitlements を調査してください：
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
特権ヘルパーを audit する際は、**実際の client identity と request path** を追跡してください。entitled service の confused-deputy bug は、`nvram` を直接呼び出すより有用な場合がありますが、到達可能な variable/operation は XNU によって制限されている可能性があります。

## Intel SIP State と Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Intel では、`csr-active-config` が `CSR_ALLOW_*` exceptions をエンコードします。一般的に関連する bit positions は次のとおりです：
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
`csrutil status`で有効な設定を確認します。raw `nvram`の出力では、パーセントエンコードされたlittle-endianバイトが使用される場合があります。保護とbypassへの影響については、[macOS SIP](../macos-security-protections/macos-sip.md)を参照してください。
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: 受け入れられる boot policy の検査

Apple silicon では、Secure Enclave によって署名された `LocalPolicy` 内の `sip0` に、以前は NVRAM に保存されていた SIP policy bits が格納されています。その他の関連する policy fields は、`sip1`（SSV の root-hash 検証失敗を許可）、`sip2`（CTRR による kernel memory のロックを行わない）、`sip3`（iBoot の `boot-args` allowlist を無効化）です。これらのフィールドを変更できるのは、ペアリングされた One True recoveryOS（1TR）からのみです。また、`sip3` を有効にするには、Permissive Security への downgrade も必要です。<sup>[[4]](#references)</sup>

列挙中は display 操作のみを使用します。
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> audit 中は `bputil` のポリシー変更オプションを使用しないでください。通常の macOS compromise では、上記のフィールドを密かに有効化できないはずです。downgrade path では、意図的にペアリング済みの 1TR への物理的なアクセスと owner authentication が必要になります。<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` as a Post-Compromise Amplifier

kernel-debugging options、`kcsuffix=development`、`amfi_get_out_of_my_way=1` などの引数は、後続の boot stages を弱める可能性がありますが、それは platform がそれらを受け入れる場合に限られます。Apple silicon の Full または Reduced Security では、iBoot が security-reducing arguments をフィルタリングします。制限のない引数を使用するには、上記で説明した `sip3` policy downgrade が必要です。Intel では、SIP の NVRAM restriction により、root shell を `boot-args` の制御権限として自動的に扱うことも同様に防止されます。
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
[AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) と [kernel debugging](macos-kernel-extensions.md) を参照し、過去の議論がすべての macOS リリースで同じように機能すると仮定しないでください。

### NVRAM-backed `rc.trampoline` Execution

最近の research では、NVRAM データを利用する具体的な consumer が記録されています。それが Apple platform binary `/System/Library/CoreServices/rc.trampoline` です。launchd が `rc.trampoline=1` boot argument を検出すると、この boot task は `IODeviceTree:/options` から `apple-trusted-trampoline` property を読み取り、一時 executable に書き込み、suspended 状態で起動し、その code-signing state を確認してから unlink し、再開します。boot task は child が終了するまで launchd を block します。<sup>[[5]](#references)</sup>

これは **SIP bypass ではなく、post-downgrade persistence primitive** です。実証された path では、boot task を実行し、`boot-args` を設定できるようにするため、SIP を無効化する必要がありました。research では、value-size の上限が約 390 KB であることも確認されています。この手法の価値は、attacker が必要な security downgrade をすでに取得した後、executable bytes を通常の filesystem の外部に保存し、boot 中に materialize できる点にあります。<sup>[[5]](#references)</sup>

必要な両方の artifact と launchd event を hunt します。
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
任意のカスタム NVRAM 変数は、それ以外の場合は単なる **storage** にすぎません。firmware、Apple の boot component、または別の persistence mechanism がそれらを利用しない限り、何も実行しません。この区別により、`nvram attacker-config=...` のような marker を firmware code execution として過大評価することを避けられます。

## Enumeration Script

<details>
<summary>NVRAM と Apple silicon の boot-policy audit</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — 起動プロセス](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM関連のCVE](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Apple silicon搭載MacのLocalPolicyファイルの内容](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — apple-trusted-trampolineを使用してNVRAM経由でPersist](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
