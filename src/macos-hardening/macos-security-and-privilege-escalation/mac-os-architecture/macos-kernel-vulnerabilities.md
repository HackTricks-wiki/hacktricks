# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**このレポートでは**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) ソフトウェアアップデーターを妥協させるカーネルの脆弱性がいくつか説明されています。\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024: 実際の環境でのカーネル0-day (CVE-2024-23225 & CVE-2024-23296)

Appleは2024年3月にiOSとmacOSに対して積極的に悪用されていた2つのメモリ破損バグを修正しました（macOS 14.4/13.6.5/12.7.4で修正）。

* **CVE-2024-23225 – カーネル**
• XNU仮想メモリサブシステムにおけるバッファ外書き込みにより、特権のないプロセスがカーネルアドレス空間で任意の読み書きを取得でき、PAC/KTRRを回避します。
• `libxpc`内のバッファをオーバーフローさせるように作成されたXPCメッセージからユーザースペースでトリガーされ、メッセージが解析されるとカーネルにピボットします。
* **CVE-2024-23296 – RTKit**
• Apple Silicon RTKit（リアルタイムコプロセッサ）におけるメモリ破損。
• 観察された悪用チェーンは、カーネルのR/WにCVE-2024-23225を使用し、PACを無効にするためにCVE-2024-23296を使用してセキュアコプロセッササンドボックスから脱出しました。

パッチレベル検出:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
アップグレードが不可能な場合は、脆弱なサービスを無効にすることで対策を講じてください:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIGタイプ混乱 – CVE-2023-41075

`mach_msg()` リクエストが特権のないIOKitユーザクライアントに送信されると、MIG生成のグルーコードにおいて**タイプ混乱**が発生します。返信メッセージが元々割り当てられたよりも大きなアウトオブラインディスクリプタで再解釈されると、攻撃者はカーネルヒープゾーンへの制御された**OOB書き込み**を達成し、最終的に`root`に昇格することができます。

プリミティブアウトライン（Sonoma 14.0-14.1、Ventura 13.5-13.6）：
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
公開エクスプロイトは、バグを武器化するために以下の手順を踏みます：
1. アクティブポートポインタで `ipc_kmsg` バッファをスプレーします。
2. ダングリングポートの `ip_kobject` を上書きします。
3. `mprotect()` を使用してPACで偽造されたアドレスにマッピングされたシェルコードにジャンプします。

---

## 2024-2025: サードパーティKextを通じたSIPバイパス – CVE-2024-44243（通称「Sigma」）

Microsoftのセキュリティ研究者は、高特権デーモン `storagekitd` が**署名されていないカーネル拡張**をロードするよう強制され、完全にパッチが適用されたmacOS（15.2以前）で**システムインテグリティ保護（SIP）**を完全に無効にできることを示しました。攻撃の流れは以下の通りです：

1. プライベート権限 `com.apple.storagekitd.kernel-management` を悪用して、攻撃者の制御下にヘルパーを生成します。
2. ヘルパーは、悪意のあるkextバンドルを指す加工された情報辞書を持つ `IOService::AddPersonalitiesFromKernelModule` を呼び出します。
3. SIPの信頼性チェックは、`storagekitd` によってkextがステージングされた*後*に実行されるため、検証前にコードがリング0で実行され、`csr_set_allow_all(1)` を使用してSIPをオフにすることができます。

検出のヒント：
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
即時の修正は、macOS Sequoia 15.2 以降にアップデートすることです。

---

### クイック列挙チートシート
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Machメッセージファズァーで、MIGサブシステムをターゲットにしています (`github.com/preshing/luftrauser`)。
* **oob-executor** – CVE-2024-23225の研究で使用されるIPCアウトオブバウンズプリミティブジェネレーター。
* **kmutil inspect** – kextをロードする前に静的に分析するためのAppleの組み込みユーティリティ（macOS 11+）： `kmutil inspect -b io.kext.bundleID`。



## References

* Apple. “macOS Sonoma 14.4のセキュリティコンテンツについて。” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “CVE-2024-44243の分析、カーネル拡張を通じたmacOSシステム整合性保護のバイパス。” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
