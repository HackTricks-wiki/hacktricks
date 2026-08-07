# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

システム上で実行されるコードの integrity の強制に重点を置き、XNU の code signature verification の背後にあるロジックを提供します。また、entitlements の確認や、debugging の許可、task ports の取得など、その他の機密性の高いタスクにも対応できます。

さらに、一部の操作では、kext は user space で動作する daemon `/usr/libexec/amfid` への接続を優先します。この trust relationship は、複数の jailbreak で悪用されてきました。

最近の macOS バージョンでは、AMFI は独立した on-disk kext として簡単に確認できなくなっているため、通常の reverse では `/System/Library/Extensions` を参照する代わりに、**kernelcache** または **KDK** を扱うことになります。

AMFI は **MACF** policies を使用し、起動した時点で hooks を登録します。また、ロードを阻止したり unload したりすると、kernel panic が発生する可能性があります。ただし、AMFI を無効化できる boot arguments がいくつかあります。

- `amfi_unrestricted_task_for_pid`: 必要な entitlements がなくても task_for_pid を許可
- `amfi_allow_any_signature`: 任意の code signature を許可
- `cs_enforcement_disable`: code signing enforcement を system-wide で無効化するために使用される argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements を持つ platform binaries を無効化
- `amfi_get_out_of_my_way`: amfi を完全に無効化

以下は、登録される MACF policies の一部です:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update を実行し、1 を返す
- **`cred_label_associate`**: AMFI の mac label slot を label で更新
- **`cred_label_destroy`**: AMFI の mac label slot を削除
- **`cred_label_init`**: AMFI の mac label slot に 0 を移動
- **`cred_label_update_execve`:** プロセスの entitlements を確認し、labels の変更が許可されるべきかを判断
- **`file_check_mmap`:** mmap が memory を取得して executable として設定しているかを確認します。その場合、library validation が必要かを確認し、必要であれば library validation function を呼び出します。
- **`file_check_library_validation`**: library validation function を呼び出します。この function は、platform binary が別の platform binary を load しているか、process と新たに load された file が同じ TeamID を持つかなどを確認します。特定の entitlements により、任意の library の load も許可されます。
- **`policy_initbsd`**: trusted NVRAM Keys を設定
- **`policy_syscall`**: binary が unrestricted segments を持つか、env vars を許可すべきかなど、DYLD policies を確認します。これは、`amfi_check_dyld_policy_self()` を介して process が start された場合にも呼び出されます。
- **`proc_check_inherit_ipc_ports`**: process が新しい binary を execute した際、他の processes がその process の task port に対する SEND rights を保持すべきかどうかを確認します。Platform binaries、`get-task-allow` entitlement を持つもの、`task_for_pid-allow` entitlements を持つもの、および同じ TeamID を持つ binaries は許可されます。
- **`proc_check_expose_task`**: entitlements を強制
- **`amfi_exc_action_check_exception_send`**: debugger に exception message を送信
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling（debugging）中の label lifecycle
- **`proc_check_get_task`**: 他の processes が process の task port を取得できる `get-task-allow` や、process が他の processes の task ports を取得できる `task_for_pid-allow` などの entitlements を確認します。どちらもない場合は、許可されているかを確認するために `amfid permitunrestricteddebugging` を呼び出します。
- **`proc_check_mprotect`**: `mprotect` が、region を valid code signature があるものとして扱う必要があることを示す flag `VM_PROT_TRUSTED` とともに呼び出された場合は deny
- **`vnode_check_exec`**: executable files が memory に load された際に呼び出され、`cs_hard | cs_kill` を設定します。これにより、いずれかの pages が invalid になると process が kill されます<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` を確認
- **`vnode_check_setextattr`**: get に加えて、`com.apple.private.allow-bless` および internal-installer-equivalent entitlement を確認
- **`vnode_check_signature`**: entitlements、trust cache、`amfid` を使用して code signature を確認するために XNU を呼び出す code<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` calls（`PT_ATTACH` および `PT_TRACE_ME`）を intercept します。`get-task-allow`、`run-invalid-allow`、`run-unsigned-code` のいずれかの entitlements を確認し、どれもない場合は debugging が許可されているかを確認します。
- **`proc_check_map_anon`**: mmap が **`MAP_JIT`** flag とともに呼び出された場合、AMFI は `dynamic-codesigning` entitlement を確認します。

`AMFI.kext` は他の kernel extensions 向けの API も公開しており、次の方法でその dependencies を見つけることができます。
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

これは user mode で実行される daemon で、`AMFI.kext` が user mode で code signature をチェックするために使用します。\
`AMFI.kext` がこの daemon と通信するために、ポート `HOST_AMFID_PORT`（特殊ポート `18`）上で mach messages を使用します。

macOS では、特殊ポートが `SIP` によって保護され、launchd だけが取得できるため、root プロセスが特殊ポートを hijack することはもはやできません。iOS では、response を返すプロセスが `amfid` の CDHash を hardcode で保持していることがチェックされます。

`amfid` が binary のチェックを要求されたタイミングと、その response は、debugging して `mach_msg` に breakpoint を設定することで確認できます。

特殊ポート経由で message を受信すると、**MIG** が各 function を呼び出し先の function に送信するために使用されます。主要な function は book 内で reverse され、説明されています。

### DYLD policy and library validation

Recent `dyld` versions は、`configureProcessRestrictions()` から非常に早い段階で `amfi_check_dyld_policy_self()` を呼び出し、プロセスが `DYLD_*` path variables、interposing、fallback paths、embedded variables を使用できるか、または library insertion の失敗を許容できるかを AMFI に問い合わせます。したがって、injection surface を triage する際は、Mach-O load commands だけを調べるのでは不十分です。AMFI が `dyld` policy に変換する entitlements と runtime flags も調べる必要があります。

実践的な triage loop は次のとおりです:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
最新の macOS では、多くの Apple バイナリが `com.apple.security.cs.disable-library-validation` を直接持たなくなり、代わりに `com.apple.private.security.clear-library-validation` を含むようになっています。この場合、library validation は `execve` 時に無効化されません。プロセス自身が `csops(..., CS_OPS_CLEAR_LV, ...)` を呼び出す必要があり、XNU は entitlement が存在する場合に限り、呼び出し元のプロセスに対してこの操作を許可します。攻撃の観点では、これは重要です。なぜなら、ターゲットが明示的に LV をクリアする code path に到達した**後**にのみ injectable になる可能性があるためです（例えば、optional plugins をロードする直前など）。<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile は code の sign に使用できます。code の sign と test に使用できる **Developer** profile と、すべての device で使用できる **Enterprise** profile があります。

App が Apple Store に submit され、承認されると、Apple によって sign され、provisioning profile は不要になります。

Profile には通常 `.mobileprovision` または `.provisionprofile` の extension が付いており、次のコマンドで dump できます。
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Although sometimes referred as certificated, these provisioning profiles have more than a certificate:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: これが Apple Internal profile であることを示す
- **ApplicationIdentifierPrefix**: AppIDName の先頭に付加される（TeamIdentifier と同じ）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の作成日
- **DeveloperCertificates**: Base64 data としてエンコードされた（通常は1つの）certificate(s) の配列
- **Entitlements**: この profile で許可される entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の有効期限
- **Name**: Application Name。AppIDName と同じ
- **ProvisionedDevices**: （developer certificates の場合）この profile が有効な UDIDs の配列
- **ProvisionsAllDevices**: boolean（enterprise certificates の場合は true）
- **TeamIdentifier**: inter-app interaction の目的で developer を識別するために使用される、（通常は1つの）英数字文字列の配列
- **TeamName**: developer を識別するために使用される、人間が読める名前
- **TimeToLive**: certificate の有効期間（日数）
- **UUID**: この profile の Universally Unique Identifier
- **Version**: 現在は 1 に設定

entitlements エントリには制限された entitlements のセットが含まれ、Apple private entitlements が付与されるのを防ぐため、provisioning profile はそれらの特定の entitlements のみを付与できます。

profiles は通常 `/var/MobileDeviceProvisioningProfiles` に配置され、**`security cms -D -i /path/to/profile`** で確認できます。

## **libmis.dylib**

これは `amfid` が何かを許可すべきかどうか問い合わせるために呼び出す外部 library です。過去には、すべてを許可する backdoored version を実行することで、jailbreaking に悪用されてきました。

macOS では、これは `MobileDevice.framework` 内にあります。

## AMFI Trust Caches

Trust caches は iOS にだけ存在する概念ではありません。現代の macOS、特に **Apple silicon** では、static trust cache と loadable trust caches は Secure Boot chain の一部です。Mach-O の **CodeDirectory hash** がそこに存在する場合、AMFI は launch 時に追加の authenticity checks を行わずに、対象へ **platform privilege** を付与できます。これは、Apple が platform binaries を特定の OS version に固定し、新しい system 上で古い Apple-signed binaries が replay されるのを防止できることも意味します。<sup>[[6]](#references)</sup>

最近の macOS releases では、trust-cache metadata も **launch constraints** に関連付けられています。そのため、コピーされた system apps や binaries は、依然として Apple-signed であっても、誤った parent/location から起動されると AMFI によって拒否される可能性があります。詳細な extraction と reversing の workflow については、以下で説明しています。

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS と jailbreak research では、ad-hoc signed binaries を whitelist するために、従来の **loadable trust caches** モデルが使用されていることも確認できます。

## References

- [1] [XNU — `security/mac_policy.h` (AMFI が登録する MACF policy ops。`mpo_policy_syscall` を含む)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (AMFI が設定する `CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob の parsing と validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations と `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
