# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext と amfid

システム上で実行されるコードの integrity の強制に重点を置いており、XNU の code signature 検証の背後にあるロジックを提供します。また、entitlements の確認や、debugging の許可、task ports の取得など、その他の機密性の高い処理にも対応します。

さらに、一部の操作では、kext は user space で動作する daemon `/usr/libexec/amfid` への接続を優先します。この trust relationship は、複数の jailbreak で悪用されてきました。

最近の macOS バージョンでは、AMFI は on-disk の standalone kext として簡単に公開されなくなっているため、通常は `/System/Library/Extensions` を調べるのではなく、**kernelcache** または **KDK** を使って reverse engineering することになります。

AMFI は **MACF** policies を使用し、起動すると同時にその hooks を登録します。また、その loading を防止したり unloading したりすると、kernel panic が発生する可能性があります。ただし、AMFI を無効化できる boot arguments がいくつか存在します。

- `amfi_unrestricted_task_for_pid`: 必要な entitlements がなくても task_for_pid を許可する
- `amfi_allow_any_signature`: 任意の code signature を許可する
- `cs_enforcement_disable`: system-wide で code signing enforcement を無効化するために使用される argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements を持つ platform binaries を無効にする
- `amfi_get_out_of_my_way`: amfi を完全に無効化する

以下は、登録される MACF policies の一部です:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** Label の更新を実行し、1 を返す
- **`cred_label_associate`**: AMFI の mac label slot を label で更新する
- **`cred_label_destroy`**: AMFI の mac label slot を削除する
- **`cred_label_init`**: AMFI の mac label slot に 0 を移動する
- **`cred_label_update_execve`:** プロセスの entitlements を確認し、label の変更が許可されるべきかを判断する
- **`file_check_mmap`:** mmap が memory を取得し、それを executable として設定しているかを確認する。その場合、library validation が必要かを確認し、必要であれば library validation function を呼び出す
- **`file_check_library_validation`**: library validation function を呼び出す。この function は、platform binary が別の platform binary を loading しているか、process と新たに loaded された file が同じ TeamID を持つかなどを確認する。特定の entitlements により、任意の library の loading も許可される
- **`policy_initbsd`**: trusted NVRAM Keys を設定する
- **`policy_syscall`**: binary が unrestricted segments を持つか、env vars を許可すべきかなど、DYLD policies を確認する。これは `amfi_check_dyld_policy_self()` を介して process が開始された場合にも呼び出される
- **`proc_check_inherit_ipc_ports`**: process が新しい binary を実行した際、他の processes がその process の task port に対する SEND rights を持っている場合、それらを維持すべきかどうかを確認する。Platform binaries、`get-task-allow` entitlement を持つもの、`task_for_pid-allow` entitlements を持つもの、同じ TeamID を持つ binaries は許可される
- **`proc_check_expose_task`**: entitlements を強制する
- **`amfi_exc_action_check_exception_send`**: debugger に exception message を送信する
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling（debugging）中の label lifecycle
- **`proc_check_get_task`**: `get-task-allow` などの entitlements を確認する。これは他の processes がその process の task port を取得することを許可し、`task_for_pid-allow` はその process が他の processes の task ports を取得することを許可する。どちらも存在しない場合は、`amfid permitunrestricteddebugging` を呼び出し、許可されているかを確認する
- **`proc_check_mprotect`**: region に有効な code signature があるものとして扱う必要があることを示す `VM_PROT_TRUSTED` flag を付けて `mprotect` が呼び出された場合は拒否する
- **`vnode_check_exec`**: executable files が memory に loaded された際に呼び出され、いずれかの pages が invalid になると process を kill する `cs_hard | cs_kill` を設定する<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` を確認する
- **`vnode_check_setextattr`**: `get` と同様に、`com.apple.private.allow-bless` および `internal-installer-equivalent` entitlement を確認する
- **`vnode_check_signature`**: entitlements、trust cache、`amfid` を使用して XNU に code signature の確認を行わせる code<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` calls（`PT_ATTACH` と `PT_TRACE_ME`）を intercept する。`get-task-allow`、`run-invalid-allow`、`run-unsigned-code` のいずれかの entitlements を確認し、どれも存在しない場合は debugging が許可されているかを確認する
- **`proc_check_map_anon`**: **`MAP_JIT`** flag を付けて mmap が呼び出された場合、AMFI は `dynamic-codesigning` entitlement を確認する

`AMFI.kext` は他の kernel extensions 向けの API も公開しており、以下の方法でその dependencies を確認できます。
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

これは user mode で実行される daemon で、`AMFI.kext` は user mode における code signature のチェックに使用します。\
`AMFI.kext` がこの daemon と通信するために、port `HOST_AMFID_PORT`（special port `18`）を介して mach messages を使用します。

macOS では、special ports は `SIP` によって保護され、launchd だけが取得できるため、root process が special ports を hijack することはもはやできない点に注意してください。iOS では、response を返す process が `amfid` の CDHash を hardcode された値として持っているかどうかがチェックされます。

`amfid` が binary のチェックを要求されたタイミングと、その response は、debugging を行い、`mach_msg` に breakpoint を設定することで確認できます。

special port 経由で message を受信すると、**MIG** が各 function を呼び出し先の function に送信するために使用されます。主要な function については reverse 解析され、book 内で説明されています。

### DYLD policy と library validation

Recent `dyld` versions は、`configureProcessRestrictions()` から非常に早い段階で `amfi_check_dyld_policy_self()` を呼び出し、process が `DYLD_*` path variables、interposing、fallback paths、embedded variables を使用できるか、または library insertion の失敗を許容できるかを AMFI に確認します。そのため、injection surface を triage する際には、Mach-O load commands だけを調べるだけでは不十分です。AMFI が `dyld` policy に変換する entitlements と runtime flags も調べる必要があります。

実用的な triage loop は次のとおりです。
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
現代の macOS では、多くの Apple バイナリが `com.apple.security.cs.disable-library-validation` を直接保持せず、代わりに `com.apple.private.security.clear-library-validation` を含むようになっています。この場合、library validation は `execve` の時点では無効化されません。プロセス自身が `csops(..., CS_OPS_CLEAR_LV, ...)` を呼び出す必要があり、XNU は entitlement が存在する場合に限り、呼び出し元のプロセスに対してこの操作を許可します。攻撃者の視点では、これは重要な点です。対象は、明示的に LV をクリアする code path（例えば、optional plugin をロードする直前）に到達した**後**にのみ injectable になる可能性があるためです。<sup>[4][5]</sup>

## Provisioning Profiles

provisioning profile は code の署名に使用できます。code の署名とテストに使用できる **Developer** profile と、すべてのデバイスで使用できる **Enterprise** profile があります。

App が Apple Store に submit され、承認されると、Apple によって署名され、provisioning profile は不要になります。

profile には通常、`.mobileprovision` または `.provisionprofile` という extension が付いており、以下のコマンドで dump できます。
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Although sometimes referred to as certificated, these provisioning profiles have more than a certificate:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: これが Apple Internal profile であることを示す
- **ApplicationIdentifierPrefix**: AppIDName の前に付加される（TeamIdentifier と同じ）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の日付
- **DeveloperCertificates**: Base64 data としてエンコードされた（通常は 1 つの）certificate の配列
- **Entitlements**: この profile で許可される entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の有効期限
- **Name**: Application Name。AppIDName と同じ
- **ProvisionedDevices**: この profile が有効な UDID の配列（developer certificates の場合）
- **ProvisionsAllDevices**: boolean（enterprise certificates の場合は true）
- **TeamIdentifier**: inter-app interaction の目的で developer を識別するために使用される、（通常は 1 つの）英数字文字列の配列
- **TeamName**: developer を識別するために使用される、人間が読める名前
- **TimeToLive**: certificate の有効期間（日数）
- **UUID**: この profile の Universally Unique Identifier
- **Version**: 現在は 1 に設定

entitlements エントリには制限された entitlements のセットが含まれ、Apple の private entitlements を付与できないように、provisioning profile はそれらの特定の entitlements のみを付与できます。

profiles は通常 `/var/MobileDeviceProvisioningProfiles` にあり、**`security cms -D -i /path/to/profile`** で確認できます。

## **libmis.dylib**

これは、何かを許可すべきかどうかを問い合わせるために `amfid` が呼び出す external library です。これまでは、すべてを許可する backdoored version を実行することで、jailbreaking に悪用されてきました。

macOS では、これは `MobileDevice.framework` の内部にあります。

## AMFI Trust Caches

Trust caches は iOS だけの概念ではありません。modern macOS、特に **Apple silicon** では、static trust cache と loadable trust caches が Secure Boot chain の一部です。Mach-O の **CodeDirectory hash** がそこに存在する場合、AMFI は launch 時に追加の authenticity checks を行わずに **platform privilege** を付与できます。これは、Apple が platform binaries を特定の OS version に固定し、新しい system 上で古い Apple-signed binaries が replay されるのを防止できることも意味します。<sup>[6]</sup>

recent macOS releases では、trust-cache metadata も **launch constraints** に関連付けられています。そのため、コピーされた system apps や binaries は、Apple-signed のままであっても、誤った parent/location から起動されると AMFI によって拒否される可能性があります。詳細な extraction と reversing の workflow については、以下で説明しています。

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS と jailbreak research では、ad-hoc signed binaries を whitelist するために、従来の **loadable trust caches** モデルが使用されていることも確認できます。

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
