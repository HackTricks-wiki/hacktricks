# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext と amfid

システム上で実行される code の integrity の強制に重点を置き、XNU の code signature 検証の背後にあるロジックを提供します。また、entitlements の確認や、debugging の許可、task ports の取得などの機密性の高い処理にも対応できます。

さらに、一部の操作では、kext は user space で実行されている daemon `/usr/libexec/amfid` への接続を優先します。この trust relationship は、複数の jailbreak で悪用されています。

最近の macOS versions では、AMFI は独立した on-disk kext として簡単に公開されなくなったため、通常、reverse engineering では `/System/Library/Extensions` を調べる代わりに、**kernelcache** または **KDK** を扱うことになります。

AMFI は **MACF** policies を使用し、起動した時点で hooks を登録します。また、その loading を防止したり unloading したりすると、kernel panic が発生する可能性があります。ただし、AMFI を無効化できる boot arguments がいくつか存在します。

- `amfi_unrestricted_task_for_pid`: 必要な entitlements なしで task_for_pid を許可
- `amfi_allow_any_signature`: 任意の code signature を許可
- `cs_enforcement_disable`: code signing enforcement を system-wide で無効化するために使用される argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements を持つ platform binaries を無効化
- `amfi_get_out_of_my_way`: amfi を完全に無効化

AMFI が登録する MACF policies の一部を以下に示します。<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label の update を実行し、1 を返す
- **`cred_label_associate`**: AMFI の mac label slot を label で update
- **`cred_label_destroy`**: AMFI の mac label slot を削除
- **`cred_label_init`**: AMFI の mac label slot に 0 を移動
- **`cred_label_update_execve:`**: process の entitlements を確認し、label の変更が許可されるかを確認
- **`file_check_mmap:`**: mmap が memory を取得し、executable として設定しているかを確認します。その場合、library validation が必要かを確認し、必要であれば library validation function を呼び出します。
- **`file_check_library_validation`**: library validation function を呼び出します。この function は、platform binary が別の platform binary を load しているか、process と新たに load された file が同じ TeamID を持つかなどを確認します。特定の entitlements により、任意の library の load も許可されます。
- **`policy_initbsd`**: trusted NVRAM Keys を設定
- **`policy_syscall`**: binary に unrestricted segments があるか、env vars を許可すべきかなど、DYLD policies を確認します。process が `amfi_check_dyld_policy_self()` によって起動された場合にも呼び出されます。
- **`proc_check_inherit_ipc_ports`**: process が新しい binary を実行したとき、他の processes がその process の task port に対する SEND rights を保持すべきかどうかを確認します。Platform binaries、`get-task-allow` entitlement、`task_for_pid-allow` entitlements、同じ TeamID を持つ binaries は許可されます。
- **`proc_check_expose_task`**: entitlements を強制
- **`amfi_exc_action_check_exception_send`**: debugger に exception message を送信
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling（debugging）中の Label lifecycle
- **`proc_check_get_task`**: 他の processes が process の task port を取得できる `get-task-allow` や、process が他の processes の task ports を取得できる `task_for_pid-allow` などの entitlements を確認します。どちらも存在しない場合は、`amfid permitunrestricteddebugging` を呼び出して許可されているかを確認します。
- **`proc_check_mprotect`**: `mprotect` が、region を有効な code signature があるものとして扱う必要があることを示す `VM_PROT_TRUSTED` flag 付きで呼び出された場合は deny
- **`vnode_check_exec`**: executable files が memory に load されたときに呼び出され、いずれかの pages が invalid になった場合に process を kill する `cs_hard | cs_kill` を設定します。<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` を確認
- **`vnode_check_setextattr`**: get に加えて、com.apple.private.allow-bless および internal-installer-equivalent entitlement を確認
- **`vnode_check_signature`**: entitlements、trust cache、`amfid` を使用して code signature を確認するために XNU を呼び出す code<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` calls（`PT_ATTACH` および `PT_TRACE_ME`）を intercept します。`get-task-allow`、`run-invalid-allow`、`run-unsigned-code` のいずれかの entitlements を確認し、いずれも存在しない場合は debugging が許可されているかを確認します。
- **`proc_check_map_anon`**: mmap が **`MAP_JIT`** flag 付きで呼び出された場合、AMFI は `dynamic-codesigning` entitlement を確認します。

`AMFI.kext` は他の kernel extensions 向けの API も公開しており、次の方法で dependencies を確認できます。
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

これは user mode で動作する daemon で、`AMFI.kext` が user mode で code signature をチェックするために使用します。\
`AMFI.kext` がこの daemon と通信するために、port `HOST_AMFID_PORT`（special port `18`）上で mach messages を使用します。

macOS では、special ports は `SIP` によって保護され、launchd だけが取得できるため、root process が special ports を hijack することはもはやできません。iOS では、response を返す process が `amfid` の CDHash を hardcoded で持っているかどうかがチェックされます。

`amfid` が binary のチェックを要求された時点と、その response は、debugging を行って `mach_msg` に breakpoint を設定することで確認できます。

special port 経由で message を受信すると、**MIG** が各 function を、呼び出される function に送信するために使用されます。主要な function は reverse 解析され、book 内で説明されています。

### DYLD policy and library validation

Recent `dyld` versions は、`configureProcessRestrictions()` から非常に早い段階で `amfi_check_dyld_policy_self()` を呼び出し、process が `DYLD_*` path variables、interposing、fallback paths、embedded variables を使用できるか、または failed library insertion を許容できるかを AMFI に問い合わせます。したがって、injection surface を triage する際は、Mach-O load commands だけを調べれば十分ではありません。entitlements と runtime flags も調べ、AMFI がそれらを `dyld` policy に変換する仕組みを確認する必要があります。

実用的な triage loop は次のとおりです。
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
最新のmacOSでは、多くのAppleバイナリが`com.apple.security.cs.disable-library-validation`を直接持たず、代わりに`com.apple.private.security.clear-library-validation`を持つようになっています。この場合、library validationは`execve`時には無効化されません。プロセス自身が`csops(..., CS_OPS_CLEAR_LV, ...)`を呼び出す必要があり、XNUはentitlementが存在する場合にのみ、呼び出し元のプロセスに対してこの操作を許可します。攻撃の観点では、これは重要です。対象は、LVを明示的にクリアするコードパスに到達した**後**にのみinject可能になる場合があるためです（例えば、optional pluginsをロードする直前など）。<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profileはcodeのsigningに使用できます。codeのsigningとテストに使用できる**Developer** profilesと、すべてのデバイスで使用できる**Enterprise** profilesがあります。

AppをApple Storeに提出し、承認されると、Appleによってsigningされ、provisioning profileは不要になります。

profileの拡張子は通常`.mobileprovision`または`.provisionprofile`で、以下のコマンドでdumpできます。
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Although sometimes referred as certificated, these provisioning profiles have more than a certificate:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: これが Apple Internal profile であることを示します
- **ApplicationIdentifierPrefix**: AppIDName の先頭に付加されます（TeamIdentifier と同じ）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の日付
- **DeveloperCertificates**: Base64 data としてエンコードされた証明書の配列（通常は1つ）
- **Entitlements**: この profile で許可される entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の有効期限
- **Name**: Application Name（AppIDName と同じ）
- **ProvisionedDevices**: この profile が有効な UDID の配列（developer certificates の場合）
- **ProvisionsAllDevices**: boolean（enterprise certificates の場合は true）
- **TeamIdentifier**: inter-app interaction の目的で developer を識別するために使用される英数字の文字列の配列（通常は1つ）
- **TeamName**: developer を識別するために使用される、人間が読める名前
- **TimeToLive**: certificate の有効期間（日数）
- **UUID**: この profile の Universally Unique Identifier
- **Version**: 現在は 1 に設定

entitlements entry には制限された entitlements のセットが含まれ、Apple private entitlements が付与されるのを防ぐため、provisioning profile はそれらの specific entitlements のみを付与できることに注意してください。

profiles は通常 `/var/MobileDeviceProvisioningProfiles` にあり、**`security cms -D -i /path/to/profile`** で確認できます。

## **libmis.dylib**

これは、何かを許可すべきかどうかを問い合わせるために `amfid` が呼び出す外部 library です。過去には、すべてを許可する backdoored version を実行することで、jailbreaking に悪用されてきました。

macOS では、これは `MobileDevice.framework` 内にあります。

## AMFI Trust Caches

Trust caches は iOS だけの概念ではありません。modern macOS、特に **Apple silicon** では、static trust cache と loadable trust caches は Secure Boot chain の一部です。Mach-O の **CodeDirectory hash** がそこに存在する場合、AMFI は launch 時に追加の authenticity checks を行わずに、対象へ **platform privilege** を付与できます。これは、Apple が platform binaries を特定の OS version に固定し、新しい system 上で古い Apple-signed binaries が replay されるのを防止できることも意味します。<sup>[[6]](#references)</sup>

recent macOS releases では、trust-cache metadata も **launch constraints** に関連付けられています。そのため、copied system apps や binaries は、Apple-signed のままであっても、誤った parent/location から起動されると AMFI によって拒否される可能性があります。詳細な extraction および reversing workflow については、以下で説明しています。

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS および jailbreak research では、ad-hoc signed binaries を whitelist するために、従来の **loadable trust caches** model が使用されていることも確認できます。

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
