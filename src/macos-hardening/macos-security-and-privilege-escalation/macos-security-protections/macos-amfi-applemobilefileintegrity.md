# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

これは、システム上で実行されるコードの整合性を強制することに重点を置いており、XNU の code signature 検証のロジックを提供します。また、entitlements を確認したり、debugging を許可する、task ports を取得するなどの他の機微な処理も扱えます。

さらに、一部の操作では、kext はユーザースペースで動作する daemon `/usr/libexec/amfid` と通信することを優先します。この信頼関係は、いくつかの jailbreak で悪用されてきました。

最近の macOS バージョンでは、AMFI はもはやディスク上で単独の kext として都合よく公開されていないため、通常は `/System/Library/Extensions` を調べるのではなく、**kernelcache** か **KDK** から解析します。

AMFI は **MACF** policies を使用し、起動した瞬間に hooks を登録します。また、その読み込みを妨げたり unload したりすると kernel panic を引き起こす可能性があります。ただし、AMFI を弱体化させる boot arguments もいくつかあります。

- `amfi_unrestricted_task_for_pid`: 必要な entitlements なしで task_for_pid を許可
- `amfi_allow_any_signature`: 任意の code signature を許可
- `cs_enforcement_disable`: code signing enforcement をシステム全体で無効化する引数
- `amfi_prevent_old_entitled_platform_binaries`: entitlements を持つ platform binaries を無効化
- `amfi_get_out_of_my_way`: amfi を完全に無効化

以下は、AMFI が登録する MACF policies の一部です。

- **`cred_check_label_update_execve:`** ラベル更新が実行され、1 を返す
- **`cred_label_associate`**: AMFI の mac label slot を label で更新
- **`cred_label_destroy`**: AMFI の mac label slot を削除
- **`cred_label_init`**: AMFI の mac label slot で 0 に移動
- **`cred_label_update_execve`:** プロセスの entitlements を確認し、labels を変更してよいか判定する
- **`file_check_mmap`:** mmap がメモリを取得してそれを executable に設定しようとしているかを確認する。その場合、library validation が必要かを確認し、必要なら library validation 関数を呼び出す
- **`file_check_library_validation`**: library validation 関数を呼び出し、platform binary が別の platform binary を読み込んでいるかどうか、またはプロセスと新しく読み込まれたファイルが同じ TeamID を持つかどうかなどを確認する。特定の entitlements があれば任意の library の読み込みも許可される
- **`policy_initbsd`**: 信頼された NVRAM Keys を設定
- **`policy_syscall`**: binary に unrestricted segments があるか、環境変数を許可すべきかなど、DYLD policies を確認する。これはプロセスが `amfi_check_dyld_policy_self()` 経由で開始されたときにも呼ばれる
- **`proc_check_inherit_ipc_ports`**: プロセスが新しい binary を実行したとき、プロセスの task port に対する SEND 権限を持つ他のプロセスがそれを保持すべきかどうかを確認する。Platform binaries は許可され、`get-task-allow` entitlement でも許可され、`task_for_pid-allow` を持つものも許可され、さらに同じ TeamID の binaries も許可される
- **`proc_check_expose_task`**: entitlements を強制する
- **`amfi_exc_action_check_exception_send`**: exception message が debugger に送信される
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: debugging 中の exception handling における label のライフサイクル
- **`proc_check_get_task`**: 他のプロセスが task port を取得できる `get-task-allow` や、プロセスが他のプロセスの task port を取得できる `task_for_pid-allow` などの entitlements を確認する。どちらもなければ、許可されているかを確認するために `amfid permitunrestricteddebugging` へ問い合わせる
- **`proc_check_mprotect`**: `mprotect` が `VM_PROT_TRUSTED` フラグ付きで呼ばれた場合は拒否する。このフラグは、その領域を有効な code signature を持つものとして扱う必要があることを示す
- **`vnode_check_exec`**: executable files がメモリに読み込まれたときに呼ばれ、`cs_hard | cs_kill` を設定する。これにより、ページのいずれかが無効になるとプロセスが kill される
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` を確認
- **`vnode_check_setextattr`**: get + `com.apple.private.allow-bless` と internal-installer-equivalent entitlement
- **`vnode_check_signature`**: entitlements、trust cache、`amfid` を使って XNU に code signature の確認を要求するコード
- **`proc_check_run_cs_invalid`**: `ptrace()` 呼び出し (`PT_ATTACH` と `PT_TRACE_ME`) を中継する。`get-task-allow`、`run-invalid-allow`、`run-unsigned-code` のいずれかの entitlements を確認し、どれもなければ debugging が許可されているかを確認する
- **`proc_check_map_anon`**: `mmap` が **`MAP_JIT`** フラグ付きで呼ばれた場合、AMFI は `dynamic-codesigning` entitlement を確認する

`AMFI.kext` は他の kernel extensions 向けの API も公開しており、以下でその依存関係を見つけることができます:
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

これは `AMFI.kext` がユーザーモードでコード署名を確認するために使用するユーザーモード実行デーモンです。\
`AMFI.kext` がこのデーモンと通信するために、特別なポート `18` である `HOST_AMFID_PORT` を介して mach messages を使用します。

macOS では、root プロセスが special ports をハイジャックすることはもはやできません。`SIP` によって保護されており、`launchd` だけが取得できます。iOS では、応答を返すプロセスが `amfid` の CDHash をハードコードされたものと持っていることが確認されます。

`amfid` に binary のチェックが要求されたタイミングとその応答は、デバッグして `mach_msg` に breakpoint を設定することで確認できます。

special port 経由でメッセージを受信すると、各 function を呼び出し先の function に送るために **MIG** が使用されます。主要な functions はリバースされ、book 内で説明されています。

### DYLD policy and library validation

最近の `dyld` versions は、`configureProcessRestrictions()` のかなり早い段階で `amfi_check_dyld_policy_self()` を呼び出し、プロセスが `DYLD_*` path variables、interposing、fallback paths、embedded variables を使用できるか、または failed library insertion を許容できるかを AMFI に問い合わせます。そのため、injection surface を triage する際は Mach-O load commands だけを確認するのでは不十分です。AMFI が `dyld` policy に変換する entitlements と runtime flags も確認する必要があります。

実用的な triage loop は次のとおりです:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
現代の macOS では、多くの Apple バイナリはもはや直接 `com.apple.security.cs.disable-library-validation` を持たず、代わりに `com.apple.private.security.clear-library-validation` を含んでいます。その場合、library validation は `execve` 時に無効化されません。プロセスは自身に対して `csops(..., CS_OPS_CLEAR_LV, ...)` を呼び出す必要があり、XNU はその entitlement が存在する場合にのみ、呼び出し元プロセスに対してその操作を許可します。攻撃者の視点では、これは重要です。なぜなら、ターゲットは LV を明示的に解除するコードパスに到達した**後**にのみ注入可能になる場合があるからです（たとえば、オプションの plugins を読み込む直前など）。

## Provisioning Profiles

Provisioning profile は code に署名するために使えます。code に署名してテストできる **Developer** profiles と、すべての devices で使える **Enterprise** profiles があります。

App が Apple Store に提出され、承認されると、Apple によって署名され、provisioning profile は不要になります。

通常、profile の拡張子は `.mobileprovision` または `.provisionprofile` で、次の方法でダンプできます:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
たとえ certificated と呼ばれることがあっても、これらの provisioning profiles には certificate 以上のものが含まれます:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: これを Apple Internal profile と指定する
- **ApplicationIdentifierPrefix**: AppIDName の前に付加される（TeamIdentifier と同じ）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の日付
- **DeveloperCertificates**: Base64 data としてエンコードされた（通常 1 つの）certificate の配列
- **Entitlements**: この profile で許可される entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の有効期限
- **Name**: Application Name、AppIDName と同じ
- **ProvisionedDevices**: この profile が有効な UDID の配列（developer certificates 用）
- **ProvisionsAllDevices**: boolean（enterprise certificates では true）
- **TeamIdentifier**: app 間の interaction のために developer を識別するのに使われる、（通常 1 つの）英数字文字列の配列
- **TeamName**: developer を識別するための人間が読める名前
- **TimeToLive**: certificate の有効期間（日数）
- **UUID**: この profile の Universally Unique Identifier
- **Version**: 現在は 1 に設定されている

entitlements のエントリには制限された entitlements のセットが含まれ、provisioning profile はそれら特定の entitlements だけを付与できるため、Apple の private entitlements を与えることはできません。

profiles は通常 `/var/MobileDeviceProvisioningProfiles` にあり、**`security cms -D -i /path/to/profile`** で確認できます

## **libmis.dylib**

これは `amfid` が、何かを許可すべきかどうかを問い合わせるために呼び出す外部 library です。歴史的には、これを改変して全てを許可する backdoored version を実行する jailbreak で悪用されてきました。

macOS ではこれは `MobileDevice.framework` の中にあります。

## AMFI Trust Caches

Trust caches は iOS だけの概念ではありません。現代の macOS、特に **Apple silicon** では、static trust cache と loadable trust caches は Secure Boot chain の一部です。Mach-O の **CodeDirectory hash** がそこに存在すると、AMFI は起動時にそれ以上の真正性チェックを行わずに、そのバイナリへ **platform privilege** を付与できます。これはまた、Apple が platform binaries を特定の OS version に固定し、古い Apple-signed binaries が新しいシステムで再実行されるのを防げることも意味します。

最近の macOS release では、trust-cache metadata は **launch constraints** にも結び付けられているため、コピーされた system apps や、正しくない parent/location から起動された binaries は、Apple-signed のままであっても AMFI に拒否されることがあります。詳細な extraction と reversing の workflow は以下で解説されています:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS と jailbreak の research では、引き続き **loadable trust caches** の従来のモデルが、ad-hoc signed binaries を whitelist するために使われています。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
