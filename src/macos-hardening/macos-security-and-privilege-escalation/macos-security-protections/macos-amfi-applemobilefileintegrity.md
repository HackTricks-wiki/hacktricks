# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

これは、システム上で実行されるコードの整合性を強制し、XNU のコード署名検証のロジックを提供することに重点を置いています。また、entitlements の確認や、debugging の許可、task ports の取得などの他の機密性の高い処理も扱えます。

さらに、一部の操作では、kext はユーザースペースで動作する daemon `/usr/libexec/amfid` への問い合わせを優先します。この信頼関係は、いくつかの jailbreak で悪用されてきました。

最近の macOS バージョンでは、AMFI はもはやスタンドアロンのオンディスク kext として都合よく公開されていないため、逆解析は通常 `/System/Library/Extensions` を参照するのではなく、**kernelcache** または **KDK** を使って行います。

AMFI は **MACF** policies を使用し、起動した瞬間にその hooks を登録します。また、その読み込みを妨げたりアンロードしたりすると、kernel panic を引き起こす可能性があります。ただし、AMFI を弱体化させる boot arguments がいくつかあります:

- `amfi_unrestricted_task_for_pid`: 必要な entitlements なしで task_for_pid を許可する
- `amfi_allow_any_signature`: どんな code signature でも許可する
- `cs_enforcement_disable`: code signing enforcement をシステム全体で無効化するための引数
- `amfi_prevent_old_entitled_platform_binaries`: entitlements を持つ platform binaries を無効化する
- `amfi_get_out_of_my_way`: amfi を完全に無効化する

これは、登録される MACF policies の一部です:

- **`cred_check_label_update_execve:`** Label の更新が実行され、1 を返す
- **`cred_label_associate`**: AMFI の mac label スロットを label で更新する
- **`cred_label_destroy`**: AMFI の mac label スロットを削除する
- **`cred_label_init`**: AMFI の mac label スロットを 0 にする
- **`cred_label_update_execve`:** プロセスの entitlements を確認し、label を変更してよいかを判定する
- **`file_check_mmap`:** mmap がメモリを取得して実行可能に設定しているかを確認する。その場合、library validation が必要かを確認し、必要なら library validation 関数を呼び出す
- **`file_check_library_validation`**: library validation 関数を呼び出し、たとえば platform binary が別の platform binary を読み込んでいるか、あるいは process と新しく読み込まれた file が同じ TeamID を持つかなどを確認する。特定の entitlements があると任意の library の読み込みも許可される
- **`policy_initbsd`**: 信頼された NVRAM Keys を設定する
- **`policy_syscall`**: binary に unrestricted segments があるか、環境変数を許可すべきかなど、DYLD policies を確認する。process が `amfi_check_dyld_policy_self()` 経由で開始された場合にも呼び出される
- **`proc_check_inherit_ipc_ports`**: process が新しい binary を実行したとき、process の task port に対して SEND 権限を持つ他の process について、その権限を維持するかどうかを確認する。platform binaries は許可され、`get-task-allow` の entitlement があれば許可され、`task_for_pid-allow` の entitlement があれば許可され、さらに同じ TeamID を持つ binaries も許可される
- **`proc_check_expose_task`**: entitlements を強制する
- **`amfi_exc_action_check_exception_send`**: exception message が debugger に送信される
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: debugging 中の exception handling における label のライフサイクル
- **`proc_check_get_task`**: `get-task-allow` のような entitlements を確認する。これは他の process が task port を取得することを許可し、`task_for_pid-allow` は process が他の process の task port を取得することを許可する。どちらもない場合は、許可されるかどうかを確認するために `amfid permitunrestricteddebugging` に問い合わせる
- **`proc_check_mprotect`**: `mprotect` が `VM_PROT_TRUSTED` フラグ付きで呼ばれた場合に拒否する。これは、その領域が有効な code signature を持つものとして扱われるべきことを示す
- **`vnode_check_exec`**: 実行可能 file がメモリに読み込まれたときに呼び出され、`cs_hard | cs_kill` を設定する。これにより、どのページでも無効になると process は kill される
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` を確認する
- **`vnode_check_setextattr`**: get に加えて `com.apple.private.allow-bless` と internal-installer-equivalent entitlement を確認する
- **`vnode_check_signature`**: entitlements、trust cache、`amfid` を使って XNU に code signature の確認を行わせるコード
- **`proc_check_run_cs_invalid`**: `ptrace()` 呼び出し（`PT_ATTACH` と `PT_TRACE_ME`）を intercept する。`get-task-allow`、`run-invalid-allow`、`run-unsigned-code` のいずれかの entitlement があるかを確認し、どれもなければ debugging が許可されているかを確認する
- **`proc_check_map_anon`**: `mmap` が **`MAP_JIT`** フラグ付きで呼ばれた場合、AMFI は `dynamic-codesigning` entitlement を確認する

`AMFI.kext` は他の kernel extensions 向けの API も公開しており、次の方法で依存関係を見つけることができます:
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

これは、`AMFI.kext` が user mode で code signature を確認するために使う user mode の実行中 daemon です。\
`AMFI.kext` がこの daemon と通信するには、特別な port `18` である `HOST_AMFID_PORT` を介して mach messages を使います。

macOS では、root process が special ports を hijack することはもはや不可能です。`SIP` によって保護されており、`launchd` だけが取得できます。iOS では、応答を返す process の CDHash が `amfid` のものとして hardcoded されているかが確認されます。

`amfid` に binary の確認が要求されたときと、その応答を、`mach_msg` に breakpoint を設定して debug することで確認できます。

special port 経由で message を受信すると、**MIG** が使われ、呼び出されている function ごとに function が送られます。主要な functions は reverse され、本の中で説明されています。

### DYLD policy and library validation

最近の `dyld` versions は、`configureProcessRestrictions()` の非常に早い段階で `amfi_check_dyld_policy_self()` を呼び出し、process が `DYLD_*` path variables、interposing、fallback paths、embedded variables を使えるか、あるいは失敗した library insertion を許容できるかを AMFI に問い合わせます。したがって、injection surface を triage するときは、Mach-O load commands だけを確認するのでは不十分です。AMFI が `dyld` policy に変換する entitlements と runtime flags も確認する必要があります。

実用的な triage loop は次のとおりです:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
現代の macOS では、多くの Apple バイナリが `com.apple.security.cs.disable-library-validation` を直接持たなくなり、その代わりに `com.apple.private.security.clear-library-validation` を使うようになっています。この場合、library validation は `execve` 時点では無効化されません。プロセスは自分自身に対して `csops(..., CS_OPS_CLEAR_LV, ...)` を呼び出す必要があり、XNU はその entitlement が存在する場合にのみ、呼び出し元プロセスに対してこの操作を許可します。攻撃側の観点では、これは重要です。なぜなら、ターゲットは LV を明示的に解除するコードパスに到達した「後」で初めて injectable になる可能性があるからです（たとえば、任意の plugins を読み込む直前など）。

## Provisioning Profiles

provisioning profile は code を署名するために使えます。code を署名してテストできる **Developer** profiles と、すべての devices で使用できる **Enterprise** profiles があります。

App が Apple Store に提出され、承認されると、Apple によって署名され、provisioning profile は不要になります。

profile は通常 `.mobileprovision` または `.provisionprofile` という extension を使い、次のように dump できます:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
certificated と呼ばれることもありますが、これらの provisioning profiles には certificate 以上の情報が含まれています:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: これが Apple Internal profile であることを示す
- **ApplicationIdentifierPrefix**: AppIDName の前に付加される (TeamIdentifier と同じ)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の日付
- **DeveloperCertificates**: Base64 data としてエンコードされた (通常 1 つの) certificate の配列
- **Entitlements**: この profile に対して許可される entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 形式の有効期限
- **Name**: Application Name、AppIDName と同じ
- **ProvisionedDevices**: この profile が有効な UDID の配列 (developer certificates 用)
- **ProvisionsAllDevices**: boolean (enterprise certificates の場合は true)
- **TeamIdentifier**: app 間の相互作用目的で developer を識別するために使われる (通常 1 つの) 英数字文字列の配列
- **TeamName**: developer を識別するための人間が読める名前
- **TimeToLive**: certificate の有効期間 (日数)
- **UUID**: この profile の Universally Unique Identifier
- **Version**: 現在は 1 に設定

entitlements entry には制限された entitlements のセットが含まれ、provisioning profile は Apple private entitlements を付与しないように、その特定の entitlements だけを付与できます。

profiles は通常 `/var/MobileDeviceProvisioningProfiles` にあり、**`security cms -D -i /path/to/profile`** で確認できます。

## **libmis.dylib**

これは `amfid` が、何かを許可すべきかどうかを確認するために呼び出す外部 library です。歴史的には、すべてを許可する backdoored version を実行することで jailbreak で悪用されてきました。

macOS ではこれは `MobileDevice.framework` の中にあります。

## AMFI Trust Caches

Trust caches は iOS の概念だけではありません。現代の macOS、特に **Apple silicon** では、static trust cache と loadable trust caches は Secure Boot chain の一部です。Mach-O の **CodeDirectory hash** がそこに存在すると、AMFI は起動時に追加の authenticity checks を行わずに、それへ **platform privilege** を付与できます。これはまた、Apple が platform binaries を特定の OS version に固定し、Apple が署名した古い binaries が新しいシステム上で再利用されるのを防げることも意味します。

最近の macOS リリースでは、trust-cache metadata は **launch constraints** にも結び付けられているため、正しくない parent/location から起動されたコピー済みの system apps や binaries は、たとえ Apple-signed のままでも AMFI に拒否されることがあります。詳細な extraction と reversing の手順は以下で説明されています:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS と jailbreak research では、今でも **loadable trust caches** の従来モデルが使われ、ad-hoc signed binaries を whitelist するのが一般的です。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
