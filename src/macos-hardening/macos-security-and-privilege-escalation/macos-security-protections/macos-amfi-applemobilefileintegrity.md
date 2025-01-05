# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext と amfid

これは、システム上で実行されるコードの整合性を強制することに焦点を当てており、XNUのコード署名検証の背後にあるロジックを提供します。また、権限をチェックし、デバッグを許可したりタスクポートを取得したりするなどの他の敏感なタスクを処理することもできます。

さらに、いくつかの操作において、kextはユーザースペースで実行されているデーモン `/usr/libexec/amfid` に連絡することを好みます。この信頼関係は、いくつかの脱獄で悪用されてきました。

AMFIは **MACF** ポリシーを使用し、起動時にフックを登録します。また、その読み込みやアンロードを防ぐと、カーネルパニックが発生する可能性があります。ただし、AMFIを弱体化させるいくつかのブート引数があります：

- `amfi_unrestricted_task_for_pid`: 必要な権限なしで task_for_pid を許可
- `amfi_allow_any_signature`: 任意のコード署名を許可
- `cs_enforcement_disable`: コード署名の強制を無効にするためのシステム全体の引数
- `amfi_prevent_old_entitled_platform_binaries`: 権限のあるプラットフォームバイナリを無効にする
- `amfi_get_out_of_my_way`: amfi を完全に無効にする

これらは、登録されるいくつかの MACF ポリシーです：

- **`cred_check_label_update_execve:`** ラベルの更新が行われ、1が返されます
- **`cred_label_associate`**: AMFIのmacラベルスロットをラベルで更新
- **`cred_label_destroy`**: AMFIのmacラベルスロットを削除
- **`cred_label_init`**: AMFIのmacラベルスロットに0を移動
- **`cred_label_update_execve`:** プロセスの権限をチェックし、ラベルの変更が許可されるべきかを確認します。
- **`file_check_mmap`:** mmapがメモリを取得し、実行可能として設定しているかをチェックします。その場合、ライブラリの検証が必要かどうかを確認し、必要であればライブラリ検証関数を呼び出します。
- **`file_check_library_validation`**: ライブラリ検証関数を呼び出し、プラットフォームバイナリが別のプラットフォームバイナリを読み込んでいるか、プロセスと新しく読み込まれたファイルが同じTeamIDを持っているかなどを確認します。特定の権限により、任意のライブラリを読み込むことも許可されます。
- **`policy_initbsd`**: 信頼されたNVRAMキーを設定
- **`policy_syscall`**: バイナリが制限のないセグメントを持っているか、環境変数を許可するべきかなど、DYLDポリシーをチェックします...これは、`amfi_check_dyld_policy_self()`を介してプロセスが開始されるときにも呼び出されます。
- **`proc_check_inherit_ipc_ports`**: プロセスが新しいバイナリを実行する際に、他のプロセスがプロセスのタスクポートに対してSEND権を持っている場合、それを保持するかどうかをチェックします。プラットフォームバイナリは許可され、`get-task-allow`権限がそれを許可し、`task_for_pid-allow`権限が許可され、同じTeamIDを持つバイナリも許可されます。
- **`proc_check_expose_task`**: 権限を強制
- **`amfi_exc_action_check_exception_send`**: 例外メッセージがデバッガに送信されます
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: 例外処理中のラベルライフサイクル（デバッグ）
- **`proc_check_get_task`**: `get-task-allow`のような権限をチェックし、他のプロセスがタスクポートを取得できるかどうかを確認し、`task_for_pid-allow`が許可されている場合、プロセスが他のプロセスのタスクポートを取得できるかどうかを確認します。どちらもない場合、`amfid permitunrestricteddebugging`を呼び出して許可されているかを確認します。
- **`proc_check_mprotect`**: `mprotect`がフラグ `VM_PROT_TRUSTED` で呼び出された場合、拒否します。これは、その領域が有効なコード署名を持っているかのように扱われる必要があることを示します。
- **`vnode_check_exec`**: 実行可能ファイルがメモリに読み込まれるときに呼び出され、`cs_hard | cs_kill`を設定します。これにより、ページのいずれかが無効になるとプロセスが終了します。
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` と `isVnodeQuarantined()` をチェック
- **`vnode_check_setextattr`**: get + com.apple.private.allow-bless および internal-installer-equivalent 権限として
- **`vnode_check_signature`**: 権限、信頼キャッシュ、および `amfid` を使用してコード署名をチェックするためにXNUを呼び出すコード
- **`proc_check_run_cs_invalid`**: `ptrace()`呼び出し（`PT_ATTACH`および`PT_TRACE_ME`）をインターセプトします。`get-task-allow`、`run-invalid-allow`、および `run-unsigned-code` のいずれかの権限をチェックし、いずれもない場合はデバッグが許可されているかを確認します。
- **`proc_check_map_anon`**: mmapが **`MAP_JIT`** フラグで呼び出された場合、AMFIは `dynamic-codesigning` 権限をチェックします。

`AMFI.kext` は他のカーネル拡張のためのAPIも公開しており、その依存関係を見つけることが可能です：
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

これは、`AMFI.kext`がユーザーモードでコード署名をチェックするために使用するユーザーモードのデーモンです。\
`AMFI.kext`がデーモンと通信するためには、特別なポート`18`である`HOST_AMFID_PORT`を介してmachメッセージを使用します。

macOSでは、特別なポートをrootプロセスがハイジャックすることはもはや不可能であり、これらは`SIP`によって保護されており、launchdのみがそれらを取得できます。iOSでは、応答を返すプロセスが`amfid`のCDHashをハードコーディングしていることが確認されます。

`amfid`がバイナリをチェックするように要求されたときとその応答を見ることが可能であり、これをデバッグして`mach_msg`にブレークポイントを設定することで確認できます。

特別なポートを介してメッセージが受信されると、**MIG**が呼び出されている関数に各関数を送信するために使用されます。主要な関数は逆アセンブルされ、本書内で説明されています。

## Provisioning Profiles

プロビジョニングプロファイルは、コードに署名するために使用できます。コードに署名してテストするために使用できる**Developer**プロファイルと、すべてのデバイスで使用できる**Enterprise**プロファイルがあります。

アプリがApple Storeに提出され、承認されると、Appleによって署名され、プロビジョニングプロファイルはもはや必要ありません。

プロファイルは通常、拡張子`.mobileprovision`または`.provisionprofile`を使用し、次のコマンドでダンプできます:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
これらのプロビジョニングプロファイルは、時には証明書として言及されますが、証明書以上のものがあります：

- **AppIDName:** アプリケーション識別子
- **AppleInternalProfile**: これをApple内部プロファイルとして指定します
- **ApplicationIdentifierPrefix**: AppIDNameの前に付加される（TeamIdentifierと同じ）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ`形式の日付
- **DeveloperCertificates**: Base64データとしてエンコードされた（通常は1つの）証明書の配列
- **Entitlements**: このプロファイルに許可される権利
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ`形式の有効期限
- **Name**: アプリケーション名、AppIDNameと同じ
- **ProvisionedDevices**: このプロファイルが有効なUDIDの配列（開発者証明書用）
- **ProvisionsAllDevices**: ブール値（企業証明書の場合はtrue）
- **TeamIdentifier**: アプリ間の相互作用の目的で開発者を識別するために使用される（通常は1つの）英数字の文字列の配列
- **TeamName**: 開発者を識別するために使用される人間が読める名前
- **TimeToLive**: 証明書の有効期間（日数）
- **UUID**: このプロファイルのユニバーサルユニーク識別子
- **Version**: 現在1に設定されています

権利のエントリには制限された権利のセットが含まれ、このプロビジョニングプロファイルはAppleのプライベート権利を与えないように特定の権利のみを提供できます。

プロファイルは通常`/var/MobileDeviceProvisioningProfiles`にあり、**`security cms -D -i /path/to/profile`**を使用して確認することができます。

## **libmis.dyld**

これは、`amfid`が何かを許可すべきかどうかを尋ねるために呼び出す外部ライブラリです。これは、すべてを許可するバックドア版を実行することによって、脱獄で歴史的に悪用されてきました。

macOSでは、これは`MobileDevice.framework`内にあります。

## AMFI Trust Caches

iOS AMFIは、アドホックに署名された既知のハッシュのリストを維持しており、これを**Trust Cache**と呼び、kextの`__TEXT.__const`セクションにあります。非常に特定の敏感な操作では、外部ファイルでこのTrust Cacheを拡張することが可能です。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
