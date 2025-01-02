# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

MacOS Sandbox（最初はSeatbeltと呼ばれていました）は、**サンドボックス内で実行されるアプリケーション**を、アプリが実行されている**サンドボックスプロファイルで指定された許可されたアクション**に**制限**します。これにより、**アプリケーションが予期されるリソースのみをアクセスすることが保証されます**。

**`com.apple.security.app-sandbox`**という**権限**を持つアプリは、サンドボックス内で実行されます。**Appleのバイナリ**は通常サンドボックス内で実行され、**App Store**のすべてのアプリケーションはその権限を持っています。したがって、いくつかのアプリケーションはサンドボックス内で実行されます。

プロセスが何をできるか、またはできないかを制御するために、**サンドボックスはほぼすべての操作にフック**を持っています（ほとんどのシステムコールを含む）**MACF**を使用しています。ただし、アプリの**権限**に応じて、サンドボックスはプロセスに対してより許可的になる場合があります。

サンドボックスの重要なコンポーネントは次のとおりです：

- **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
- **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- ユーザーランドで実行される**デーモン** `/usr/libexec/sandboxd`
- **コンテナ** `~/Library/Containers`

### コンテナ

すべてのサンドボックス化されたアプリケーションは、`~/Library/Containers/{CFBundleIdentifier}`に独自のコンテナを持ちます：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
各バンドルIDフォルダー内には、**plist**とアプリの**データディレクトリ**があり、ホームフォルダーに似た構造になっています。
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> サンドボックスから「脱出」して他のフォルダーにアクセスするためにシンボリックリンクがあっても、アプリはそれらにアクセスするための**権限を持っている必要があります**。これらの権限は、`RedirectablePaths`の**`.plist`**内にあります。

**`SandboxProfileData`**は、B64にエスケープされたコンパイル済みサンドボックスプロファイルCFDataです。
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> サンドボックスアプリケーションによって作成または変更されたすべてのものには、**隔離属性**が付与されます。これは、サンドボックスアプリが**`open`**を使用して何かを実行しようとした場合に、Gatekeeperをトリガーすることによってサンドボックス空間を防ぎます。

## サンドボックスプロファイル

サンドボックスプロファイルは、その**サンドボックス**で何が**許可/禁止**されるかを示す設定ファイルです。これは、[**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>)プログラミング言語を使用する**サンドボックスプロファイル言語（SBPL）**を使用します。

ここに例があります：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> この[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)を確認して、許可または拒否される可能性のあるアクションをさらに確認してください。
>
> プロファイルのコンパイル版では、操作の名前がdylibおよびkextによって知られている配列のエントリに置き換えられ、コンパイル版が短く、読みづらくなります。

重要な**システムサービス**は、`mdnsresponder`サービスのように独自のカスタム**サンドボックス**内で実行されます。これらのカスタム**サンドボックスプロファイル**は以下で確認できます：

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- その他のサンドボックスプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**アプリは**プロファイル****`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルで、**`com.apple.security.network.server`**のような権限がプロセスにネットワークを使用することを許可する方法を確認できます。

次に、一部の**Appleデーモンサービス**は、`/System/Library/Sandbox/Profiles/*.sb`または`/usr/share/sandbox/*.sb`にある異なるプロファイルを使用します。これらのサンドボックスは、API `sandbox_init_XXX`を呼び出すメイン関数で適用されます。

**SIP**は、`/System/Library/Sandbox/rootless.conf`にあるplatform_profileというサンドボックスプロファイルです。

### サンドボックスプロファイルの例

**特定のサンドボックスプロファイル**でアプリケーションを起動するには、次のようにします：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> **Apple**が作成した**ソフトウェア**は、**Windows**上で**追加のセキュリティ対策**、例えばアプリケーションサンドボックスがありません。

バイパスの例:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（彼らは`~$`で始まる名前のファイルをサンドボックスの外に書き込むことができます）。

### サンドボックストレース

#### プロファイル経由

アクションがチェックされるたびにサンドボックスが実行するすべてのチェックをトレースすることが可能です。そのためには、次のプロファイルを作成してください:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
その後、そのプロファイルを使用して何かを実行します:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` では、呼び出されるたびに実行される各サンドボックスチェックを見ることができます（つまり、多くの重複があります）。

**`-t`** パラメータを使用してサンドボックスをトレースすることも可能です: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API経由

`libsystem_sandbox.dylib` にエクスポートされている関数 `sandbox_set_trace_path` は、サンドボックスチェックが書き込まれるトレースファイル名を指定することを可能にします。\
`sandbox_vtrace_enable()` を呼び出し、その後 `sandbox_vtrace_report()` を呼び出してバッファからログエラーを取得することでも、同様のことが可能です。

### サンドボックス検査

`libsandbox.dylib` は、プロセスのサンドボックス状態のリスト（拡張を含む）を提供する `sandbox_inspect_pid` という関数をエクスポートしています。ただし、この関数はプラットフォームバイナリのみが使用できます。

### MacOS & iOS サンドボックスプロファイル

MacOS は、システムサンドボックスプロファイルを **/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles** の2つの場所に保存します。

サードパーティアプリケーションが _**com.apple.security.app-sandbox**_ 権限を持っている場合、システムはそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** プロファイルを適用します。

iOS では、デフォルトプロファイルは **container** と呼ばれ、SBPL テキスト表現はありません。メモリ内では、このサンドボックスはサンドボックスからの各権限のための許可/拒否バイナリツリーとして表現されます。

### App Store アプリのカスタム SBPL

企業が **カスタムサンドボックスプロファイル** でアプリを実行することが可能かもしれません（デフォルトのものではなく）。彼らは、Apple によって承認される必要がある権限 **`com.apple.security.temporary-exception.sbpl`** を使用する必要があります。

この権限の定義は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
この権限の後にある文字列は、Sandboxプロファイルとして**eval**されます。

### Sandboxプロファイルのコンパイルとデコンパイル

**`sandbox-exec`**ツールは、`libsandbox.dylib`の`sandbox_compile_*`関数を使用します。エクスポートされる主な関数は次のとおりです：`sandbox_compile_file`（ファイルパスを期待、パラメータ`-f`）、`sandbox_compile_string`（文字列を期待、パラメータ`-p`）、`sandbox_compile_name`（コンテナの名前を期待、パラメータ`-n`）、`sandbox_compile_entitlements`（権限plistを期待）。

この逆コンパイルされた[**sandbox-execツールのオープンソース版**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c)は、**`sandbox-exec`**がコンパイルされたSandboxプロファイルをファイルに書き込むことを可能にします。

さらに、プロセスをコンテナ内に制限するために、`sandbox_spawnattrs_set[container/profilename]`を呼び出し、コンテナまたは既存のプロファイルを渡すことがあります。

## Sandboxのデバッグとバイパス

macOSでは、プロセスがカーネルによって最初からサンドボックス化されるiOSとは異なり、**プロセスは自らサンドボックスに参加する必要があります**。これは、macOSではプロセスが自らサンドボックスに入ることを積極的に決定するまで、サンドボックスによって制限されないことを意味しますが、App Storeアプリは常にサンドボックス化されています。

プロセスは、権限`com.apple.security.app-sandbox`を持っている場合、ユーザーランドから自動的にサンドボックス化されます。このプロセスの詳細な説明については、次を確認してください：

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox拡張**

拡張はオブジェクトにさらなる権限を与えることを可能にし、次の関数のいずれかを呼び出すことで与えられます：

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

拡張は、プロセスの資格情報からアクセス可能な2番目のMACFラベルスロットに保存されます。次の**`sbtool`**がこの情報にアクセスできます。

拡張は通常、許可されたプロセスによって付与されることに注意してください。たとえば、`tccd`は、プロセスが写真にアクセスし、XPCメッセージで許可された場合、`com.apple.tcc.kTCCServicePhotos`の拡張トークンを付与します。その後、プロセスは拡張トークンを消費する必要があり、それが追加されます。\
拡張トークンは、付与された権限をエンコードする長い16進数であることに注意してください。ただし、許可されたPIDがハードコーディングされていないため、トークンにアクセスできる任意のプロセスが**複数のプロセスによって消費される可能性があります**。

拡張は権限とも非常に関連しているため、特定の権限を持つことが特定の拡張を自動的に付与する可能性があります。

### **PID権限の確認**

[**これによると**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)、**`sandbox_check`**関数（これは`__mac_syscall`です）は、特定のPID、監査トークン、またはユニークIDによってサンドボックスで**操作が許可されているかどうか**を確認できます。

[**ツールsbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)（[ここでコンパイルされたものを見つけてください](https://newosxbook.com/articles/hitsb.html)）は、PIDが特定のアクションを実行できるかどうかを確認できます：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

サンドボックスを一時停止および再開することも可能で、`libsystem_sandbox.dylib`の`sandbox_suspend`および`sandbox_unsuspend`関数を使用します。

一時停止関数を呼び出すには、呼び出し元が呼び出すことを許可されるためにいくつかの権限がチェックされます。例えば：

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

このシステムコール（#381）は、最初の引数として実行するモジュールを示す文字列を期待し、次の引数には実行する関数を示すコードを指定します。3番目の引数は実行される関数に依存します。

関数`___sandbox_ms`の呼び出しは、最初の引数に`"Sandbox"`を指定して`mac_syscall`をラップします。同様に、`___sandbox_msp`は`mac_set_proc`（#387）のラッパーです。次に、`___sandbox_ms`によってサポートされるコードの一部は次の表に示されています：

- **set_profile (#0)**: プロセスにコンパイル済みまたは名前付きプロファイルを適用します。
- **platform_policy (#1)**: プラットフォーム固有のポリシーチェックを強制します（macOSとiOSで異なります）。
- **check_sandbox (#2)**: 特定のサンドボックス操作の手動チェックを実行します。
- **note (#3)**: サンドボックスに注釈を追加します。
- **container (#4)**: サンドボックスに注釈を添付します。通常はデバッグや識別のために使用されます。
- **extension_issue (#5)**: プロセスの新しい拡張を生成します。
- **extension_consume (#6)**: 指定された拡張を消費します。
- **extension_release (#7)**: 消費された拡張に関連付けられたメモリを解放します。
- **extension_update_file (#8)**: サンドボックス内の既存のファイル拡張のパラメータを変更します。
- **extension_twiddle (#9)**: 既存のファイル拡張を調整または変更します（例：TextEdit、rtf、rtfd）。
- **suspend (#10)**: すべてのサンドボックスチェックを一時的に停止します（適切な権限が必要です）。
- **unsuspend (#11)**: 以前に一時停止されたすべてのサンドボックスチェックを再開します。
- **passthrough_access (#12)**: サンドボックスチェックをバイパスしてリソースへの直接パススルーアクセスを許可します。
- **set_container_path (#13)**: （iOSのみ）アプリグループまたは署名IDのためのコンテナパスを設定します。
- **container_map (#14)**: （iOSのみ）`containermanagerd`からコンテナパスを取得します。
- **sandbox_user_state_item_buffer_send (#15)**: （iOS 10+）サンドボックス内のユーザーモードメタデータを設定します。
- **inspect (#16)**: サンドボックス化されたプロセスに関するデバッグ情報を提供します。
- **dump (#18)**: （macOS 11）分析のためにサンドボックスの現在のプロファイルをダンプします。
- **vtrace (#19)**: 監視またはデバッグのためにサンドボックス操作をトレースします。
- **builtin_profile_deactivate (#20)**: （macOS < 11）名前付きプロファイルを無効にします（例：`pe_i_can_has_debugger`）。
- **check_bulk (#21)**: 単一の呼び出しで複数の`sandbox_check`操作を実行します。
- **reference_retain_by_audit_token (#28)**: サンドボックスチェックで使用するための監査トークンの参照を作成します。
- **reference_release (#29)**: 以前に保持された監査トークンの参照を解放します。
- **rootless_allows_task_for_pid (#30)**: `task_for_pid`が許可されているかどうかを確認します（`csr`チェックに類似）。
- **rootless_whitelist_push (#31)**: （macOS）システム整合性保護（SIP）マニフェストファイルを適用します。
- **rootless_whitelist_check (preflight) (#32)**: 実行前にSIPマニフェストファイルをチェックします。
- **rootless_protected_volume (#33)**: （macOS）ディスクまたはパーティションにSIP保護を適用します。
- **rootless_mkdir_protected (#34)**: ディレクトリ作成プロセスにSIP/DataVault保護を適用します。

## Sandbox.kext

iOSでは、カーネル拡張が`__TEXT.__const`セグメント内に**すべてのプロファイルをハードコーディング**しているため、変更されることはありません。以下はカーネル拡張からのいくつかの興味深い関数です：

- **`hook_policy_init`**: `mpo_policy_init`をフックし、`mac_policy_register`の後に呼び出されます。サンドボックスの初期化のほとんどを実行します。また、SIPも初期化します。
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active`、および`security.mac.sandbox.debug_mode`を登録するsysctlインターフェースを設定します（`PE_i_can_has_debugger`でブートされた場合）。
- **`hook_policy_syscall`**: "Sandbox"を最初の引数、操作を示すコードを2番目の引数として`mac_syscall`によって呼び出されます。スイッチを使用して、要求されたコードに応じて実行するコードを見つけます。

### MACF Hooks

**`Sandbox.kext`**は、MACFを介して100以上のフックを使用します。ほとんどのフックは、アクションを実行することを許可する単純なケースをチェックするだけであり、そうでない場合は、**`cred_sb_evalutate`**を呼び出し、**資格情報**と**操作**に対応する番号、および出力用の**バッファ**を渡します。

その良い例は、**`_mpo_file_check_mmap`**関数で、これは**`mmap`**をフックし、新しいメモリが書き込み可能かどうかをチェックし（そうでない場合は実行を許可）、次にそれがdyld共有キャッシュに使用されているかどうかをチェックし、そうであれば実行を許可し、最後に**`sb_evaluate_internal`**（またはそのラッパーの1つ）を呼び出してさらなる許可チェックを実行します。

さらに、サンドボックスが使用する数百のフックの中で、特に興味深い3つがあります：

- `mpo_proc_check_for`: 必要に応じてプロファイルを適用し、以前に適用されていない場合。
- `mpo_vnode_check_exec`: プロセスが関連するバイナリをロードするときに呼び出され、プロファイルチェックとSUID/SGID実行を禁止するチェックが行われます。
- `mpo_cred_label_update_execve`: ラベルが割り当てられるときに呼び出されます。これは最も長いもので、バイナリが完全にロードされるときに呼び出されますが、まだ実行されていません。サンドボックスオブジェクトの作成、kauth資格情報へのサンドボックス構造の添付、machポートへのアクセスの削除などのアクションを実行します。

**`_cred_sb_evalutate`**は**`sb_evaluate_internal`**のラッパーであり、この関数は渡された資格情報を取得し、次に**`eval`**関数を使用して評価を実行します。この関数は通常、すべてのプロセスにデフォルトで適用される**プラットフォームプロファイル**を評価し、その後**特定のプロセスプロファイル**を評価します。プラットフォームプロファイルは、macOSの**SIP**の主要なコンポーネントの1つです。

## Sandboxd

サンドボックスには、XPC Machサービス`com.apple.sandboxd`を公開し、カーネル拡張が通信に使用する特別なポート14（`HOST_SEATBELT_PORT`）をバインドするユーザーデーモンもあります。MIGを使用していくつかの関数を公開します。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
