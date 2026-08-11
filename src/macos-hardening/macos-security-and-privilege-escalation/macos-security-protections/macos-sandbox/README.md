# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MacOS Sandbox（当初は Seatbelt と呼ばれていた）は、Sandbox profile で指定された**許可されたアクション**に、Sandbox 内で実行される**アプリケーションの操作を制限します**。これにより、**アプリケーションが想定されたリソースにのみアクセスすること**を保証しやすくなります。

**entitlement** **`com.apple.security.app-sandbox`** を持つアプリは Sandbox 内で実行されます。**Apple のバイナリ**は通常 Sandbox 内で実行され、**App Store のすべてのアプリケーションがこの entitlement を持っています**。そのため、多くのアプリケーションが Sandbox 内で実行されます。<sup>[[4]](#references)</sup>

プロセスが実行できることとできないことを制御するため、**Sandbox にはフック**があり、**MACF**を使用して、プロセスが試行する可能性のあるほぼすべての操作（ほとんどの syscall を含む）を監視します。ただし、アプリの**entitlements**に応じて、Sandbox はプロセスに対してより寛容になる場合があります。

Sandbox の重要なコンポーネントには、次のものがあります。

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland で実行される **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Sandbox 化されたすべてのアプリケーションは、`~/Library/Containers/{CFBundleIdentifier}` に独自の container を持ちます：
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
各 bundle id フォルダ内には、Home フォルダを模した構造の **plist** と **Data directory** があり、App の次の情報を確認できます：
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
> symlink が Sandbox から「escape」して他のフォルダにアクセスできる状態でも、App にはそれらにアクセスするための**権限**が必要です。これらの権限は、`RedirectablePaths` 内の **`.plist`** にあります。

**`SandboxProfileData`** は、コンパイル済みの sandbox profile CFData を B64 にエスケープしたものです。
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
> Sandboxed applicationによって作成・変更されたすべてのものには、**quarantine attribute**が付与されます。これにより、Sandbox appが**`open`**を使用して何かを実行しようとすると、Gatekeeperがトリガーされ、sandbox spaceが妨げられます。

## Sandbox Profiles

Sandbox profilesは、その**Sandbox**で何が**許可／禁止**されるかを示す設定ファイルです。これは、[**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programming languageを使用する**Sandbox Profile Language (SBPL)**を利用します。

ここに例を示します:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> どのような action が許可または拒否されるかをさらに確認するには、この [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) を確認してください。<sup>[[5]](#references)</sup>
>
> profile のコンパイル済みバージョンでは、operation の名前が dylib と kext によって認識される array 内のエントリに置き換えられるため、コンパイル済みバージョンはより短く、読み取りにくくなります。

重要な **system services** も、`mdnsresponder` service など、それぞれ独自のカスタム **sandbox** 内で実行されます。これらのカスタム **sandbox profiles** は以下で確認できます。

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- その他の sandbox profiles は [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) で確認できます。
- iOS では、platform profile はバイナリ内の `_platform_profile_data` 内にある sandbox `.kext` の内部に存在します。

**App Store** apps は **profile** **`/System/Library/Sandbox/Profiles/application.sb`** を使用します。この profile では、**`com.apple.security.network.server`** などの entitlements によって process が network を使用できる仕組みを確認できます。

また、一部の **Apple daemon services** は、`/System/Library/Sandbox/Profiles/*.sb` または `/usr/share/sandbox/*.sb` にある異なる profiles を使用します。これらの sandboxes は、API `sandbox_init_XXX` を呼び出す main function で適用されます。<sup>[[3]](#references)</sup>

**SIP** は `/System/Library/Sandbox/rootless.conf` にある platform_profile という Sandbox profile です。

### Sandbox Profile の例

**特定の sandbox profile** で application を起動するには、次を使用できます。
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> **Windows**上で動作する**Appleが作成した** **software**には、application sandboxingなどの**追加のセキュリティ対策がない**ことに注意してください。

Bypassの例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（`~$`で始まる名前のファイルをsandbox外に書き込むことができます）。<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### プロファイル経由

sandboxがアクションをチェックするたびに実行するすべてのチェックをtraceできます。そのためには、次のプロファイルを作成します：
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
そして、そのプロファイルを使って何かを実行するだけです：
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` では、sandbox check が呼び出されるたびに実行された各チェックを確認できます（そのため、多数の重複があります）。

**`-t`** パラメータを使用して sandbox を trace することもできます: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

`libsystem_sandbox.dylib` が export する関数 `sandbox_set_trace_path` を使用すると、sandbox check の結果を書き込む trace filename を指定できます。\
`sandbox_vtrace_enable()` を呼び出して同様の処理を行い、その後 `sandbox_vtrace_report()` を呼び出して buffer から error log を取得することもできます。

### Sandbox Inspection

`libsandbox.dylib` は、プロセスの sandbox state（extensions を含む）の一覧を返す関数 sandbox_inspect_pid を export しています。ただし、この関数を使用できるのは platform binaries のみです。

### MacOS & iOS Sandbox Profiles

MacOS は system sandbox profiles を 2 か所に保存します: **/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles**。

また、third-party application が _**com.apple.security.app-sandbox**_ entitlement を持っている場合、system はそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** profile を適用します。

iOS では、default profile は **container** と呼ばれ、SBPL text representation は存在しません。memory 上では、この sandbox は sandbox の各 permission に対する Allow/Deny binary tree として表現されます。

### Custom SBPL in App Store apps

企業が、自社の apps を default profile ではなく **custom Sandbox profiles** で実行させることは可能です。そのためには entitlement **`com.apple.security.temporary-exception.sbpl`** を使用する必要があり、Apple による承認が必要です。

この entitlement の定義は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
これは、**この entitlement の後の文字列を Sandbox profile として eval します**。

### Sandbox Profile のコンパイルと逆コンパイル

**`sandbox-exec`** ツールは、`libsandbox.dylib` の `sandbox_compile_*` 関数を使用します。主な export 関数は次のとおりです。`sandbox_compile_file`（ファイルパスを受け取り、param は `-f`）、`sandbox_compile_string`（文字列を受け取り、param は `-p`）、`sandbox_compile_name`（container の名前を受け取り、param は `-n`）、`sandbox_compile_entitlements`（entitlements plist を受け取る）。

この逆解析され、[**open sourced された tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) のバージョンを使うと、コンパイル済みの Sandbox profile をファイルに書き込むよう **`sandbox-exec`** に指示できます。

さらに、process を container 内に閉じ込めるために、`sandbox_spawnattrs_set[container/profilename]` を呼び出し、container または既存の profile を渡すことがあります。

## Debug と Sandbox の Bypass

macOS では、process が kernel によって最初から sandbox 化される iOS とは異なり、**process 自身が Sandbox に opt-in する必要があります**。つまり macOS では、process が Sandbox への移行を明示的に決定するまで、その process は Sandbox による制限を受けません。ただし、App Store の apps は常に sandbox 化されています。

process に entitlement `com.apple.security.app-sandbox` がある場合、process は userland から自動的に Sandbox 化されます。この process の詳細な説明については、次を確認してください。


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions は object に追加の privileges を与えるもので、次のいずれかの function を呼び出すことで付与されます。

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions は、process credentials からアクセス可能な 2 番目の MACF label slot に保存されます。次の **`sbtool`** でこの情報にアクセスできます。

Extensions は通常、許可された process によって付与されることに注意してください。たとえば、process が photos へのアクセスを試み、XPC message で許可された場合、`tccd` は `com.apple.tcc.kTCCServicePhotos` の extension token を付与します。その後、process は extension token を consume して、自身に追加する必要があります。\
また、extension token は、付与された permissions を encode した長い hexadecimal であることに注意してください。ただし、許可された PID は hardcode されていないため、token にアクセスできる任意の process によって **複数の process が consume できます**。

Extensions は entitlements とも非常に関連しているため、特定の entitlements を持つことで、特定の Extensions が自動的に付与される場合もあります。

### **PID Privileges の確認**

[**これによると**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)、**`sandbox_check`** functions（これは `__mac_syscall`）は、特定の PID、audit token、または unique ID において、**Sandbox が operation を許可しているかどうか**を確認できます。<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)（[ここで compiled version を確認できます](https://newosxbook.com/articles/hitsb.html)）は、PID が特定の actions を実行できるかどうかを確認できます。
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` の `sandbox_suspend` および `sandbox_unsuspend` 関数を使用して、Sandbox を suspend および unsuspend することも可能です。

suspend 関数を呼び出すには、呼び出し元が呼び出しを許可されていることを認証するため、いくつかの entitlements がチェックされる点に注意してください。

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

この system call（#381）は、最初の引数として実行するモジュールを示す 1 つの文字列を受け取り、次に 2 番目の引数として実行する関数を示すコードを受け取ります。その後、3 番目の引数は実行される関数によって異なります。<sup>[[2]](#references)</sup>

`___sandbox_ms` 関数の call は、最初の引数に `"Sandbox"` を指定して `mac_syscall` をラップします。同様に、`___sandbox_msp` は `mac_set_proc`（#387）の wrapper です。`___sandbox_ms` がサポートするコードの一部は、次の表に示されています。

- **set_profile (#0)**: コンパイル済みまたは名前付きの profile を process に適用します。
- **platform_policy (#1)**: platform 固有の policy check を強制します（macOS と iOS で異なります）。
- **check_sandbox (#2)**: 特定の Sandbox operation の手動 check を実行します。
- **note (#3)**: Sandbox に annotation を追加します。
- **container (#4)**: Sandbox に annotation を付加します。通常は debugging または識別のために使用されます。
- **extension_issue (#5)**: process 用の新しい extension を生成します。
- **extension_consume (#6)**: 指定された extension を consume します。
- **extension_release (#7)**: consume された extension に紐付く memory を解放します。
- **extension_update_file (#8)**: Sandbox 内にある既存の file extension のパラメータを変更します。
- **extension_twiddle (#9)**: 既存の file extension（例: TextEdit、rtf、rtfd）を調整または変更します。
- **suspend (#10)**: すべての Sandbox check を一時的に suspend します（適切な entitlements が必要です）。
- **unsuspend (#11)**: 以前に suspend されたすべての Sandbox check を再開します。
- **passthrough_access (#12)**: resource への直接 passthrough access を許可し、Sandbox check を bypass します。
- **set_container_path (#13)**: （iOS のみ）app group または signing ID の container path を設定します。
- **container_map (#14)**: （iOS のみ）`containermanagerd` から container path を取得します。
- **sandbox_user_state_item_buffer_send (#15)**: （iOS 10 以降）Sandbox に user mode metadata を設定します。
- **inspect (#16)**: Sandbox 化された process に関する debug information を提供します。
- **dump (#18)**: （macOS 11）分析用に Sandbox の現在の profile を dump します。
- **vtrace (#19)**: monitoring または debugging のために Sandbox operation を trace します。
- **builtin_profile_deactivate (#20)**: （macOS < 11）名前付き profile（例: `pe_i_can_has_debugger`）を deactivate します。
- **check_bulk (#21)**: 1 回の call で複数の `sandbox_check` operation を実行します。
- **reference_retain_by_audit_token (#28)**: Sandbox check で使用する audit token の reference を作成します。
- **reference_release (#29)**: 以前に retain された audit token の reference を解放します。
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` が許可されているかを確認します（`csr` check に類似）。
- **rootless_whitelist_push (#31)**: （macOS）System Integrity Protection（SIP）の manifest file を適用します。
- **rootless_whitelist_check (preflight) (#32)**: 実行前に SIP manifest file を check します。
- **rootless_protected_volume (#33)**: （macOS）disk または partition に SIP protection を適用します。
- **rootless_mkdir_protected (#34)**: directory creation process に SIP/DataVault protection を適用します。

## Sandbox.kext

iOS では、変更を防ぐため、kernel extension が `__TEXT.__const` segment 内に **すべての profile を hardcode している**点に注意してください。kernel extension に含まれる興味深い関数には、次のようなものがあります。

- **`hook_policy_init`**: `mpo_policy_init` を hook し、`mac_policy_register` の後に call されます。Sandbox の初期化の大部分を実行します。また、SIP も初期化します。
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active`、および `security.mac.sandbox.debug_mode`（`PE_i_can_has_debugger` で boot された場合）を register して、sysctl interface を設定します。
- **`hook_policy_syscall`**: 第 1 引数に `"Sandbox"`、第 2 引数に operation を示す code を指定して `mac_syscall` から call されます。switch を使用して、要求された code に応じて実行する code を探します。

### MACF Hooks

**`Sandbox.kext`** は MACF 経由で 100 個を超える hook を使用します。多くの hook は、action を実行できる trivial な case を check するだけで、実行できない場合は MACF の **credentials**、実行する **operation** に対応する number、および output 用の **buffer** を指定して **`cred_sb_evalutate`** を call します。<sup>[[1]](#references)</sup>

その良い例が、`mmap` を hook する関数 **`_mpo_file_check_mmap`** です。この関数は、まず新しい memory が writable になるかを check し（writable でなければ execution を許可します）、次に dyld shared cache 用に使用されるかを check し、使用される場合は execution を許可します。最後に、**`sb_evaluate_internal`**（またはその wrapper の 1 つ）を call して、さらに allowance check を実行します。

さらに、Sandbox が使用する数百の hook の中でも、特に興味深いものが 3 つあります。

- `mpo_proc_check_for`: 必要で、以前に適用されていない場合に profile を適用します。
- `mpo_vnode_check_exec`: process が関連付けられた binary を load するときに call されます。その後、profile check と SUID/SGID execution を禁止する check が実行されます。
- `mpo_cred_label_update_execve`: label が割り当てられるときに call されます。binary が完全に load されたものの、まだ execute されていない段階で call されるため、最も長い関数です。Sandbox object の作成、kauth credentials への Sandbox struct の attach、mach port への access の削除などの action を実行します。

**`_cred_sb_evalutate`** は **`sb_evaluate_internal`** の wrapper であり、この関数は渡された credentials を取得し、通常はすべての process にデフォルトで適用される **platform profile**、続いて **specific process profile** を評価する **`eval`** 関数を使用して evaluation を実行する点に注意してください。platform profile は macOS における **SIP** の主要 component の 1 つです。

## Sandboxd

Sandbox には、XPC Mach service `com.apple.sandboxd` を公開する user daemon も存在し、kernel extension が通信に使用する special port 14（`HOST_SEATBELT_PORT`）に bind しています。MIG を使用していくつかの関数を公開します。

## References

- [1] [XNU — `security/mac_policy.h`（Sandbox kext が register する MACF hooks）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`__sandbox_ms` の背後にある entry point、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
