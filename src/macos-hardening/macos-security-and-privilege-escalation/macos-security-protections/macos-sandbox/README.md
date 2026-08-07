# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

macOS Sandbox（当初はSeatbeltと呼ばれていました）は、Sandbox内で実行される**アプリケーションを、アプリが使用しているSandbox profileで指定された許可済みの操作に制限します**。これにより、**アプリケーションが想定されたリソースにのみアクセスすること**を保証できます。

**`com.apple.security.app-sandbox`** **entitlement**を持つアプリは、Sandbox内で実行されます。**Apple binaries**は通常Sandbox内で実行され、**App Storeのすべてのアプリケーションがこのentitlementを持っています**。そのため、多くのアプリケーションがSandbox内で実行されます。<sup>[[4]](#references)</sup>

プロセスが実行できる操作と実行できない操作を制御するため、**Sandboxにはhooksが存在し**、**MACF**を使用して、プロセスが実行しようとするほぼすべての操作（ほとんどのsyscallsを含む）を監視します。ただし、アプリの**entitlements**に**応じて**、Sandboxがプロセスに対してより寛容になる場合があります。

Sandboxの重要なコンポーネントは次のとおりです。

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userlandで実行される**daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Sandbox内で実行されるすべてのアプリケーションは、`~/Library/Containers/{CFBundleIdentifier}` に独自のcontainerを持ちます：
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
各 bundle id フォルダ内には、**plist** と、Home フォルダを模倣した構造の App の **Data directory** があります。
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
> symlink が Sandbox から「escape」して他のフォルダにアクセスするために存在していても、App にはそれらにアクセスする**permissions**が必要です。これらの permissions は `RedirectablePaths` 内の **`.plist`** にあります。

**`SandboxProfileData`** は、B64 にエスケープされたコンパイル済み sandbox profile の CFData です。
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
> Sandboxアプリケーションによって作成または変更されたすべてのものには、**quarantine attribut**eが付与されます。これにより、Sandboxアプリが**`open`**を使用して何かを実行しようとすると、Gatekeeperがトリガーされ、Sandbox spaceが阻止されます。

## Sandbox Profiles

Sandbox profilesは、その**Sandbox**で何が**許可／禁止**されるかを示す設定ファイルです。これは[**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>)プログラミング言語を使用する**Sandbox Profile Language (SBPL)**を用います。

以下に例を示します：
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
> どのようなアクションが許可または拒否される可能性があるかをさらに確認するには、こちらの[**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)を参照してください。<sup>[[5]](#references)</sup>
>
> コンパイル済みプロファイルでは、操作の名前が dylib と kext によって認識される配列内のエントリに置き換えられるため、コンパイル済みバージョンは短くなり、読み取りも難しくなることに注意してください。

`mdnsresponder`サービスなど、重要な**system services**も独自のカスタム**sandbox**内で実行されます。これらのカスタム**sandbox profiles**は以下で確認できます。

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- その他のsandbox profilesは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。
- iOSでは、platform profileはバイナリ内の`_platform_profile_data`にあるsandbox `.kext`内に存在します。

**App Store**のアプリは**profile** **`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このprofileでは、**`com.apple.security.network.server`**などのentitlementsによってプロセスがネットワークを使用できる仕組みを確認できます。

また、一部の**Apple daemon services**は、`/System/Library/Sandbox/Profiles/*.sb`または`/usr/share/sandbox/*.sb`にある異なるprofilesを使用します。これらのsandboxesは、API `sandbox_init_XXX`を呼び出すメイン関数で適用されます。<sup>[[3]](#references)</sup>

**SIP**は、`/System/Library/Sandbox/rootless.conf`にあるplatform_profileというSandbox profileです。

### Sandbox Profile Examples

**specific sandbox profile**を指定してアプリケーションを起動するには、次のコマンドを使用できます。
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
> **Windows** 上で動作する **Apple 作成**の **software** には、application sandboxing などの追加のセキュリティ対策がないことに注意してください。

Bypasses の例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（名前が `~$` で始まるファイルを sandbox 外に書き込むことができます）。<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### profile を使用

sandbox がアクションをチェックするたびに実行するすべてのチェックを trace できます。そのためには、次の profile を作成します。
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
そして、そのプロファイルを使用して何かを実行するだけです：
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` では、実行されるたびに行われた各 sandbox check を確認できます（そのため、多数の重複が含まれます）。

**`-t`** パラメータを使用して sandbox を trace することもできます: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API経由

`libsystem_sandbox.dylib` が export している関数 `sandbox_set_trace_path` を使用すると、sandbox check の内容を書き込む trace filename を指定できます。\
`sandbox_vtrace_enable()` を呼び出して同様の処理を行い、その後、バッファから `sandbox_vtrace_report()` を呼び出してログ error を取得することもできます。

### Sandbox Inspection

`libsandbox.dylib` は、プロセスの sandbox state（extensions を含む）の一覧を返す関数 sandbox_inspect_pid を export しています。ただし、この関数を使用できるのは platform binaries のみです。

### MacOS & iOS Sandbox Profiles

MacOS は system sandbox profiles を次の2か所に保存します: **/usr/share/sandbox/** および **/System/Library/Sandbox/Profiles**。

また、third-party application が _**com.apple.security.app-sandbox**_ entitlement を持つ場合、system はそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** profile を適用します。

iOS では、default profile は **container** という名前で、SBPL の text representation はありません。メモリ上では、この sandbox は sandbox の各 permission に対応する Allow/Deny binary tree として表現されます。

### App Store apps の Custom SBPL

企業が、自社の apps を default のものではなく **custom Sandbox profiles** で実行させることは可能です。そのためには、Apple による承認が必要な entitlement **`com.apple.security.temporary-exception.sbpl`** を使用する必要があります。

この entitlement の定義は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
この entitlement の後に続く文字列を **Sandbox profile** として `eval` します。

### Sandbox Profile のコンパイルと逆コンパイル

**`sandbox-exec`** tool は、`libsandbox.dylib` の `sandbox_compile_*` functions を使用します。export されている主な functions は次のとおりです: `sandbox_compile_file`（file path を受け取り、param は `-f`）、`sandbox_compile_string`（string を受け取り、param は `-p`）、`sandbox_compile_name`（container の name を受け取り、param は `-n`）、`sandbox_compile_entitlements`（entitlements plist を受け取る）。

この reverse された [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) を使用すると、**`sandbox-exec`** にコンパイル済みの Sandbox profile を file に書き込ませることができます。

さらに、process を container 内に confine するために、`sandbox_spawnattrs_set[container/profilename]` を呼び出し、container または既存の profile を渡す場合があります。

## Debug と Sandbox の Bypass

macOS では、process が kernel によって最初から sandbox 化されている iOS とは異なり、**process 自身が sandbox への opt-in を行う必要があります**。つまり macOS では、process が積極的に sandbox へ入ることを決定するまで、Sandbox による制限を受けません。ただし、App Store apps は常に sandbox 化されています。

次の entitlement を持つ process は、起動時に userland から自動的に Sandbox 化されます: `com.apple.security.app-sandbox`。この process の詳細な説明については、次を確認してください:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions を使用すると、object にさらなる privileges を付与できます。これは、次のいずれかの functions を呼び出すことで行われます:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions は、process credentials からアクセス可能な 2 番目の MACF label slot に保存されます。次の **`sbtool`** でこの情報にアクセスできます。

Extensions は通常、許可された process によって付与されることに注意してください。たとえば、process が photos へのアクセスを試み、XPC message で許可された場合、`tccd` は `com.apple.tcc.kTCCServicePhotos` の extension token を付与します。その後、process は extension token を consume する必要があり、これによって token が process に追加されます。\
また、extension tokens は、付与された permissions を encode した長い hexadecimal 文字列であることに注意してください。しかし、許可された PID は hardcode されていません。つまり、token にアクセスできる任意の process によって、**複数の process が consume できる**可能性があります。

Extensions は entitlements とも非常に密接に関連しているため、特定の entitlements を持つことで、特定の extensions が自動的に付与される場合もあります。

### **PID Privileges の確認**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) によると、**`sandbox_check`** functions（これは `__mac_syscall` です）は、特定の PID、audit token、または unique ID において、operation が Sandbox によって許可されているかどうかを確認できます。<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)（[ここで compiled version](https://newosxbook.com/articles/hitsb.html) を入手できます）を使用すると、PID が特定の actions を実行できるかどうかを確認できます:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` の `sandbox_suspend` および `sandbox_unsuspend` functions を使用して、sandbox を suspend および unsuspend することも可能です。

suspend function を呼び出すには、caller が呼び出しを許可されているか確認するため、いくつかの entitlements がチェックされる点に注意してください。

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

この system call (#381) は、最初の引数として実行する module を示す 1 つの string を受け取り、次に 2 番目の引数として実行する function を示す code を受け取ります。3 番目の引数は、実行される function に依存します。<sup>[[2]](#references)</sup>

`___sandbox_ms` function の call は、最初の引数に `"Sandbox"` を指定して `mac_syscall` を wrap します。これは、`___sandbox_msp` が `mac_set_proc` (#387) の wrapper であるのと同様です。`___sandbox_ms` がサポートする code の一部は、次の table に示されています。

- **set_profile (#0)**: コンパイル済みまたは名前付きの profile を process に適用します。
- **platform_policy (#1)**: platform 固有の policy check を強制します（macOS と iOS で異なります）。
- **check_sandbox (#2)**: 特定の sandbox operation の手動 check を実行します。
- **note (#3)**: Sandbox に annotation を追加します。
- **container (#4)**: sandbox に annotation を attach します。通常は debugging または identification に使用されます。
- **extension_issue (#5)**: process 用の新しい extension を生成します。
- **extension_consume (#6)**: 指定された extension を consume します。
- **extension_release (#7)**: consume された extension に紐付く memory を release します。
- **extension_update_file (#8)**: sandbox 内に存在する file extension の parameters を変更します。
- **extension_twiddle (#9)**: 既存の file extension（例: TextEdit、rtf、rtfd）を調整または変更します。
- **suspend (#10)**: すべての sandbox check を一時的に suspend します（適切な entitlements が必要です）。
- **unsuspend (#11)**: 以前 suspend されたすべての sandbox check を再開します。
- **passthrough_access (#12)**: sandbox check を bypass して、resource への direct passthrough access を許可します。
- **set_container_path (#13)**: （iOS のみ）app group または signing ID の container path を設定します。
- **container_map (#14)**: （iOS のみ）`containermanagerd` から container path を取得します。
- **sandbox_user_state_item_buffer_send (#15)**: （iOS 10 以降）sandbox に user mode metadata を設定します。
- **inspect (#16)**: sandbox 化された process に関する debug information を提供します。
- **dump (#18)**: （macOS 11）分析用に sandbox の現在の profile を dump します。
- **vtrace (#19)**: monitoring または debugging のために sandbox operation を trace します。
- **builtin_profile_deactivate (#20)**: （macOS < 11）名前付き profile（例: `pe_i_can_has_debugger`）を deactivate します。
- **check_bulk (#21)**: 1 回の call で複数の `sandbox_check` operation を実行します。
- **reference_retain_by_audit_token (#28)**: sandbox check で使用する audit token の reference を作成します。
- **reference_release (#29)**: retain された audit token reference を release します。
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` が許可されているか確認します（`csr` check と類似）。
- **rootless_whitelist_push (#31)**: （macOS）System Integrity Protection (SIP) manifest file を適用します。
- **rootless_whitelist_check (preflight) (#32)**: 実行前に SIP manifest file を check します。
- **rootless_protected_volume (#33)**: （macOS）disk または partition に SIP protection を適用します。
- **rootless_mkdir_protected (#34)**: directory 作成 process に SIP/DataVault protection を適用します。

## Sandbox.kext

iOS では、profile が変更されるのを防ぐため、kernel extension が **すべての profile を `__TEXT.__const` segment 内に hardcode している**点に注意してください。kernel extension に存在する興味深い function の一部を以下に示します。

- **`hook_policy_init`**: `mpo_policy_init` を hook し、`mac_policy_register` の後に call されます。Sandbox の初期化の大部分を実行します。また、SIP も初期化します。
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active`、`security.mac.sandbox.debug_mode`（`PE_i_can_has_debugger` で boot された場合）を register して、sysctl interface を setup します。
- **`hook_policy_syscall`**: 最初の引数に "Sandbox"、2 番目の引数に operation を示す code を指定して `mac_syscall` から call されます。switch を使用して、要求された code に応じて実行する code を特定します。

### MACF Hooks

**`Sandbox.kext`** は MACF 経由で 100 個を超える hook を使用します。多くの hook は、action を許可できる trivial な case を check するだけで、許可できない場合は MACF の **credentials**、実行する **operation** に対応する number、出力用の **buffer** を使用して **`cred_sb_evalutate`** を call します。<sup>[[1]](#references)</sup>

その好例が、`mmap` を hook する **`_mpo_file_check_mmap`** function です。この function はまず、新しい memory が writable になるかどうかを check し（writable でなければ execution を許可します）、次に dyld shared cache に使用されるかどうかを check し、該当する場合は execution を許可します。最後に、**`sb_evaluate_internal`**（またはその wrapper の 1 つ）を call して、さらに allowance check を実行します。

さらに、Sandbox が使用する 100 個以上の hook の中でも、特に興味深いものが 3 つあります。

- `mpo_proc_check_for`: 必要で、まだ適用されていない場合に profile を適用します。
- `mpo_vnode_check_exec`: process が関連する binary を load するときに call されます。その後 profile check が実行され、SUID/SGID execution を禁止する check も実行されます。
- `mpo_cred_label_update_execve`: label が割り当てられるときに call されます。binary が完全に load されたものの、まだ execute されていない段階で call されるため、最も長い function です。sandbox object の作成、sandbox struct の kauth credentials への attach、mach ports への access の削除などの action を実行します。

**`_cred_sb_evalutate`** は **`sb_evaluate_internal`** の wrapper であり、この function は渡された credentials を取得してから、通常はすべての process にデフォルトで適用される **platform profile**、続いて **specific process profile** を評価する **`eval`** function を使用して evaluation を実行する点に注意してください。platform profile は macOS における **SIP** の主要 component の 1 つです。

## Sandboxd

Sandbox には user daemon も存在します。この daemon は XPC Mach service `com.apple.sandboxd` を expose し、kernel extension が通信に使用する special port 14（`HOST_SEATBELT_PORT`）に bind します。また、MIG を使用していくつかの function を expose します。

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
