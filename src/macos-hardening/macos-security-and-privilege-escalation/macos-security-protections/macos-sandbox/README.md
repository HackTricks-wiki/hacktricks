# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

MacOS Sandbox（当初は Seatbelt と呼ばれていた）は、Sandbox 内で実行される**アプリケーションを、そのアプリが使用している Sandbox profile で指定された****許可された操作に制限**します。これにより、**アプリケーションが予期されたリソースにのみアクセスすること**を保証できます。

**entitlement** **`com.apple.security.app-sandbox`** を持つアプリは、Sandbox 内で実行されます。**Apple バイナリ**は通常 Sandbox 内で実行され、**App Store のすべてのアプリケーションにはその entitlement が付与されています**。そのため、多くのアプリケーションが Sandbox 内で実行されます。<sup>[[4]](#references)</sup>

プロセスが実行できること、または実行できないことを制御するため、**Sandbox にはフックがあります**。これは **MACF** を使用し、プロセスが試行する可能性のあるほぼすべての操作（ほとんどの syscall を含む）を対象とします。ただし、アプリの **entitlements** に**応じて**、Sandbox はプロセスに対してより寛容になる場合があります。

Sandbox の重要なコンポーネントには、以下があります。

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland で実行される **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Sandbox 化されたすべてのアプリケーションは、`~/Library/Containers/{CFBundleIdentifier}` に独自のコンテナを持ちます：
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
各 bundle id フォルダー内には、**plist** と、ホームフォルダーを模した構造の App の **Data directory** があります:
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
> Sandbox から「脱出」して他のフォルダにアクセスするための symlink が存在していても、App がそれらにアクセスする**権限を持っている**必要があります。これらの権限は `RedirectablePaths` 内の **`.plist`** に記述されています。

**`SandboxProfileData`** は、B64 にエスケープされたコンパイル済みの sandbox profile CFData です。
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
> Sandboxアプリケーションによって作成または変更されたすべてのものには、**quarantine attribute**が付与されます。Sandboxアプリケーションが**`open`**を使用して何かを実行しようとすると、Gatekeeperがトリガーされ、Sandbox escapeを防止できる場合があります。

## Sandboxプロファイル

Sandboxプロファイルは、その**Sandbox**で何が**許可／禁止**されるかを示す設定ファイルです。これは、[**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>)プログラミング言語を使用する **Sandbox Profile Language (SBPL)** を使用します。

ここに例を示します：
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
> **許可または拒否される可能性があるその他のアクションを確認するには、この[**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)を確認してください。**<sup>[[5]](#references)</sup>
>
> コンパイル済みの profile では、操作の名前が dylib と kext によって認識されている配列内のエントリに置き換えられるため、コンパイル済みのバージョンは短くなり、読み取りがより困難になることに注意してください。

`mdnsresponder` service など、重要な **system services** も独自のカスタム **sandbox** 内で実行されます。これらのカスタム **sandbox profiles** は以下で確認できます。

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- その他の sandbox profiles は [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) で確認できます。
- iOS では、platform profile はバイナリ内の `_platform_profile_data` にある sandbox `.kext` 内に存在します。

**App Store** apps は **profile** **`/System/Library/Sandbox/Profiles/application.sb`** を使用します。この profile で、**`com.apple.security.network.server`** などの entitlements によって process が network を使用できる仕組みを確認できます。

さらに、一部の **Apple daemon services** は、`/System/Library/Sandbox/Profiles/*.sb` または `/usr/share/sandbox/*.sb` にある異なる profiles を使用します。これらの sandboxes は、API `sandbox_init_XXX` を呼び出す main function で適用されます。<sup>[[3]](#references)</sup>

**SIP** は、`/System/Library/Sandbox/rootless.conf` 内の platform_profile という名前の Sandbox profile です。

### Sandbox Profile Examples

**specific sandbox profile** を指定して application を起動するには、次のコマンドを使用できます。
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
> **Windows**上で実行される**Appleが作成した** **software**には、application sandboxingなどの**追加のセキュリティ対策がない**ことに注意してください。

Bypassesの例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（sandboxの外部に、名前が`~$`で始まるファイルを書き込むことができます）。<sup>[[7]](#references)</sup>

### Sandboxのトレース

#### プロファイル経由

sandboxがアクションをチェックするたびに実行するすべてのチェックをトレースできます。そのためには、次のプロファイルを作成します：
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
そして、そのプロファイルを使って何かを実行するだけです：
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` では、実行されるたびに実行された各 sandbox check を確認できます（そのため、多数の重複があります）。

**`-t`** パラメータを使用して sandbox を trace することもできます: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API 経由

`libsystem_sandbox.dylib` が export する `sandbox_set_trace_path` 関数を使用すると、sandbox checks の内容を書き込む trace filename を指定できます。\
` sandbox_vtrace_enable()` を呼び出して同様の処理を行い、その後 `sandbox_vtrace_report()` を呼び出して buffer から error logs を取得することもできます。

### Sandbox の Inspection

`libsandbox.dylib` は、プロセスの sandbox state（extensions を含む）のリストを返す `sandbox_inspect_pid` 関数を export します。ただし、この関数を使用できるのは platform binaries のみです。

### MacOS および iOS の Sandbox Profiles

MacOS は system sandbox profiles を **/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles** の2か所に保存します。

また、third-party application が _**com.apple.security.app-sandbox**_ entitlement を持つ場合、system はそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** profile を適用します。

iOS では、default profile は **container** と呼ばれ、SBPL text representation はありません。memory 上では、この sandbox は sandbox の各 permission に対する Allow/Deny binary tree として表現されます。

### App Store apps の Custom SBPL

企業が、自分たちの apps を default profile ではなく **custom Sandbox profiles** で実行させることは可能です。そのためには、Apple による authorization が必要な **`com.apple.security.temporary-exception.sbpl`** entitlement を使用する必要があります。

この entitlement の definition は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
この entitlement の後の **文字列を Sandbox profile として eval** します。

### Sandbox Profile のコンパイルと逆コンパイル

**`sandbox-exec`** ツールは、`libsandbox.dylib` の `sandbox_compile_*` 関数を使用します。主なエクスポート関数は次のとおりです。`sandbox_compile_file`（ファイルパスを受け取り、パラメータは `-f`）、`sandbox_compile_string`（文字列を受け取り、パラメータは `-p`）、`sandbox_compile_name`（container の名前を受け取り、パラメータは `-n`）、`sandbox_compile_entitlements`（entitlements plist を受け取る）。

このリバースエンジニアリングされた [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) を使うと、**`sandbox-exec`** にコンパイル済みの Sandbox profile をファイルへ書き込ませることができます。

さらに、プロセスを container 内に閉じ込めるために、`sandbox_spawnattrs_set[container/profilename]` を呼び出して container または既存の profile を渡すことがあります。

## Debug & Bypass Sandbox

macOS では、プロセスが kernel によって最初から sandbox 化されている iOS とは異なり、**プロセス自身が Sandbox への opt-in を行う必要があります**。つまり macOS では、プロセスが自ら Sandbox に入ることを明示的に選択するまで、Sandbox による制限を受けません。ただし、App Store のアプリは常に sandbox 化されています。

`com.apple.security.app-sandbox` entitlement を持つプロセスは、起動時に userland から自動的に Sandbox 化されます。このプロセスの詳細な説明については、次を確認してください。


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions を使うと、object に追加の privileges を与えることができます。これらは次のいずれかの関数を呼び出すことで付与されます。

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions は、process credentials からアクセス可能な 2 番目の MACF label slot に保存されます。次の **`sbtool`** でこの情報にアクセスできます。

Extensions は通常、許可されたプロセスによって付与されます。たとえば、プロセスが photos へのアクセスを試み、XPC message で許可された場合、`tccd` は `com.apple.tcc.kTCCServicePhotos` の extension token を付与します。その後、プロセスは extension token を consume して、自身に追加する必要があります。\
Extension token は、付与された permissions をエンコードした長い hexadecimal 文字列です。ただし、許可された PID はハードコードされていないため、token にアクセスできる任意のプロセスが、**複数のプロセスによって consume される**可能性があります。

Extensions は entitlements とも密接に関係しています。そのため、特定の entitlements を持っていると、特定の extensions が自動的に付与される場合があります。

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) によると、**`sandbox_check`** functions（`__mac_syscall`）は、特定の PID、audit token、または unique ID において、**ある operation が Sandbox によって許可されているかどうか**を確認できます。<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)（[compiled here](https://newosxbook.com/articles/hitsb.html) にあります）を使うと、PID が特定の actions を実行できるかどうかを確認できます。
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` の `sandbox_suspend` および `sandbox_unsuspend` 関数を使用して、sandbox を suspend および unsuspend することも可能です。

suspend 関数を呼び出すには、呼び出し元が呼び出しを許可されているか確認するため、いくつかの entitlements がチェックされることに注意してください。

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

この system call（#381）は、最初の引数として実行する module を示す string を受け取り、次に実行する function を示す code を第 2 引数として受け取ります。その後、第 3 引数は実行された function に依存します。<sup>[[2]](#references)</sup>

`___sandbox_ms` 関数の call は、第 1 引数に `"Sandbox"` を指定して `mac_syscall` をラップします。これは、`___sandbox_msp` が `mac_set_proc`（#387）の wrapper であるのと同様です。`___sandbox_ms` がサポートする code の一部は、次の表に示されています。

- **set_profile (#0)**: コンパイル済みまたは名前付きの profile を process に適用します。
- **platform_policy (#1)**: platform 固有の policy チェックを強制します（macOS と iOS で異なります）。
- **check_sandbox (#2)**: 特定の sandbox operation の手動チェックを実行します。
- **note (#3)**: Sandbox に annotation を追加します。
- **container (#4)**: sandbox に annotation を付加します。通常は debugging または識別に使用されます。
- **extension_issue (#5)**: process 用の新しい extension を生成します。
- **extension_consume (#6)**: 指定された extension を consume します。
- **extension_release (#7)**: consume された extension に関連付けられた memory を解放します。
- **extension_update_file (#8)**: sandbox 内にある既存の file extension のパラメータを変更します。
- **extension_twiddle (#9)**: 既存の file extension（例: TextEdit、rtf、rtfd）を調整または変更します。
- **suspend (#10)**: すべての sandbox チェックを一時的に suspend します（適切な entitlements が必要です）。
- **unsuspend (#11)**: 以前 suspend されたすべての sandbox チェックを再開します。
- **passthrough_access (#12)**: sandbox チェックを bypass して、resource への直接の passthrough access を許可します。
- **set_container_path (#13)**: （iOS のみ）app group または signing ID 用の container path を設定します。
- **container_map (#14)**: （iOS のみ）`containermanagerd` から container path を取得します。
- **sandbox_user_state_item_buffer_send (#15)**: （iOS 10 以降）sandbox に user mode metadata を設定します。
- **inspect (#16)**: sandbox 化された process に関する debug 情報を提供します。
- **dump (#18)**: （macOS 11）分析用に sandbox の現在の profile を dump します。
- **vtrace (#19)**: monitoring または debugging のために sandbox operation を trace します。
- **builtin_profile_deactivate (#20)**: （macOS 11 未満）名前付き profile（例: `pe_i_can_has_debugger`）を deactivate します。
- **check_bulk (#21)**: 1 回の call で複数の `sandbox_check` operation を実行します。
- **reference_retain_by_audit_token (#28)**: sandbox チェックで使用する audit token の reference を作成します。
- **reference_release (#29)**: 以前 retain された audit token の reference を release します。
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` が許可されているか確認します（`csr` チェックと同様です）。
- **rootless_whitelist_push (#31)**: （macOS）System Integrity Protection（SIP）の manifest file を適用します。
- **rootless_whitelist_check (preflight) (#32)**: 実行前に SIP manifest file をチェックします。
- **rootless_protected_volume (#33)**: （macOS）disk または partition に SIP protections を適用します。
- **rootless_mkdir_protected (#34)**: directory creation process に SIP/DataVault protection を適用します。

## Sandbox.kext

iOS では、kernel extension に **すべての profile が `__TEXT.__const` segment 内に hardcoded されている**ことに注意してください。これは profile が変更されるのを防ぐためです。kernel extension にある興味深い function の一部を以下に示します。

- **`hook_policy_init`**: `mpo_policy_init` を hook し、`mac_policy_register` の後に call されます。Sandbox の初期化の大部分を実行します。また、SIP も初期化します。
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active`、および `security.mac.sandbox.debug_mode`（`PE_i_can_has_debugger` で boot された場合）を登録して sysctl interface を設定します。
- **`hook_policy_syscall`**: 第 1 引数に `"Sandbox"`、第 2 引数に operation を示す code を指定した `mac_syscall` によって call されます。switch を使用して、要求された code に対応する code を検索し実行します。

### MACF Hooks

**`Sandbox.kext`** は MACF 経由で 100 個を超える hook を使用します。ほとんどの hook は、action を実行可能にするいくつかの trivial なケースをチェックするだけです。それ以外の場合は、MACF の **credentials**、実行する **operation** に対応する number、および output 用の **buffer** を指定して **`cred_sb_evalutate`** を call します。<sup>[[1]](#references)</sup>

その良い例が、`mmap` を hook する function **`_mpo_file_check_mmap`** です。この function は、新しい memory が writable になるかどうかを最初にチェックし（writable でなければ execution を許可します）、次に dyld shared cache に使用されるかを確認し、該当する場合は execution を許可します。最後に、**`sb_evaluate_internal`**（またはその wrapper の 1 つ）を call して、さらなる allowance チェックを実行します。

さらに、Sandbox が使用する 100 個以上の hook のうち、特に興味深いものが 3 つあります。

- `mpo_proc_check_for`: 必要であり、まだ適用されていない場合に profile を適用します。
- `mpo_vnode_check_exec`: process が関連する binary を load するときに call されます。その後 profile チェックが実行され、SUID/SGID execution を禁止するチェックも行われます。
- `mpo_cred_label_update_execve`: label が割り当てられるときに call されます。binary が完全に load されたものの、まだ execution されていない段階で call されるため、最も長い function です。sandbox object の作成、kauth credentials への sandbox struct の attach、mach ports への access の削除などを実行します。

**`_cred_sb_evalutate`** は **`sb_evaluate_internal`** の wrapper であり、この function は渡された credentials を取得し、**`eval`** function を使用して evaluation を実行することに注意してください。`eval` は通常、すべての process にデフォルトで適用される **platform profile**、続いて **specific process profile** を評価します。macOS において platform profile は **SIP** の主要な components の 1 つであることにも注意してください。

## Sandboxd

Sandbox には、user daemon も存在します。この daemon は XPC Mach service `com.apple.sandboxd` を expose し、kernel extension が通信に使用する special port 14（`HOST_SEATBELT_PORT`）に bind します。MIG を使用していくつかの function を expose します。

## References

- [1] [XNU — `security/mac_policy.h`（Sandbox kext が登録する MACF hooks）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`__sandbox_ms` の背後にある entry point、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` の man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
