# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC is a framework for **communication between processes** on macOS and iOS. It provides mechanisms for making **safe, asynchronous calls between processes**. XPC supports **privilege-separated applications**, where each **component** runs with **only the permissions it needs**, thereby limiting the potential damage from a compromised process.<sup>[[1]](#references)</sup>

XPC uses a form of Inter-Process Communication (IPC), which is a set of methods for different programs running on the same system to send data back and forth.

The primary benefits of XPC include:

1. **Security**: By separating work into different processes, each process can be granted only the permissions it needs. This means that even if a process is compromised, it has limited ability to do harm.
2. **Stability**: XPC helps isolate crashes to the component where they occur. If a process crashes, it can be restarted without affecting the rest of the system.
3. **Performance**: XPC allows for easy concurrency, as different tasks can be run simultaneously in different processes.

The main **drawback** is that **separating an application into several processes** and making them communicate through XPC adds overhead. On modern systems this overhead is usually small compared with the security and stability benefits.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

The XPC components of an application are **inside the application itself**. For example, in Safari you can find them in **`/Applications/Safari.app/Contents/XPCServices`**. They have the extension **`.xpc`** (like **`com.apple.Safari.SandboxBroker.xpc`**) and are **also bundles**, with the main binary and an `Info.plist` inside them. For example: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` and `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

An **XPC component can have different entitlements and privileges** from other XPC components or the main application binary. One exception is an XPC service configured with **`JoinExistingSession`** set to `true` in its **Info.plist** file. In this case, the XPC service joins the **same security session as the application** that called it.<sup>[[4]](#references)</sup>

XPC services are **started** by **launchd** when required and can be **shut down** once their tasks are **complete** to free system resources. **Application-specific XPC components can only be used by their containing application**, thereby reducing the exposure of potential vulnerabilities.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Unlike application-specific services, system-wide XPC services are not restricted to their containing application. They may be reachable by clients from multiple users, depending on the launchd domain and the service's own authorization checks. These launchd-managed Mach services need to be **defined in plist** files located in directories such as **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, or **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

These plist files have a **`MachServices`** key containing the service name and a **`Program`** key containing the path to the binary:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

Services in **`LaunchDaemons`** commonly run as root. Therefore, if an unprivileged process can reach a vulnerable method exposed by one of these services, it may be able to escalate privileges.

## XPC Objects

- **`xpc_object_t`**

XPC request and reply payloads are commonly dictionary objects, which simplify serialization and deserialization. `libxpc.dylib` also declares the data types needed to verify that received data has the expected type. In the C API every object is an `xpc_object_t` (and its type can be checked using `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Moreover, the function `xpc_copy_description(object)` can be used to get a string representation of the object that can be useful for debugging purposes.\
These objects also have some methods to call like `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

The `xpc_object_t` objects are created by calling an `xpc_<objectType>_create` function, which internally calls `_xpc_base_create(Class, Size)`, indicating the object's class (one of `XPC_TYPE_*`) and size. An extra 40 bytes are added for metadata, so the object data starts at offset 40 bytes.\
Therefore, the `xpc_<objectType>_t` is kind of a subclass of the `xpc_object_t` which would be a subclass of `os_object_t*`.

> [!WARNING]
> Note that it should be the developer who uses `xpc_dictionary_[get/set]_<objectType>` to get or set the type and real value of a key.

- **`xpc_pipe`**

A **`xpc_pipe`** is a FIFO pipe that processes can use to communicate (the communication use Mach messages).\
It's possible to create a XPC server calling `xpc_pipe_create()` or `xpc_pipe_create_from_port()` to create it using a specific Mach port. Then, to receive messages it's possible to call `xpc_pipe_receive` and `xpc_pipe_try_receive`.

Note that the **`xpc_pipe`** object is a **`xpc_object_t`** with information in its struct about the two Mach ports used and the name (if any). The name, for example, the daemon `secinitd` in its plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configures the pipe called `com.apple.secinitd`.

An example of an **`xpc_pipe`** is the **bootstrap pipe** created by **`launchd`**, which makes it possible to share Mach ports.

- **`NSXPC*`**

These are high-level Objective-C objects that abstract XPC connections.\
Moreover, it's easier to debug these objects with DTrace than the previous ones.

- **`GCD Queues`**

XPC uses GCD to pass messages, moreover it generates certain dispatch queues like `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

These are **bundles with `.xpc`** extension located inside the **`XPCServices`** folder of other projects and in the `Info.plist` they have the `CFBundlePackageType` set to **`XPC!`**.\
This file has other configuration keys, such as `ServiceType`, which can be Application, User, or System; `_SandboxProfile`, which can define a sandbox; and `_AllowedClients`, which may indicate the entitlements or identity required to contact the service. These and other options configure the service when it is launched.<sup>[[2]](#references)</sup>

### Starting a Service

The app attempts to **connect** to an XPC service using `xpc_connection_create_mach_service`; launchd then locates the daemon and starts **`xpcproxy`**. **`xpcproxy`** enforces the configured restrictions and spawns the service with the provided file descriptors and Mach ports.<sup>[[3]](#references)</sup>

In order to improve the speed of the search of the XPC service, a cache is used.

It's possible to trace the actions of `xpcproxy` using:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

The XPC library uses `kdebug` to log actions by calling `xpc_ktrace_pid0` and `xpc_ktrace_pid1`. The codes it uses are undocumented, so they need to be added to `/usr/share/misc/trace.codes`. They have the prefix `0x29`; for example, `0x29000004` is `XPC_serializer_pack`.\
The utility `xpcproxy` uses the prefix `0x22`, for example: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Applications can **subscribe** to different event **messages**, enabling them to be **initiated on-demand** when such events happen. The **setup** for these services is done in l**aunchd plist files**, located in the **same directories as the previous ones** and containing an extra **`LaunchEvent`** key.

### XPC Connecting Process Check

When a process tries to call a method through an XPC connection, the **XPC service should check whether that process is allowed to connect**. Here are common verification methods and their pitfalls:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple also allows apps to **configure authorization rights and how callers obtain them**, so a process with the required rights is **allowed to call a method** exposed by the XPC service:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

To sniff XPC messages, you can use **xpcspy**, which uses **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Another possible tool is **XPoCe2**.<sup>[[6]](#references)</sup>

## XPC Communication C Code Example

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## XPC Communication Objective-C Code Example

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Client Inside a Dylib

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

The functionality provided by `RemoteXPC.framework` (from `libxpc`) allows XPC communication between different hosts.\
Services that support remote XPC have the `UsesRemoteXPC` key in their plist, as is the case for `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Although the service is registered with `launchd`, `UserEventAgent` and its `com.apple.remoted.plugin` and `com.apple.remoteservicediscovery.events.plugin` plugins provide the functionality.

Moreover, `RemoteServiceDiscovery.framework` obtains information from `com.apple.remoted.plugin`, exposing functions such as `get_device`, `get_unique_device`, and `connect`.

Once `connect` has returned the service's socket file descriptor, it is possible to use the `remote_xpc_connection_*` class.

It is possible to get information about remote services with the `/usr/libexec/remotectl` CLI using commands such as:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Communication between bridgeOS and the host occurs through a dedicated IPv6 interface. `MultiverseSupport.framework` establishes sockets whose file descriptors are used for communication.\
It is possible to find these communications using `netstat`, `nettop`, or the open-source alternative `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
