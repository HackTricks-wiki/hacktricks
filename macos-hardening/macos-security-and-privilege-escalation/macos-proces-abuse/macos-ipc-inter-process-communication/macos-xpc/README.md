# macOS XPC

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

## Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

XPC uses a form of Inter-Process Communication (IPC), which is a set of methods for different programs running on the same system to send data back and forth.

The primary benefits of XPC include:

1. **Security**: By separating work into different processes, each process can be granted only the permissions it needs. This means that even if a process is compromised, it has limited ability to do harm.
2. **Stability**: XPC helps isolate crashes to the component where they occur. If a process crashes, it can be restarted without affecting the rest of the system.
3. **Performance**: XPC allows for easy concurrency, as different tasks can be run simultaneously in different processes.

The only **drawback** is that **separating an application in several processes** making them communicate via XPC is **less efficient**. But in todays systems this isn't almost noticeable and the benefits are better.

## Application Specific XPC services

The XPC components of an application are **inside the application itself.** For example, in Safari you can find them in **`/Applications/Safari.app/Contents/XPCServices`**. They have extension **`.xpc`** (like **`com.apple.Safari.SandboxBroker.xpc`**) and are **also bundles** with the main binary inside of it: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` and an `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

As you might be thinking a **XPC component will have different entitlements and privileges** than the other XPC components or the main app binary. EXCEPT if a XPC service is configured with [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) set to “True” in its **Info.plist** file. In this case, the XPC service will run in the **same security session as the application** that called it.

XPC services are **started** by **launchd** when required and **shut down** once all tasks are **complete** to free system resources. **Application-specific XPC components can only be utilized by the application**, thereby reducing the risk associated with potential vulnerabilities.

## System Wide XPC services

System-wide XPC services are accessible to all users. These services, either launchd or Mach-type, need to be **defined in plist** files located in specified directories such as **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, or **`/Library/LaunchAgents`**.

These plists files will have a key called **`MachServices`** with the name of the service, and a key called **`Program`** with the path to the binary:

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

The ones in **`LaunchDameons`** are run by root. So if an unprivileged process can talk with one of these it could be able to escalate privileges.

## XPC Objects

* **`xpc_object_t`**

Every XPC message is a dictionary object that simplifies the serialization and deserialization. Moreover, `libxpc.dylib` declares most of the data types so it's possible to make that the received data is of the expected type. In the C API every object is a `xpc_object_t` (and it's type can be checked using `xpc_get_type(object)`).\
Moreover, the function `xpc_copy_description(object)` can be used to get a string representation of the object that can be useful for debugging purposes.\
These objects also have some methods to call like `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

The `xpc_object_t` are created calling `xpc_<objetType>_create` function, which internally calls `_xpc_base_create(Class, Size)` where it's indicated the type of the class of the object (one of `XPC_TYPE_*`) and the size of it (some extra 40B will be added to the size for metadata). Which means that the data of the object will start at the offset 40B.\
Therefore, the `xpc_<objectType>_t` is kind of a subclass of the `xpc_object_t` which would be a subclass of `os_object_t*`.

{% hint style="warning" %}
Note that it should be the developer who uses `xpc_dictionary_[get/set]_<objectType>` to get or set the type and real value of a key.
{% endhint %}

* **`xpc_pipe`**

A **`xpc_pipe`** is a FIFO pipe that processes can use to communicate (the communication use Mach messages).\
It's possible to create a XPC server calling `xpc_pipe_create()` or `xpc_pipe_create_from_port()` to create it using a specific Mach port. Then, to receive messages it's possible to call `xpc_pipe_receive` and `xpc_pipe_try_receive`.

Note that the **`xpc_pipe`** object is a **`xpc_object_t`** with information in its struct about the two Mach ports used and the name (if any). The name, for example, the daemon `secinitd` in its plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configures the pipe called `com.apple.secinitd`.

An example of a **`xpc_pipe`** is the **bootstrap pip**e created by **`launchd`** making possible sharing Mach ports.

* **`NSXPC*`**

These are Objective-C high level objects which allows the abstraction of XPC connections.\
Moreover, it's easier to debug these objects with DTrace than the previous ones.

* **`GCD Queues`**

XPC uses GCD to pass messages, moreover it generates certain dispatch queues like `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

These are **bundles with `.xpc`** extension located inside the **`XPCServices`** folder of other projects and in the `Info.plist` they have the `CFBundlePackageType` set to **`XPC!`**.\
This file have other configuration keys like `ServiceType` which can be Application, User, System or `_SandboxProfile` which can define a sandbox or `_AllowedClients` which might indicate entitlements or ID required to contact the ser. these and other configuration options will be useful to configure the service when being launched.

### Starting a Service

The app attempts to **connect** to a XPC service using `xpc_connection_create_mach_service`, then launchd locates the daemon and starts **`xpcproxy`**. **`xpcproxy`** enforce configured restrictions and. spawns the service with the provided FDs and Mach ports.

In order to improve the speed of the search of the XPC service, a cache is used.

It's possible to trace the actions of `xpcproxy` using:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

The XPC library use `kdebug` to log actions calling `xpc_ktrace_pid0` and `xpc_ktrace_pid1`. The codes it uses are undocumented so it's needed to add the into `/usr/share/misc/trace.codes`. They have the prefix `0x29` and for example one is `0x29000004`: `XPC_serializer_pack`.\
The utility `xpcproxy` uses the prefix `0x22`, for example: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Applications can **subscribe** to different event **messages**, enabling them to be **initiated on-demand** when such events happen. The **setup** for these services is done in l**aunchd plist files**, located in the **same directories as the previous ones** and containing an extra **`LaunchEvent`** key.

### XPC Connecting Process Check

When a process tries to call a method from via an XPC connection, the **XPC service should check if that process is allowed to connect**. Here are the common ways to check that and the common pitfalls:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Authorization

Apple also allows apps to **configure some rights and how to get them** so if the calling process have them it would be **allowed to call a method** from the XPC service:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

To sniff the XPC messages you could use [**xpcspy**](https://github.com/hot3eed/xpcspy) which uses **Frida**.

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Another possible tool to use is [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC Communication C Code Example

{% tabs %}
{% tab title="xpc_server.c" %}
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
{% endtab %}

{% tab title="xpc_client.c" %}
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
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}
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
{% endtab %}
{% endtabs %}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
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

{% tabs %}
{% tab title="oc_xpc_server.m" %}
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
{% endtab %}

{% tab title="oc_xpc_client.m" %}
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
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
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
{% endtab %}
{% endtabs %}

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

## Client inside a Dylb code

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

This functionality provided by `RemoteXPC.framework` (from `libxpc`) allows to communicate via XPC through different hosts.\
The services that supports remote XPC will have in their plist the key UsesRemoteXPC like it's the case of `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. However, although the service will be registered with `launchd`, it's `UserEventAgent` with the plugins `com.apple.remoted.plugin` and `com.apple.remoteservicediscovery.events.plugin` which provides the functionality.

Moreover, the `RemoteServiceDiscovery.framework` allows to get info from the `com.apple.remoted.plugin` exposing functions such as `get_device`, `get_unique_device`, `connect`...

Once connect is used and the socket `fd` of the service is gathered, it's possible to use `remote_xpc_connection_*` class.

It's possible to get information about remote services using the cli tool `/usr/libexec/remotectl` using parameters as:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

The communication between BridgeOS and the host occurs through a dedicated IPv6 interface. The `MultiverseSupport.framework` allows to establish sockets whose `fd` will be used for communicating.\
It's possible to find thee communications using `netstat`, `nettop` or the open source option, `netbottom`.

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
