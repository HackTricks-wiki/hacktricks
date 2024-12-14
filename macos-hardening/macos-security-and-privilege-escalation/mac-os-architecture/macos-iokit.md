# macOS IOKit

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

The I/O Kit is an open-source, object-oriented **device-driver framework** in the XNU kernel, handles **dynamically loaded device drivers**. It allows modular code to be added to the kernel on-the-fly, supporting diverse hardware.

IOKit drivers will basically **export functions from the kernel**. These function parameter **types** are **predefined** and are verified. Moreover, similar to XPC, IOKit is just another layer on **top of Mach messages**.

**IOKit XNU kernel code** is opensourced by Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Moreover, the user space IOKit components are also opensource [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

However, **no IOKit drivers** are opensource. Anyway, from time to time a release of a driver might come with symbols that makes it easier to debug it. Check how to [**get the driver extensions from the firmware here**](./#ipsw)**.**

It's written in **C++**. You can get demangled C++ symbols with:

```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```

{% hint style="danger" %}
IOKit **exposed functions** could perform **additional security checks** when a client tries to call a function but note that the apps are usually **limited** by the **sandbox** to which IOKit functions they can interact with.
{% endhint %}

## Drivers

In macOS they are located in:

* **`/System/Library/Extensions`**
  * KEXT files built into the OS X operating system.
* **`/Library/Extensions`**
  * KEXT files installed by 3rd party software

In iOS they are located in:

* **`/System/Library/Extensions`**

```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
   10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```

Until the number 9 the listed drivers are **loaded in the address 0**. This means that those aren't real drivers but **part of the kernel and they cannot be unloaded**.

In order to find specific extensions you can use:

```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```

To load and unload kernel extensions do:

```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```

## IORegistry

The **IORegistry** is a crucial part of the IOKit framework in macOS and iOS which serves as a database for representing the system's hardware configuration and state. It's a **hierarchical collection of objects that represent all the hardware and drivers** loaded on the system, and their relationships to each other.

You can get the IORegistry using the cli **`ioreg`** to inspect it from the console (specially useful for iOS).

```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```

You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" are used to organize and display the relationships between different objects in the IORegistry. Each plane represents a specific type of relationship or a particular view of the system's hardware and driver configuration. Here are some of the common planes you might encounter in IORegistryExplorer:

1. **IOService Plane**: This is the most general plane, displaying the service objects that represent drivers and nubs (communication channels between drivers). It shows the provider-client relationships between these objects.
2. **IODeviceTree Plane**: This plane represents the physical connections between devices as they are attached to the system. It is often used to visualize the hierarchy of devices connected via buses like USB or PCI.
3. **IOPower Plane**: Displays objects and their relationships in terms of power management. It can show which objects are affecting the power state of others, useful for debugging power-related issues.
4. **IOUSB Plane**: Specifically focused on USB devices and their relationships, showing the hierarchy of USB hubs and connected devices.
5. **IOAudio Plane**: This plane is for representing audio devices and their relationships within the system.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `"YourServiceNameHere"` and calls the function inside the selector 0. For it:

* it first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
* It then establish a connection calling **`IOServiceOpen`**.
* And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).

```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Get a reference to the service using its name
        CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
        if (matchingDict == NULL) {
            NSLog(@"Failed to create matching dictionary");
            return -1;
        }
        
        // Obtain an iterator over all matching services
        io_iterator_t iter;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to get matching services");
            return -1;
        }
        
        // Get a reference to the first service (assuming it exists)
        io_service_t service = IOIteratorNext(iter);
        if (!service) {
            NSLog(@"No matching service found");
            IOObjectRelease(iter);
            return -1;
        }
        
        // Open a connection to the service
        io_connect_t connect;
        kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to open service");
            IOObjectRelease(service);
            IOObjectRelease(iter);
            return -1;
        }
        
        // Call a method on the service
        // Assume the method has a selector of 0, and takes no arguments
        kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to call method");
        }
        
        // Cleanup
        IOServiceClose(connect);
        IOObjectRelease(service);
        IOObjectRelease(iter);
    }
    return 0;
}
```

There are **other** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

You could obtain these for example from a [**firmware image (ipsw)**](./#ipsw). Then, load it into your favourite decompiler.

You could start decompiling the **`externalMethod`** function as this is the driver function that will be receiving the call and calling the correct function:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

That awful call demagled means:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Note how in the previous definition the **`self`** param is missed, the good definition would be:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Actually, you can find the real definition in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):

```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
    const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
    OSObject * target, void * reference)
```

With this info you can rewrite Ctrl+Right -> `Edit function signature` and set the known types:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

The new decompiled code will look like:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

For the next step we need to have defined the **`IOExternalMethodDispatch2022`** struct. It's opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), you could define it:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Now, following the `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` you can see a lot of data:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Change the Data Type to **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

after the change:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

And as we now in there we have an **array of 7 elements** (check the final decompiled code), click to create an array of 7 elements:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

After the array is created you can see all the exported functions:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
If you remember, to **call** an **exported** function from user space we don't need to call the name of the function, but the **selector number**. Here you can see that the selector **0** is the function **`initializeDecoder`**, the selector **1** is **`startDecoder`**, the selector **2** **`initializeEncoder`**...
{% endhint %}

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

