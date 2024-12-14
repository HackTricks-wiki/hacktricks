# macOS System Extensions

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

## System Extensions / Endpoint Security Framework

Unlike Kernel Extensions, **System Extensions run in user space** instead of kernel space, reducing the risk of a system crash due to extension malfunction.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

There are three types of system extensions: **DriverKit** Extensions, **Network** Extensions, and **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit is a replacement for kernel extensions that **provide hardware support**. It allows device drivers (like USB, Serial, NIC, and HID drivers) to run in user space rather than kernel space. The DriverKit framework includes **user space versions of certain I/O Kit classes**, and the kernel forwards normal I/O Kit events to user space, offering a safer environment for these drivers to run.

### **Network Extensions**

Network Extensions provide the ability to customize network behaviors. There are several types of Network Extensions:

* **App Proxy**: This is used for creating a VPN client that implements a flow-oriented, custom VPN protocol. This means it handles network traffic based on connections (or flows) rather than individual packets.
* **Packet Tunnel**: This is used for creating a VPN client that implements a packet-oriented, custom VPN protocol. This means it handles network traffic based on individual packets.
* **Filter Data**: This is used for filtering network "flows". It can monitor or modify network data at the flow level.
* **Filter Packet**: This is used for filtering individual network packets. It can monitor or modify network data at the packet level.
* **DNS Proxy**: This is used for creating a custom DNS provider. It can be used to monitor or modify DNS requests and responses.

## Endpoint Security Framework

Endpoint Security is a framework provided by Apple in macOS that provides a set of APIs for system security. It's intended for use by **security vendors and developers to build products that can monitor and control system activity** to identify and protect against malicious activity.

This framework provides a **collection of APIs to monitor and control system activity**, such as process executions, file system events, network and kernel events.

The core of this framework is implemented in the kernel, as a Kernel Extension (KEXT) located at **`/System/Library/Extensions/EndpointSecurity.kext`**. This KEXT is made up of several key components:

* **EndpointSecurityDriver**: This acts as the "entry point" for the kernel extension. It's the main point of interaction between the OS and the Endpoint Security framework.
* **EndpointSecurityEventManager**: This component is responsible for implementing kernel hooks. Kernel hooks allow the framework to monitor system events by intercepting system calls.
* **EndpointSecurityClientManager**: This manages the communication with user space clients, keeping track of which clients are connected and need to receive event notifications.
* **EndpointSecurityMessageManager**: This sends messages and event notifications to user space clients.

The events that the Endpoint Security framework can monitor are categorized into:

* File events
* Process events
* Socket events
* Kernel events (such as loading/unloading a kernel extension or opening an I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**User-space communication** with the Endpoint Security framework happens through the IOUserClient class. Two different subclasses are used, depending on the type of caller:

* **EndpointSecurityDriverClient**: This requires the `com.apple.private.endpoint-security.manager` entitlement, which is only held by the system process `endpointsecurityd`.
* **EndpointSecurityExternalClient**: This requires the `com.apple.developer.endpoint-security.client` entitlement. This would typically be used by third-party security software that needs to interact with the Endpoint Security framework.

The Endpoint Security Extensions:**`libEndpointSecurity.dylib`** is the C library that system extensions use to communicate with the kernel. This library uses the I/O Kit (`IOKit`) to communicate with the Endpoint Security KEXT.

**`endpointsecurityd`** is a key system daemon involved in managing and launching endpoint security system extensions, particularly during the early boot process. **Only system extensions** marked with **`NSEndpointSecurityEarlyBoot`** in their `Info.plist` file receive this early boot treatment.

Another system daemon, **`sysextd`**, **validates system extensions** and moves them into the proper system locations. It then asks the relevant daemon to load the extension. The **`SystemExtensions.framework`** is responsible for activating and deactivating system extensions.

## Bypassing ESF

ESF is used by security tools that will try to detect a red teamer, so any information about how this could be avoided sounds interesting.

### CVE-2021-30965

The thing is that the security application needs to have **Full Disk Access permissions**. So if an attacker could remove that, he could prevent the software from running:

```bash
tccutil reset All
```

For **more information** about this bypass and related ones check the talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

At the end this was fixed by giving the new permission **`kTCCServiceEndpointSecurityClient`** to the security app managed by **`tccd`** so `tccutil` won't clear its permissions preventing it from running.

## References

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

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

