# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

**Kernel Extensions**とは異なり、**System Extensionsは kernel space ではなく user space で実行される**ため、extensionの不具合によるシステムクラッシュのリスクを軽減できます。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensionsには、**DriverKit** Extensions、**Network** Extensions、**Endpoint Security** Extensionsの3種類があります。

### **DriverKit Extensions**

DriverKitは、**hardware supportを提供する**kernel extensionsの代替です。デバイスドライバー（USB、Serial、NIC、HID driversなど）をkernel spaceではなくuser spaceで実行できます。DriverKit frameworkには、**特定のI/O Kit classesの user space versions**が含まれており、kernelは通常のI/O Kit eventsをuser spaceに転送します。これにより、これらのドライバーをより安全な環境で実行できます。<sup>[2]</sup>

### **Network Extensions**

Network Extensionsは、network behaviorsをカスタマイズする機能を提供します。Network Extensionsには、いくつかの種類があります。

- **App Proxy**: flow-orientedのcustom VPN protocolを実装するVPN clientの作成に使用します。つまり、個々のpacketではなく、connections（またはflows）に基づいてnetwork trafficを処理します。
- **Packet Tunnel**: packet-orientedのcustom VPN protocolを実装するVPN clientの作成に使用します。つまり、個々のpacketsに基づいてnetwork trafficを処理します。
- **Filter Data**: network "flows"のfilteringに使用します。flow levelでnetwork dataをmonitorまたはmodifyできます。
- **Filter Packet**: 個々のnetwork packetsのfilteringに使用します。packet levelでnetwork dataをmonitorまたはmodifyできます。
- **DNS Proxy**: custom DNS providerの作成に使用します。DNS requestsとresponsesのmonitorまたはmodifyに使用できます。<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Securityは、system security用のAPI setを提供するAppleのmacOS frameworkです。**security vendorsとdevelopersが、malicious activityを特定して防御するためにsystem activityをmonitorおよびcontrolできるproductsを構築する**ことを目的としています。

このframeworkは、process executions、file system events、network events、kernel eventsなどの**system activityをmonitorおよびcontrolするAPI collection**を提供します。

このframeworkのcoreは、**`/System/Library/Extensions/EndpointSecurity.kext`**にあるKernel Extension（KEXT）としてkernelに実装されています。<sup>[2]</sup>このKEXTは、いくつかの主要なcomponentsで構成されています。

- **EndpointSecurityDriver**: Kernel Extensionの「entry point」として機能します。OSとEndpoint Security framework間の主要なinteraction pointです。
- **EndpointSecurityEventManager**: kernel hooksの実装を担当します。Kernel hooksにより、system callsをinterceptしてsystem eventsをmonitorできます。
- **EndpointSecurityClientManager**: user space clientsとのcommunicationを管理し、接続されているclientとevent notificationsを受信する必要があるclientを追跡します。
- **EndpointSecurityMessageManager**: user space clientsにmessagesとevent notificationsを送信します。

Endpoint Security frameworkがmonitorできるeventsは、次のように分類されます。

- File events
- Process events
- Socket events
- Kernel events（kernel extensionのloading/unloadingやI/O Kit deviceのopeningなど）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security frameworkとの**user-space communication**は、IOUserClient classを介して行われます。callerの種類に応じて、2つの異なるsubclassesが使用されます。

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` entitlementが必要です。このentitlementを保持しているのは、system processである`endpointsecurityd`のみです。
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlementが必要です。通常、Endpoint Security frameworkとinteractionする必要があるthird-party security softwareによって使用されます。<sup>[1]</sup>

Endpoint Security Extensionsの**`libEndpointSecurity.dylib`**は、system extensionsがkernelとcommunicationするためのC libraryです。このlibraryは、I/O Kit（`IOKit`）を使用してEndpoint Security KEXTとcommunicationします。<sup>[2]</sup>

**`endpointsecurityd`**は、endpoint security system extensionsのmanagementとlaunch、特にearly boot processに関与する主要なsystem daemonです。**`Info.plist` fileで** **`NSEndpointSecurityEarlyBoot`**が指定された**system extensionsのみ**が、このearly boot treatmentを受けます。<sup>[2]</sup>

もう1つのsystem daemonである**`sysextd`**は、**system extensionsをvalidate**し、それらを適切なsystem locationsに移動します。その後、該当するdaemonにextensionのloadを要求します。**`SystemExtensions.framework`**は、system extensionsのactivateとdeactivateを担当します。<sup>[2]</sup>

## Bypassing ESF

ESFはred teamerをdetectしようとするsecurity toolsによって使用されるため、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

問題は、security applicationに**Full Disk Access permissions**が必要なことです。そのため、attackerがそれをremoveできれば、softwareの実行を防止できます。<sup>[3]</sup>
```bash
tccutil reset All
```
この bypass および関連する bypass の**詳細情報**については、講演 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) を確認してください。

最終的に、**`kTCCServiceEndpointSecurityClient`** という新しい permission を、**`tccd`** が管理する security app に付与することで修正されました。これにより、`tccutil` がその permission を消去して実行を妨げることがなくなりました。<sup>[3]</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
