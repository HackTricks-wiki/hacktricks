# macOS 시스템 확장

{{#include ../../../banners/hacktricks-training.md}}

## 시스템 확장 / Endpoint Security Framework

Kernel Extensions와 달리 **System Extensions는 kernel space 대신 user space에서 실행**되므로, extension malfunction으로 인한 system crash 위험이 줄어듭니다.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensions에는 **DriverKit** Extensions, **Network** Extensions, **Endpoint Security** Extensions의 세 가지 유형이 있습니다.

### **DriverKit Extensions**

DriverKit은 **hardware support를 제공하는** kernel extensions를 대체합니다. 이를 통해 device drivers(예: USB, Serial, NIC, HID drivers)가 kernel space가 아닌 user space에서 실행될 수 있습니다. DriverKit framework에는 **특정 I/O Kit classes의 user space 버전**이 포함되어 있으며, kernel은 일반적인 I/O Kit events를 user space로 전달하여 이러한 drivers가 더 안전한 환경에서 실행되도록 합니다.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions는 network behaviors를 custom할 수 있는 기능을 제공합니다. Network Extensions에는 여러 유형이 있습니다.

- **App Proxy**: flow-oriented custom VPN protocol을 구현하는 VPN client를 생성하는 데 사용됩니다. 이는 개별 packets가 아니라 connections(또는 flows)를 기반으로 network traffic을 처리한다는 의미입니다.
- **Packet Tunnel**: packet-oriented custom VPN protocol을 구현하는 VPN client를 생성하는 데 사용됩니다. 이는 개별 packets를 기반으로 network traffic을 처리한다는 의미입니다.
- **Filter Data**: network "flows"를 filtering하는 데 사용됩니다. flow level에서 network data를 monitor하거나 modify할 수 있습니다.
- **Filter Packet**: 개별 network packets를 filtering하는 데 사용됩니다. packet level에서 network data를 monitor하거나 modify할 수 있습니다.
- **DNS Proxy**: custom DNS provider를 생성하는 데 사용됩니다. DNS requests와 responses를 monitor하거나 modify하는 데 사용할 수 있습니다.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security는 macOS에서 Apple이 제공하는 framework로, system security를 위한 API 집합을 제공합니다. **security vendors와 developers가 system activity를 monitor하고 control하여** malicious activity를 식별하고 방어하는 products를 구축하는 데 사용하도록 설계되었습니다.

이 framework는 process executions, file system events, network 및 kernel events와 같은 **system activity를 monitor하고 control하기 위한 API 모음**을 제공합니다.

이 framework의 핵심은 **`/System/Library/Extensions/EndpointSecurity.kext`**에 위치한 Kernel Extension(KEXT)으로 kernel에 구현되어 있습니다.<sup>[[2]](#references)</sup> 이 KEXT는 다음과 같은 여러 핵심 components로 구성됩니다.

- **EndpointSecurityDriver**: Kernel Extension의 "entry point" 역할을 합니다. OS와 Endpoint Security framework 간 상호작용의 주요 지점입니다.
- **EndpointSecurityEventManager**: kernel hooks를 구현합니다. Kernel hooks를 사용하면 system calls를 intercept하여 system events를 monitor할 수 있습니다.
- **EndpointSecurityClientManager**: user space clients와의 communication을 관리하고, 어떤 clients가 연결되어 있으며 event notifications를 받아야 하는지 추적합니다.
- **EndpointSecurityMessageManager**: user space clients에 messages와 event notifications를 전송합니다.

Endpoint Security framework가 monitor할 수 있는 events는 다음과 같이 분류됩니다.

- File events
- Process events
- Socket events
- Kernel events(kernel extension의 loading/unloading 또는 I/O Kit device의 opening 등)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework와의 **user-space communication**은 IOUserClient class를 통해 이루어집니다. Caller의 유형에 따라 서로 다른 두 subclasses가 사용됩니다.

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` entitlement가 필요하며, 이 entitlement는 system process인 `endpointsecurityd`만 보유합니다.
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement가 필요합니다. 일반적으로 Endpoint Security framework와 상호작용해야 하는 third-party security software가 사용합니다.<sup>[[1]](#references)</sup>

Endpoint Security Extensions의 **`libEndpointSecurity.dylib`**는 system extensions가 kernel과 communication하는 데 사용하는 C library입니다. 이 library는 I/O Kit(`IOKit`)를 사용하여 Endpoint Security KEXT와 communication합니다.<sup>[[2]](#references)</sup>

**`endpointsecurityd`**는 endpoint security system extensions를 관리하고 launch하는 데 관여하는 핵심 system daemon이며, 특히 early boot process에서 중요한 역할을 합니다. `Info.plist` file에서 **`NSEndpointSecurityEarlyBoot`**로 표시된 **system extensions만** 이러한 early boot 처리를 받습니다.<sup>[[2]](#references)</sup>

또 다른 system daemon인 **`sysextd`**는 **system extensions를 validate**하고 적절한 system locations로 이동합니다. 그런 다음 관련 daemon에 extension을 load하도록 요청합니다. **`SystemExtensions.framework`**는 system extensions를 activate하고 deactivate하는 역할을 담당합니다.<sup>[[2]](#references)</sup>

## ESF 우회

ESF는 red teamer를 detect하려는 security tools에서 사용되므로, 이를 어떻게 회피할 수 있는지에 관한 정보는 흥미로울 수 있습니다.

### CVE-2021-30965

문제는 security application에 **Full Disk Access permissions**가 필요하다는 것입니다. 따라서 attacker가 해당 permissions를 remove할 수 있다면 software가 실행되는 것을 방지할 수 있습니다.<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
**더 많은 정보**와 이와 관련된 우회 방법은 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) 강연을 확인하세요.

결국 새로운 permission **`kTCCServiceEndpointSecurityClient`**를 **`tccd`**가 관리하는 security app에 부여하여 이 문제가 해결되었습니다. 이를 통해 `tccutil`이 해당 앱의 permission을 지우지 못하게 되어 앱이 실행될 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
