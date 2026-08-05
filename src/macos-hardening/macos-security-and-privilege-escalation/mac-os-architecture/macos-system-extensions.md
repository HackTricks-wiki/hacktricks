# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions와 달리 **System Extensions는 kernel space 대신 user space에서 실행**되므로, extension malfunction으로 인한 system crash 위험을 줄일 수 있습니다.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensions에는 **DriverKit** Extensions, **Network** Extensions, **Endpoint Security** Extensions의 세 가지 유형이 있습니다.

### **DriverKit Extensions**

DriverKit은 **hardware support를 제공하는** kernel extensions를 대체합니다. 이를 통해 device driver(예: USB, Serial, NIC, HID driver)가 kernel space가 아닌 user space에서 실행될 수 있습니다. DriverKit framework에는 **특정 I/O Kit class의 user space version**이 포함되어 있으며, kernel은 일반적인 I/O Kit event를 user space로 전달하므로 이러한 driver가 더 안전한 환경에서 실행될 수 있습니다.<sup>[2]</sup>

### **Network Extensions**

Network Extensions는 network behavior를 customize할 수 있는 기능을 제공합니다. Network Extensions에는 다음과 같은 여러 유형이 있습니다.

- **App Proxy**: flow-oriented custom VPN protocol을 구현하는 VPN client를 생성하는 데 사용됩니다. 이는 개별 packet이 아니라 connection(또는 flow)을 기준으로 network traffic을 처리한다는 의미입니다.
- **Packet Tunnel**: packet-oriented custom VPN protocol을 구현하는 VPN client를 생성하는 데 사용됩니다. 이는 개별 packet을 기준으로 network traffic을 처리한다는 의미입니다.
- **Filter Data**: network "flow"를 filtering하는 데 사용됩니다. flow level에서 network data를 monitor하거나 modify할 수 있습니다.
- **Filter Packet**: 개별 network packet을 filtering하는 데 사용됩니다. packet level에서 network data를 monitor하거나 modify할 수 있습니다.
- **DNS Proxy**: custom DNS provider를 생성하는 데 사용됩니다. DNS request와 response를 monitor하거나 modify하는 데 사용할 수 있습니다.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security는 macOS에서 Apple이 제공하는 framework로, system security를 위한 API 집합을 제공합니다. 이 framework는 **security vendor와 developer가 system activity를 monitor하고 control하여** malicious activity를 식별하고 방어하는 product를 build하는 데 사용하도록 설계되었습니다.

이 framework는 process execution, file system event, network 및 kernel event와 같은 **system activity를 monitor하고 control하기 위한 API 모음**을 제공합니다.

이 framework의 핵심은 **`/System/Library/Extensions/EndpointSecurity.kext`**에 위치한 Kernel Extension(KEXT)으로 kernel에 구현되어 있습니다.<sup>[2]</sup> 이 KEXT는 다음과 같은 주요 component로 구성됩니다.

- **EndpointSecurityDriver**: Kernel Extension의 "entry point" 역할을 합니다. OS와 Endpoint Security framework 간 상호작용의 주요 지점입니다.
- **EndpointSecurityEventManager**: kernel hook 구현을 담당합니다. Kernel hook을 사용하면 system call을 intercept하여 system event를 monitor할 수 있습니다.
- **EndpointSecurityClientManager**: user space client와의 communication을 관리하며, 어떤 client가 연결되어 있고 event notification을 받아야 하는지 추적합니다.
- **EndpointSecurityMessageManager**: user space client에 message와 event notification을 전송합니다.

Endpoint Security framework가 monitor할 수 있는 event는 다음과 같이 분류됩니다.

- File event
- Process event
- Socket event
- Kernel event(kernel extension을 loading/unloading하거나 I/O Kit device를 opening하는 event 등)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework와의 **user-space communication**은 IOUserClient class를 통해 이루어집니다. caller type에 따라 두 가지 subclass가 사용됩니다.

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` entitlement가 필요하며, 이 entitlement는 system process인 `endpointsecurityd`만 보유합니다.
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement가 필요합니다. 일반적으로 Endpoint Security framework와 상호작용해야 하는 third-party security software가 사용합니다.<sup>[1]</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`**는 system extension이 kernel과 communication하는 데 사용하는 C library입니다. 이 library는 I/O Kit(`IOKit`)를 사용하여 Endpoint Security KEXT와 communication합니다.<sup>[2]</sup>

**`endpointsecurityd`**는 endpoint security system extension을 관리하고 launch하는 데 관여하는 주요 system daemon이며, 특히 early boot process 중에 사용됩니다. **`Info.plist` file에서** **`NSEndpointSecurityEarlyBoot`**으로 표시된 **system extension만** 이러한 early boot 처리를 받습니다.<sup>[2]</sup>

또 다른 system daemon인 **`sysextd`**는 **system extension을 validate**하고 적절한 system location으로 이동합니다. 그런 다음 관련 daemon에 extension을 load하도록 요청합니다. **`SystemExtensions.framework`**는 system extension의 activate 및 deactivate를 담당합니다.<sup>[2]</sup>

## Bypassing ESF

ESF는 red teamer를 detect하려는 security tool에서 사용되므로, 이를 avoid할 수 있는 방법에 관한 정보는 흥미롭게 들릴 수 있습니다.

### CVE-2021-30965

문제는 security application에 **Full Disk Access permissions**가 필요하다는 것입니다. 따라서 attacker가 이를 remove할 수 있다면 software가 실행되는 것을 방지할 수 있습니다.<sup>[3]</sup>
```bash
tccutil reset All
```
**more information** about this bypass 및 관련 bypass에 대해서는 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) 강연을 확인하세요.

결국 이 문제는 `tccd`가 관리하는 security app에 새로운 권한 **`kTCCServiceEndpointSecurityClient`**를 부여하여 해결되었습니다. 따라서 `tccutil`이 해당 앱의 권한을 지워 실행을 방해할 수 없습니다.<sup>[3]</sup>

## 참고 자료

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
