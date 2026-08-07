# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions とは異なり、**System Extensions は kernel space ではなく user space で実行される**ため、extension の不具合によるシステムクラッシュのリスクを軽減できます。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensions には、**DriverKit** Extensions、**Network** Extensions、**Endpoint Security** Extensions の3種類があります。

### **DriverKit Extensions**

DriverKit は、**hardware support を提供する**kernel extensions の代替です。デバイスドライバ（USB、Serial、NIC、HID driver など）を kernel space ではなく user space で実行できます。DriverKit framework には、**特定の I/O Kit classes の user space versions** が含まれており、kernel は通常の I/O Kit events を user space に転送することで、これらの driver をより安全な環境で実行できるようにします。<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions は、network behaviors をカスタマイズする機能を提供します。Network Extensions には、いくつかの種類があります。

- **App Proxy**: flow-oriented の custom VPN protocol を実装する VPN client の作成に使用されます。つまり、個々の packet ではなく、connections（または flows）に基づいて network traffic を処理します。
- **Packet Tunnel**: packet-oriented の custom VPN protocol を実装する VPN client の作成に使用されます。つまり、個々の packets に基づいて network traffic を処理します。
- **Filter Data**: network "flows" の filtering に使用されます。flow level で network data を monitor または modify できます。
- **Filter Packet**: 個々の network packets の filtering に使用されます。packet level で network data を monitor または modify できます。
- **DNS Proxy**: custom DNS provider の作成に使用されます。DNS requests と responses の monitor または modify に利用できます。<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security は、system security 用の API set を提供する、Apple が macOS に搭載している framework です。これは、**malicious activity を特定して防御するために、system activity を monitor および control できる製品を security vendors と developers が構築する**ことを目的としています。

この framework は、process executions、file system events、network events、kernel events などの **system activity を monitor および control する API collection** を提供します。

この framework の core は、**`/System/Library/Extensions/EndpointSecurity.kext`** にある Kernel Extension（KEXT）として kernel に実装されています。<sup>[[2]](#references)</sup> この KEXT は、いくつかの主要な component で構成されています。

- **EndpointSecurityDriver**: Kernel Extension の "entry point" として機能します。OS と Endpoint Security framework 間の主な interaction point です。
- **EndpointSecurityEventManager**: kernel hooks の実装を担当します。Kernel hooks により、system calls を intercept して system events を monitor できます。
- **EndpointSecurityClientManager**: user space clients との communication を管理し、接続中で event notifications を受信する必要がある clients を追跡します。
- **EndpointSecurityMessageManager**: user space clients に messages と event notifications を送信します。

Endpoint Security framework が monitor できる events は、以下のように分類されます。

- File events
- Process events
- Socket events
- Kernel events（kernel extension の loading/unloading や I/O Kit device の opening など）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework との **user-space communication** は、IOUserClient class を介して行われます。caller の type に応じて、2つの異なる subclasses が使用されます。

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` entitlement が必要です。この entitlement を保持しているのは、system process である `endpointsecurityd` のみです。
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement が必要です。これは通常、Endpoint Security framework と interaction する必要がある third-party security software によって使用されます。<sup>[[1]](#references)</sup>

Endpoint Security Extensions: **`libEndpointSecurity.dylib`** は、system extensions が kernel と communication するための C library です。この library は I/O Kit（`IOKit`）を使用して Endpoint Security KEXT と communication します。<sup>[[2]](#references)</sup>

**`endpointsecurityd`** は、endpoint security system extensions の management と launching、特に early boot process に関与する主要な system daemon です。**`Info.plist` file 内で `NSEndpointSecurityEarlyBoot` が付与された system extensions のみ**が、この early boot treatment を受けます。<sup>[[2]](#references)</sup>

別の system daemon である **`sysextd`** は、**system extensions を validate** し、適切な system locations に移動します。その後、該当する daemon に extension の load を依頼します。**`SystemExtensions.framework`** は、system extensions の activating と deactivating を担当します。<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF は red teamer の検出を試みる security tools によって使用されるため、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

問題は、security application に **Full Disk Access permissions** が必要なことです。したがって、attacker がそれを remove できれば、software の実行を防止できます。<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
**詳細情報**については、この bypass および関連する bypass を扱ったトーク [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup> を確認してください。

最終的にこれは、`tccd` が管理する security app に新しい permission **`kTCCServiceEndpointSecurityClient`** を付与することで修正されました。これにより、`tccutil` がその権限をクリアして実行を妨げることがなくなります。<sup>[[3]](#references)</sup>

## 参考文献

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
