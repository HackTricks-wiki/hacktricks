# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions とは異なり、**System Extensions は kernel space ではなく user space で実行される**ため、extension の不具合による system crash のリスクを軽減できます。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensions には、**DriverKit** Extensions、**Network** Extensions、**Endpoint Security** Extensions の3種類があります。

### **DriverKit Extensions**

DriverKit は、**hardware support を提供する**kernel extensions の代替です。device driver（USB、Serial、NIC、HID driver など）を kernel space ではなく user space で実行できます。DriverKit framework には、**特定の I/O Kit class の user space 版**が含まれており、kernel は通常の I/O Kit event を user space に転送します。これにより、これらの driver をより安全な環境で実行できます。<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions は、network behavior をカスタマイズする機能を提供します。Network Extensions には、いくつかの種類があります。

- **App Proxy**: flow-oriented な custom VPN protocol を実装する VPN client の作成に使用されます。これは、個々の packet ではなく、connection（または flow）に基づいて network traffic を処理することを意味します。
- **Packet Tunnel**: packet-oriented な custom VPN protocol を実装する VPN client の作成に使用されます。これは、個々の packet に基づいて network traffic を処理することを意味します。
- **Filter Data**: network "flow" の filtering に使用されます。flow level で network data を monitor または modify できます。
- **Filter Packet**: 個々の network packet の filtering に使用されます。packet level で network data を monitor または modify できます。
- **DNS Proxy**: custom DNS provider の作成に使用されます。DNS request と response の monitor または modify に利用できます。<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security は、system security 用の API セットを提供する、Apple が macOS に提供している framework です。これは、**security vendor や developer が system activity を monitor および control し、malicious activity を特定して防御する product を構築するため**に使用されることを想定しています。

この framework は、process execution、file system event、network event、kernel event などの **system activity を monitor および control する API の collection**を提供します。

この framework の core は kernel 内に Kernel Extension（KEXT）として実装されており、**`/System/Library/Extensions/EndpointSecurity.kext`** にあります。<sup>[[2]](#references)</sup> この KEXT は、いくつかの主要 component で構成されています。

- **EndpointSecurityDriver**: kernel extension の "entry point" として機能します。OS と Endpoint Security framework 間の主な interaction point です。
- **EndpointSecurityEventManager**: kernel hook の実装を担当します。Kernel hook により、system call を intercept して system event を monitor できます。
- **EndpointSecurityClientManager**: user space client との communication を管理し、接続されている client と event notification の受信が必要な client を追跡します。
- **EndpointSecurityMessageManager**: user space client に message と event notification を送信します。

Endpoint Security framework が monitor できる event は、以下のように分類されます。

- File event
- Process event
- Socket event
- Kernel event（kernel extension の load/unload や I/O Kit device の open など）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework との **user-space communication** は、IOUserClient class を介して行われます。caller の種類に応じて、2種類の異なる subclass が使用されます。

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` entitlement が必要です。この entitlement は、system process である `endpointsecurityd` のみが保持しています。
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement が必要です。これは通常、Endpoint Security framework と interaction する必要がある third-party security software によって使用されます。<sup>[[1]](#references)</sup>

Endpoint Security Extensions の **`libEndpointSecurity.dylib`** は、system extension が kernel と communication するための C library です。この library は、I/O Kit（`IOKit`）を使用して Endpoint Security KEXT と communication します。<sup>[[2]](#references)</sup>

**`endpointsecurityd`** は、endpoint security system extension の管理と起動に関わる主要な system daemon であり、特に early boot process で重要です。`Info.plist` file で **`NSEndpointSecurityEarlyBoot`** が設定された **system extension のみ**が、この early boot treatment の対象になります。<sup>[[2]](#references)</sup>

別の system daemon である **`sysextd`** は、**system extension を validate** し、適切な system location に移動します。その後、該当する daemon に extension の load を要求します。**`SystemExtensions.framework`** は、system extension の activate と deactivate を担当します。<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF は red teamer の detection を試みる security tool によって使用されるため、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

問題は、security application に **Full Disk Access permissions** が必要なことです。そのため、attacker がそれを remove できれば、software の実行を阻止できます。<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
**詳細情報**については、この bypass および関連する bypass について解説した講演 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) を確認してください。

最終的にこの問題は、**`kTCCServiceEndpointSecurityClient`** という新しい permission を、**`tccd`** が管理する security app に付与することで修正されました。これにより、`tccutil` がその permission をクリアして app の実行を妨げることがなくなります。<sup>[[3]](#references)</sup>

## 参考文献

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
