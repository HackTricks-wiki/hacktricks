# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions와 달리, **System Extensions는 사용자 공간에서 실행**되어 확장 기능 오작동으로 인한 시스템 충돌 위험을 줄입니다.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System Extensions에는 **DriverKit** Extensions, **Network** Extensions, 및 **Endpoint Security** Extensions의 세 가지 유형이 있습니다.

### **DriverKit Extensions**

DriverKit은 **하드웨어 지원**을 제공하는 커널 확장의 대체물입니다. USB, Serial, NIC 및 HID 드라이버와 같은 장치 드라이버가 커널 공간이 아닌 사용자 공간에서 실행될 수 있도록 합니다. DriverKit 프레임워크는 **특정 I/O Kit 클래스의 사용자 공간 버전**을 포함하며, 커널은 일반 I/O Kit 이벤트를 사용자 공간으로 전달하여 이러한 드라이버가 실행될 수 있는 더 안전한 환경을 제공합니다.

### **Network Extensions**

Network Extensions는 네트워크 동작을 사용자 정의할 수 있는 기능을 제공합니다. 여러 유형의 Network Extensions가 있습니다:

- **App Proxy**: 흐름 지향의 사용자 정의 VPN 프로토콜을 구현하는 VPN 클라이언트를 생성하는 데 사용됩니다. 이는 개별 패킷이 아닌 연결(또는 흐름)을 기반으로 네트워크 트래픽을 처리함을 의미합니다.
- **Packet Tunnel**: 개별 패킷을 기반으로 네트워크 트래픽을 처리하는 패킷 지향의 사용자 정의 VPN 프로토콜을 구현하는 VPN 클라이언트를 생성하는 데 사용됩니다.
- **Filter Data**: 네트워크 "흐름"을 필터링하는 데 사용됩니다. 흐름 수준에서 네트워크 데이터를 모니터링하거나 수정할 수 있습니다.
- **Filter Packet**: 개별 네트워크 패킷을 필터링하는 데 사용됩니다. 패킷 수준에서 네트워크 데이터를 모니터링하거나 수정할 수 있습니다.
- **DNS Proxy**: 사용자 정의 DNS 제공자를 생성하는 데 사용됩니다. DNS 요청 및 응답을 모니터링하거나 수정하는 데 사용할 수 있습니다.

## Endpoint Security Framework

Endpoint Security는 시스템 보안을 위한 API 집합을 제공하는 Apple의 macOS 프레임워크입니다. 이는 **보안 공급업체와 개발자가 시스템 활동을 모니터링하고 제어하여 악의적인 활동을 식별하고 보호할 수 있는 제품을 구축하는 데 사용**됩니다.

이 프레임워크는 프로세스 실행, 파일 시스템 이벤트, 네트워크 및 커널 이벤트와 같은 시스템 활동을 모니터링하고 제어하기 위한 **API 모음**을 제공합니다.

이 프레임워크의 핵심은 커널에 구현되어 있으며, **`/System/Library/Extensions/EndpointSecurity.kext`**에 위치한 커널 확장(KEXT)입니다. 이 KEXT는 여러 주요 구성 요소로 구성됩니다:

- **EndpointSecurityDriver**: 커널 확장의 "진입점" 역할을 합니다. OS와 Endpoint Security 프레임워크 간의 주요 상호작용 지점입니다.
- **EndpointSecurityEventManager**: 커널 후크를 구현하는 책임이 있는 구성 요소입니다. 커널 후크는 시스템 호출을 가로채어 시스템 이벤트를 모니터링할 수 있게 합니다.
- **EndpointSecurityClientManager**: 사용자 공간 클라이언트와의 통신을 관리하며, 어떤 클라이언트가 연결되어 있고 이벤트 알림을 받아야 하는지를 추적합니다.
- **EndpointSecurityMessageManager**: 사용자 공간 클라이언트에 메시지와 이벤트 알림을 전송합니다.

Endpoint Security 프레임워크가 모니터링할 수 있는 이벤트는 다음과 같이 분류됩니다:

- 파일 이벤트
- 프로세스 이벤트
- 소켓 이벤트
- 커널 이벤트 (예: 커널 확장을 로드/언로드하거나 I/O Kit 장치를 여는 경우)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**사용자 공간 통신**은 IOUserClient 클래스를 통해 Endpoint Security 프레임워크와 이루어집니다. 호출자 유형에 따라 두 가지 다른 하위 클래스가 사용됩니다:

- **EndpointSecurityDriverClient**: `com.apple.private.endpoint-security.manager` 권한이 필요하며, 이는 시스템 프로세스 `endpointsecurityd`만 보유합니다.
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` 권한이 필요합니다. 이는 일반적으로 Endpoint Security 프레임워크와 상호작용해야 하는 타사 보안 소프트웨어에서 사용됩니다.

Endpoint Security Extensions:**`libEndpointSecurity.dylib`**는 시스템 확장이 커널과 통신하는 데 사용하는 C 라이브러리입니다. 이 라이브러리는 I/O Kit(`IOKit`)을 사용하여 Endpoint Security KEXT와 통신합니다.

**`endpointsecurityd`**는 엔드포인트 보안 시스템 확장을 관리하고 시작하는 데 관여하는 주요 시스템 데몬으로, 특히 초기 부팅 과정에서 중요합니다. **`Info.plist`** 파일에 **`NSEndpointSecurityEarlyBoot`**로 표시된 **시스템 확장만** 이 초기 부팅 처리를 받습니다.

또 다른 시스템 데몬인 **`sysextd`**는 **시스템 확장을 검증**하고 이를 적절한 시스템 위치로 이동합니다. 그런 다음 관련 데몬에 확장을 로드하도록 요청합니다. **`SystemExtensions.framework`**는 시스템 확장을 활성화하고 비활성화하는 책임이 있습니다.

## Bypassing ESF

ESF는 레드 팀원을 감지하려고 하는 보안 도구에서 사용되므로, 이를 피할 수 있는 방법에 대한 정보는 흥미롭습니다.

### CVE-2021-30965

문제는 보안 애플리케이션이 **전체 디스크 접근 권한**을 가져야 한다는 것입니다. 따라서 공격자가 이를 제거할 수 있다면 소프트웨어가 실행되는 것을 방지할 수 있습니다:
```bash
tccutil reset All
```
더 많은 정보는 이 우회 및 관련된 내용에 대해 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) 강의를 확인하세요.

결국, 이는 **`tccd`**가 관리하는 보안 앱에 새로운 권한 **`kTCCServiceEndpointSecurityClient`**를 부여하여 수정되었으며, 이로 인해 `tccutil`이 권한을 지우지 않아 실행을 방해하지 않게 되었습니다.

## References

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
