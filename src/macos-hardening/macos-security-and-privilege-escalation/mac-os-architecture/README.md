# macOS 커널 및 시스템 확장

{{#include ../../../banners/hacktricks-training.md}}

## XNU 커널

**macOS의 핵심은 XNU**로, "X는 유닉스가 아니다"를 의미합니다. 이 커널은 기본적으로 **Mach 마이크로커널**(후에 논의될 예정)과 **버클리 소프트웨어 배포(BSD)**의 요소로 구성되어 있습니다. XNU는 **I/O Kit이라는 시스템을 통해 커널 드라이버를 위한 플랫폼을 제공합니다**. XNU 커널은 다윈 오픈 소스 프로젝트의 일부로, **소스 코드는 자유롭게 접근할 수 있습니다**.

보안 연구자나 유닉스 개발자의 관점에서 **macOS**는 **우아한 GUI와 다양한 맞춤형 애플리케이션을 갖춘 FreeBSD 시스템과 매우 유사하게 느껴질 수 있습니다**. BSD용으로 개발된 대부분의 애플리케이션은 수정 없이 macOS에서 컴파일되고 실행될 수 있으며, 유닉스 사용자에게 친숙한 명령줄 도구가 모두 macOS에 존재합니다. 그러나 XNU 커널이 Mach을 통합하고 있기 때문에 전통적인 유닉스 유사 시스템과 macOS 간에는 몇 가지 중요한 차이점이 있으며, 이러한 차이점은 잠재적인 문제를 일으키거나 독특한 이점을 제공할 수 있습니다.

XNU의 오픈 소스 버전: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach는 **UNIX 호환성**을 위해 설계된 **마이크로커널**입니다. 그 주요 설계 원칙 중 하나는 **커널** 공간에서 실행되는 **코드**의 양을 **최소화**하고 대신 파일 시스템, 네트워킹 및 I/O와 같은 많은 전형적인 커널 기능이 **사용자 수준 작업으로 실행되도록 허용하는** 것이었습니다.

XNU에서 Mach는 커널이 일반적으로 처리하는 많은 중요한 저수준 작업, 즉 프로세서 스케줄링, 멀티태스킹 및 가상 메모리 관리 등을 **책임집니다**.

### BSD

XNU **커널**은 또한 **FreeBSD** 프로젝트에서 파생된 상당량의 코드를 **포함합니다**. 이 코드는 **Mach와 함께 커널의 일부로 실행되며**, 동일한 주소 공간에서 작동합니다. 그러나 XNU 내의 FreeBSD 코드는 Mach과의 호환성을 보장하기 위해 수정이 필요했기 때문에 원래 FreeBSD 코드와 상당히 다를 수 있습니다. FreeBSD는 다음을 포함한 많은 커널 작업에 기여합니다:

- 프로세스 관리
- 신호 처리
- 사용자 및 그룹 관리 등 기본 보안 메커니즘
- 시스템 호출 인프라
- TCP/IP 스택 및 소켓
- 방화벽 및 패킷 필터링

BSD와 Mach 간의 상호작용을 이해하는 것은 그들의 서로 다른 개념적 프레임워크 때문에 복잡할 수 있습니다. 예를 들어, BSD는 프로세스를 기본 실행 단위로 사용하지만 Mach은 스레드를 기반으로 작동합니다. 이 불일치는 **각 BSD 프로세스를 하나의 Mach 스레드를 포함하는 Mach 작업과 연결함으로써 XNU에서 조정됩니다**. BSD의 fork() 시스템 호출이 사용될 때, 커널 내의 BSD 코드는 Mach 함수를 사용하여 작업 및 스레드 구조를 생성합니다.

게다가, **Mach와 BSD는 각각 다른 보안 모델을 유지합니다**: **Mach의** 보안 모델은 **포트 권한**에 기반하고, BSD의 보안 모델은 **프로세스 소유권**에 기반합니다. 이 두 모델 간의 차이로 인해 때때로 로컬 권한 상승 취약점이 발생했습니다. 일반적인 시스템 호출 외에도 **사용자 공간 프로그램이 커널과 상호작용할 수 있도록 하는 Mach 트랩**도 있습니다. 이러한 다양한 요소들이 함께 macOS 커널의 다면적이고 하이브리드 아키텍처를 형성합니다.

### I/O Kit - 드라이버

I/O Kit은 XNU 커널 내의 오픈 소스 객체 지향 **장치 드라이버 프레임워크**로, **동적으로 로드된 장치 드라이버**를 처리합니다. 이는 다양한 하드웨어를 지원하며 커널에 모듈식 코드를 즉시 추가할 수 있게 해줍니다.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - 프로세스 간 통신

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS 커널 확장

macOS는 **커널 확장**(.kext)을 로드하는 데 매우 제한적입니다. 이는 코드가 높은 권한으로 실행되기 때문입니다. 실제로 기본적으로 우회 방법이 발견되지 않는 한 사실상 불가능합니다.

다음 페이지에서는 macOS가 **kernelcache** 내에서 로드하는 `.kext`를 복구하는 방법도 볼 수 있습니다:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS 시스템 확장

커널 확장을 사용하는 대신 macOS는 시스템 확장을 생성하여 커널과 상호작용할 수 있는 사용자 수준 API를 제공합니다. 이렇게 하면 개발자는 커널 확장을 사용할 필요가 없습니다.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## 참고 문헌

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
