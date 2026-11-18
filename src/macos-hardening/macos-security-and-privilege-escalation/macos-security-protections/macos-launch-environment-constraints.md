# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS의 Launch Constraints는 **프로세스를 어떻게, 누가, 어디에서 시작할 수 있는지 규제**하여 보안을 강화하기 위해 도입되었습니다. macOS Ventura에서 도입된 이 기능은 **각 시스템 바이너리를 서로 다른 제약 조건 카테고리로 분류**하는 프레임워크를 제공합니다. 이 카테고리는 시스템 바이너리와 각 바이너리의 해시가 포함된 목록인 **trust cache**에 정의됩니다. 이러한 제약 조건은 시스템의 모든 실행 파일에 적용되며, **특정 바이너리를 실행하기 위한** 요구 사항을 규정하는 일련의 **규칙**을 포함합니다. 규칙에는 바이너리가 충족해야 하는 self constraints, 부모 프로세스가 충족해야 하는 parent constraints, 그리고 다른 관련 주체가 따라야 하는 responsible constraints가 포함됩니다.<sup>[[1]](#references)[[4]](#references)</sup>

이 메커니즘은 macOS Sonoma부터 **Environment Constraints**를 통해 타사 앱에도 적용됩니다. 개발자는 **환경 제약 조건에 사용할 키와 값의 집합**을 지정하여 앱을 보호할 수 있습니다.<sup>[[5]](#references)</sup>

**launch environment 및 library constraints**는 제약 조건 딕셔너리에서 정의합니다. 이 딕셔너리는 **`launchd` property list 파일**에 저장하거나, 코드 서명에 사용하는 **별도의 property list** 파일에 저장할 수 있습니다.<sup>[[5]](#references)</sup>

제약 조건은 4가지 유형으로 나뉩니다.

- **Self Constraints**: **실행 중인** 바이너리에 적용되는 제약 조건입니다.
- **Parent Process**: **프로세스의 부모**에 적용되는 제약 조건입니다(예: **`launchd`**가 XP 서비스를 실행하는 경우).
- **Responsible Constraints**: XPC 통신에서 **서비스를 호출하는 프로세스**에 적용되는 제약 조건입니다.
- **Library load constraints**: 로드할 수 있는 코드를 선택적으로 지정할 때 사용합니다.

따라서 프로세스가 `execve(_:_:_:)` 또는 `posix_spawn(_:_:_:_:_:_:)`을 호출하여 다른 프로세스를 실행하려고 하면, 운영 체제는 **실행 파일**이 해당 파일의 **self constraint**를 **충족하는지** 확인합니다. 또한 **부모 프로세스**의 실행 파일이 해당 실행 파일의 **parent constraint**를 충족하는지, 그리고 **responsible process**의 실행 파일이 실행 파일의 **responsible process constraint**를 충족하는지도 확인합니다. 실행 제약 조건 중 하나라도 충족되지 않으면 운영 체제는 프로그램을 실행하지 않습니다.

라이브러리를 로드할 때 **library constraint의 일부라도 참이 아니면** 프로세스는 해당 라이브러리를 **로드하지 않습니다**.

## LC 카테고리

LC는 **사실(facts)**과 사실을 결합하는 **논리 연산자**(and, or 등)로 구성됩니다.

LC에서 사용할 수 있는 [**사실은 문서화되어 있습니다**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). 예를 들면 다음과 같습니다.

- is-init-proc: 실행 파일이 운영 체제의 초기화 프로세스(`launchd`)여야 하는지를 나타내는 Boolean 값입니다.
- is-sip-protected: 실행 파일이 System Integrity Protection (SIP)으로 보호되는 파일이어야 하는지를 나타내는 Boolean 값입니다.
- `on-authorized-authapfs-volume:` 운영 체제가 실행 파일을 인증된 APFS 볼륨에서 로드했는지를 나타내는 Boolean 값입니다.
- `on-authorized-authapfs-volume`: 운영 체제가 실행 파일을 인증된 APFS 볼륨에서 로드했는지를 나타내는 Boolean 값입니다.
  - Cryptexes 볼륨
- `on-system-volume:` 운영 체제가 현재 부팅된 시스템 볼륨에서 실행 파일을 로드했는지를 나타내는 Boolean 값입니다.
  - /System 내부...
- ...

Apple 바이너리에 서명하면 해당 바이너리는 **trust cache** 내의 LC 카테고리에 할당됩니다.

- **iOS 16 LC 카테고리**는 [**여기에서 역공학되어 문서화되었습니다**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- 현재 **LC 카테고리(macOS 14 - Somona)**는 역공학되었으며, [**설명은 여기에서 확인할 수 있습니다**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

예를 들어 Category 1은 다음과 같습니다.<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: System 또는 Cryptexes 볼륨에 있어야 합니다.
- `launch-type == 1`: 시스템 서비스여야 합니다(LaunchDaemons의 plist).
- `validation-category == 1`: 운영 체제 실행 파일입니다.
- `is-init-proc`: Launchd

### LC Categories 역공학

[**여기에서 자세히 알아볼 수 있습니다**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints). 간단히 말해, 이들은 **AMFI (AppleMobileFileIntegrity)**에 정의되어 있으므로 **KEXT**를 얻으려면 Kernel Development Kit을 다운로드해야 합니다. **`kConstraintCategory`**로 시작하는 심볼이 **중요한** 심볼입니다. 이를 추출하면 DER(ASN.1) 인코딩 스트림을 얻을 수 있으며, 이 스트림은 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 또는 python-asn1 라이브러리와 해당 라이브러리의 `dump.py` 스크립트([andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master))로 디코딩해야 더 이해하기 쉬운 문자열을 얻을 수 있습니다.<sup>[[3]](#references)[[8]](#references)</sup>

## 환경 제약 조건

이는 **타사 애플리케이션**에 설정된 Launch Constraints입니다. 개발자는 애플리케이션에 대한 접근을 제한하기 위해 사용할 **조건**과 **논리 연산자**를 선택할 수 있습니다.

다음 명령으로 애플리케이션의 Environment Constraints를 열거할 수 있습니다.

```bash
codesign -d -vvvv app.app
```

## 신뢰 캐시

**macOS**에는 몇 가지 신뢰 캐시가 있습니다.

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS에서는 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**에 있는 것으로 보입니다.

> [!WARNING]
> Apple Silicon 기기에서 실행 중인 macOS의 경우, Apple이 서명한 바이너리가 신뢰 캐시에 없으면 AMFI가 해당 바이너리의 로드를 거부합니다.

### 신뢰 캐시 열거

앞서 언급한 신뢰 캐시 파일은 **IMG4** 형식이며, IM4P는 IMG4 형식의 페이로드 섹션입니다.

[**pyimg4**](https://github.com/m1stadev/PyIMG4)를 사용하여 데이터베이스의 페이로드를 추출할 수 있습니다:

```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```

(또 다른 방법으로 [**img4tool**](https://github.com/tihmstar/img4tool)을 사용할 수도 있습니다. 릴리스가 오래되었더라도 M1에서 실행되며, 적절한 위치에 설치하면 x86_64에서도 실행됩니다.)

이제 [**trustcache**](https://github.com/CRKatri/trustcache) 도구를 사용해 정보를 읽기 쉬운 형식으로 확인할 수 있습니다:

```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```

신뢰 캐시는 다음 구조를 따르므로, **LC category는 4번째 열입니다**.

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

그런 다음 [**이 스크립트**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)과 같은 것을 사용해 데이터를 추출할 수 있습니다.

그 데이터를 통해 **launch constraints 값이 `0`인** 앱을 확인할 수 있습니다. 이러한 앱에는 제약이 없습니다(각 값의 의미는 [**여기에서 확인**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)하세요).<sup>[[6]](#references)</sup>

## 공격 완화

Launch Constraints는 **프로세스가 예상치 못한 조건에서 실행되지 않도록 보장함으로써** 과거의 여러 공격을 완화했을 것입니다. 예를 들어 예상치 못한 위치에서 실행되거나, 예상치 못한 부모 프로세스에 의해 호출되는 경우입니다(launchd만 실행해야 하는 경우).

또한 Launch Constraints는 **downgrade 공격도 완화합니다.**

하지만 일반적인 **XPC** 악용, **Electron** 코드 삽입, library validation이 적용되지 않는 **dylib 삽입**은 완화하지 않습니다(라이브러리를 로드할 수 있는 팀 ID를 알고 있는 경우는 제외).<sup>[[3]](#references)</sup>

### XPC Daemon 보호

Sonoma 릴리스에서 주목할 점은 daemon XPC 서비스의 **책임 구성**입니다. 연결하는 클라이언트가 아니라 XPC 서비스가 스스로에 대한 책임을 집니다. 이는 피드백 보고서 FB13206884에 문서화되어 있습니다. 이 설정은 다음과 같은 특정 상호작용을 허용하므로 결함처럼 보일 수 있습니다.

- **XPC Service 실행**: 이를 버그로 가정하더라도, 이 설정에서는 공격자 코드로 XPC 서비스를 시작할 수 없습니다.
- **실행 중인 서비스에 연결**: XPC 서비스가 이미 실행 중이라면(원래 앱에 의해 활성화되었을 수 있음), 해당 서비스에 연결하는 데 아무런 장벽이 없습니다.

XPC 서비스에 제약을 적용하면 **잠재적 공격이 가능한 시간을 줄이는 데** 도움이 될 수 있지만, 핵심 문제를 해결하지는 못합니다. XPC 서비스의 보안을 보장하려면 기본적으로 **연결 클라이언트를 효과적으로 검증해야 합니다**. 이것이 서비스 보안을 강화하는 유일한 방법입니다. 또한 언급한 책임 구성은 현재 동작 중이며, 의도된 설계와 다를 수 있다는 점에 유의해야 합니다.<sup>[[3]](#references)</sup>

### Electron 보호

애플리케이션이 **LaunchService에 의해 열려야 한다**고 요구하더라도(부모 제약에서), **`open`**(환경 변수를 설정할 수 있음)이나 **Launch Services API**(환경 변수를 지정할 수 있음)를 사용하면 이를 충족할 수 있습니다.<sup>[[3]](#references)</sup>

정책별 spawn 속성의 일반적인 MACF 메커니즘은 [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input)를 참조하세요.

### CVE-2025-43253 - spawn 시 기본 제공 제약 재정의

Launch constraints(공식 명칭은 **lightweight code requirements**, *LWCR*)는 **AMFI MAC policy**에 의해 적용됩니다. `posix_spawn`을 사용하면 호출자가 **`posix_spawnattr_setmacpolicyinfo_np()`**를 통해 임의의 blob을 MAC policy에 전달할 수 있으며, AMFI는 이 경로를 통해 호출자가 제공한 LWCR dictionary를 허용했습니다. 문제는 **공격자가 제공한 제약이 바이너리에 기본 제공된 제약에 추가로 검사되는 대신 이를 대체했다는 점**입니다.

- 최소한의(비어 있어도 되는) launch-constraints dictionary를 만듭니다.
- **제약 범주를 `127`로 설정**합니다. 이 값은 AMFI가 spawn 속성에서 허용하지만 **적용하지는 않습니다**. 실행을 차단하는 대신 `Launch Constraint Violation (not enforcing)`만 기록합니다.
- 이를 spawn 속성을 통해 전달하면, 실제 self/parent 제약이 금지했을 컨텍스트에서 프로세스가 실행됩니다.

수정 후에는 기본 제공 제약과 제공된 제약이 **모두** 검증되므로, 제공된 dictionary로 기본 제공 제약을 더 이상 약화할 수 없습니다.<sup>[[2]](#references)</sup>

> [!TIP]
> 제약 적용을 감사할 때 찾아볼 일반적인 패턴은 다음과 같습니다. 신뢰할 수 없는 입력으로 정책을 *제공*할 수 있는 API는 정책 엔진이 제공된 값을 추가 요구 사항이 아니라 대체 값으로 취급할 때 특히 주의해야 합니다.



## References

- [1] [Objective by the Sea #OBTS v6.0 2일 차 (라이브 스트리밍)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS에서 Launch Constraints 우회하기 (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch 및 Environment Constraints 심층 분석 - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [시스템 앱이나 명령줄 도구가 실행되지 않는 이유는? Launch constraints와 trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [환경 제약으로 Mac 앱 보호하기 - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16에 도입된 Launch Constraints 설명 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [기존 LaunchAgents를 넘어 - 자세한 내용은 여기](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
