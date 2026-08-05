# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS의 Launch constraints는 **프로세스가 어떻게, 누가, 어디에서 시작될 수 있는지 규제**하여 보안을 강화하기 위해 도입되었습니다. macOS Ventura에서 처음 도입된 이 기능은 **각 system binary를 서로 다른 constraint category로 분류**하는 framework를 제공하며, 이러한 category는 system binary와 해당 hash가 포함된 목록인 **trust cache**에 정의됩니다. 이러한 constraints는 system 내 모든 executable binary에 적용되며, **특정 binary를 launch하기 위한 요구 사항**을 정의하는 **rules**를 포함합니다. rules에는 binary가 충족해야 하는 self constraints, parent process가 충족해야 하는 parent constraints, 그리고 기타 관련 entity가 준수해야 하는 responsible constraints가 포함됩니다.

이 mechanism은 macOS Sonoma부터 third-party app에도 **Environment Constraints**를 통해 적용되며, developer는 **environment constraints를 위한 key와 value set**을 지정하여 app을 보호할 수 있습니다.

**launch environment 및 library constraints**는 constraint dictionary에 정의하며, 이를 **`launchd` property list file**에 저장하거나 code signing에 사용하는 **별도의 property list** file에 저장합니다.

constraints에는 4가지 유형이 있습니다:

- **Self Constraints**: **실행 중인** binary에 적용되는 constraints입니다.
- **Parent Process**: **process의 parent**에 적용되는 constraints입니다(예: XP service를 실행하는 **`launchd`**).
- **Responsible Constraints**: XPC communication에서 **service를 호출하는 process**에 적용되는 constraints입니다.
- **Library load constraints**: library load constraints를 사용하여 load할 수 있는 code를 선택적으로 설명합니다.

따라서 process가 `execve(_:_:_:)` 또는 `posix_spawn(_:_:_:_:_:)`을 호출하여 다른 process를 launch하려 하면, operating system은 **executable** file이 자체 **self constraint**를 **충족하는지** 확인합니다. 또한 **parent** **process**의 executable이 해당 executable의 **parent constraint**를 **충족하는지**, 그리고 **responsible** **process**의 executable이 executable의 **responsible process constraint**를 **충족하는지** 확인합니다. 이러한 launch constraints 중 하나라도 충족되지 않으면 operating system은 program을 실행하지 않습니다.

library를 load할 때 **library constraint의 일부라도 충족되지 않으면**, process는 해당 library를 **load하지 않습니다**.

## LC Categories

LC는 **facts**와 facts를 결합하는 **logical operations**(and, or 등)으로 구성됩니다.

LC가 사용할 수 있는 [**facts는 문서화되어 있습니다**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). 예:

- is-init-proc: executable이 operating system의 initialization process(`launchd`)여야 하는지 나타내는 Boolean value입니다.
- is-sip-protected: executable이 System Integrity Protection(SIP)으로 보호되는 file이어야 하는지 나타내는 Boolean value입니다.
- `on-authorized-authapfs-volume:` operating system이 executable을 authorized되고 authenticated된 APFS volume에서 load했는지 나타내는 Boolean value입니다.
- `on-authorized-authapfs-volume`: operating system이 executable을 authorized되고 authenticated된 APFS volume에서 load했는지 나타내는 Boolean value입니다.
- Cryptexes volume
- `on-system-volume:` operating system이 executable을 현재 boot된 system volume에서 load했는지 나타내는 Boolean value입니다.
- /System 내부...
- ...

Apple binary가 sign되면 **trust cache** 내의 LC category에 **할당**됩니다.

- **iOS 16 LC categories**는 [**여기에서 reverse-engineering되고 문서화되었습니다**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- 현재 **LC categories(macOS 14** - Somona)는 reverse-engineering되었으며, [**description은 여기에서 확인할 수 있습니다**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

예를 들어 Category 1은 다음과 같습니다:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System 또는 Cryptexes volume에 있어야 합니다.
- `launch-type == 1`: system service여야 합니다(LaunchDaemons의 plist).
- `validation-category == 1`: 운영 체제 executable입니다.
- `is-init-proc`: Launchd

### LC Categories Reversing

[**여기에서 자세한 내용을 확인할 수 있지만**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), 기본적으로 이는 **AMFI (AppleMobileFileIntegrity)** 에 정의되어 있으므로, Kernel Development Kit을 다운로드하여 **KEXT**를 가져와야 합니다. **`kConstraintCategory`** 로 시작하는 symbol이 **중요한** symbol입니다. 이를 추출하면 DER (ASN.1) encoded stream을 얻게 되며, [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 또는 python-asn1 library와 해당 library의 `dump.py` script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1)를 사용해 decode해야 합니다. 그러면 더 이해하기 쉬운 string을 확인할 수 있습니다.<sup>[3]</sup>

## Environment Constraints

이는 **third party applications**에 설정된 Launch Constraints입니다. 개발자는 application에 사용할 **facts**와 **logical operands**를 선택하여 application 자체에 대한 access를 제한할 수 있습니다.

다음 명령을 사용하면 application의 Environment Constraints를 enumerate할 수 있습니다.
```bash
codesign -d -vvvv app.app
```
## Trust Cache

**macOS**에는 몇 가지 trust cache가 있습니다:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

그리고 iOS에서는 다음 경로에 있는 것으로 보입니다: **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Apple Silicon 장치에서 실행되는 macOS에서는 Apple signed binary가 trust cache에 없을 경우 AMFI가 해당 binary의 로드를 거부합니다.

### Trust Cache 열거

앞서 설명한 trust cache 파일은 **IMG4** 및 **IM4P** 형식이며, IM4P는 IMG4 형식의 payload 섹션입니다.

[**pyimg4**](https://github.com/m1stadev/PyIMG4)를 사용하여 database의 payload를 추출할 수 있습니다:
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
(또 다른 방법으로는 [**img4tool**](https://github.com/tihmstar/img4tool)을 사용하는 것입니다. 이 도구는 릴리스가 오래되었더라도 M1에서 실행되며, x86_64의 경우 올바른 위치에 설치하면 실행됩니다.)

이제 [**trustcache**](https://github.com/CRKatri/trustcache) 도구를 사용하여 정보를 읽기 쉬운 형식으로 확인할 수 있습니다:
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
trust cache는 다음 구조를 따르므로, **LC category는 4번째 열입니다**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
그런 다음 [**이 스크립트**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)와 같은 것을 사용하여 데이터를 추출할 수 있습니다.

해당 데이터에서 **launch constraints 값이 `0`인** App을 확인할 수 있으며, 이러한 App은 제약이 적용되지 않은 App입니다(각 값의 의미는 [**여기에서 확인**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)할 수 있습니다).<sup>[6]</sup>

## 공격 완화

Launch Constraints는 **프로세스가 예상하지 못한 조건에서 실행되지 않도록 보장함으로써** 여러 오래된 공격을 완화했을 것입니다. 예를 들어 예상하지 못한 위치에서 실행되거나, 예상하지 못한 부모 프로세스에 의해 호출되는 경우입니다(launchd만 해당 프로세스를 실행해야 하는 경우).

또한 Launch Constraints는 **downgrade attacks도 완화합니다.**

그러나 일반적인 **XPC** abuse, **Electron** code injections 또는 library validation이 없는 **dylib injections**은 완화하지 못합니다(라이브러리를 로드할 수 있는 team IDs를 알고 있는 경우는 제외).<sup>[3]</sup>

### XPC Daemon Protection

Sonoma release에서 주목할 만한 점은 daemon XPC service의 **responsibility configuration**입니다. 연결하는 client가 책임지는 것이 아니라 XPC service 자체가 책임을 집니다. 이는 feedback report FB13206884에 문서화되어 있습니다. 이 설정은 XPC service와의 특정 상호작용을 허용하므로 문제가 있어 보일 수 있습니다.

- **XPC Service 실행**: 버그라고 가정하더라도 이 설정은 attacker code를 통해 XPC service를 시작하는 것을 허용하지 않습니다.
- **활성 Service에 연결**: XPC service가 이미 실행 중인 경우(원래 application에 의해 활성화되었을 가능성이 있음), 해당 service에 연결하는 데 아무런 장벽이 없습니다.

XPC service에 constraints를 적용하면 **잠재적인 공격이 가능한 window를 좁히는 데** 도움이 될 수 있지만, primary concern을 해결하지는 못합니다. XPC service의 security를 보장하려면 근본적으로 **연결하는 client를 효과적으로 검증해야 합니다**. 이것이 service의 security를 강화할 수 있는 유일한 방법입니다. 또한 앞서 언급한 responsibility configuration은 현재 동작 중이며, 이는 의도된 design과 일치하지 않을 수 있다는 점도 유의해야 합니다.<sup>[3]</sup>

### Electron Protection

application이 **LaunchService에 의해 열려야 한다**고 요구하더라도(부모 constraints에서), 이는 env variables를 설정할 수 있는 **`open`**을 사용하거나 env variables를 지정할 수 있는 **Launch Services API**를 사용하여 달성할 수 있습니다.<sup>[3]</sup>

### CVE-2025-43253 - spawn time에 built-in constraints 재정의

Launch constraints(공식적으로 **lightweight code requirements**, *LWCR*)는 **AMFI MAC policy**에 의해 적용됩니다. `posix_spawn`은 caller가 **`posix_spawnattr_setmacpolicyinfo_np()`**를 통해 임의의 blob을 MAC policy에 전달할 수 있도록 하며, AMFI는 해당 경로를 통해 caller가 제공한 LWCR dictionary를 수락했습니다. 이 bug는 **attacker가 제공한 constraints가 binary의 built-in constraints에 추가로 검사되는 대신 이를 대체했다는 것**입니다.

- 최소한의(심지어 비어 있는) launch-constraints dictionary를 생성합니다.
- **constraint category를 `127`로 설정합니다.** 이 값은 AMFI가 spawn attributes에서는 허용하지만 **enforce하지는 않으므로**, execution을 차단하는 대신 `Launch Constraint Violation (not enforcing)`만 기록합니다.
- 이를 spawn attributes를 통해 전달하면, 실제 self/parent constraints가 금지했을 context에서 process가 실행됩니다.

수정 후에는 **built-in constraints와 제공된 constraints가 모두 검증**되므로, 제공된 dictionary로 built-in constraint를 더 이상 약화시킬 수 없습니다.<sup>[2]</sup>

> [!TIP]
> constraint enforcement를 audit할 때 찾아야 할 일반적인 형태는 다음과 같습니다. 신뢰할 수 없는 input이 policy를 *supply*할 수 있도록 허용하는 API는, policy engine이 제공된 값을 추가 requirement가 아닌 replacement로 처리할 때 흥미로운 대상이 되는 경향이 있습니다.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
