# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDM 악용

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

관리 플랫폼에 접근할 수 있는 **관리자 자격 증명을 탈취**하면, 컴퓨터에 malware를 배포해 **모든 컴퓨터를 잠재적으로 침해할 수 있습니다**.

MacOS 환경에서 Red Teaming을 수행하려면 MDM이 작동하는 방식을 어느 정도 이해하는 것이 좋습니다:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM을 C2로 사용

MDM은 프로파일을 설치, 조회 또는 제거하고, 애플리케이션을 설치하고, 로컬 관리자 계정을 생성하고, 펌웨어 암호를 설정하고, FileVault 키를 변경할 수 있는 권한을 갖습니다...

직접 MDM을 운영하려면 **벤더가 서명한 CSR**이 필요합니다. [**https://mdmcert.download/**](https://mdmcert.download/)에서 발급받을 수 있는지 시도해 볼 수 있습니다. Apple 기기용 MDM을 직접 운영하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

MDM 등록만으로 관리 서버의 TLS 인증서가 신뢰할 수 있는 CA 인증서가 되거나 앱 서명 ID가 부여되는 것은 아닙니다. 서버가 사설 CA를 사용하는 경우 해당 CA의 루트 및 중간 인증서를 등록 프로파일이나 별도의 신뢰 프로파일에 포함해야 합니다. MDM 인증에 사용되는 클라이언트 ID는 별도의 인증서입니다.<sup>[[7]](#references)</sup>

다운로드한 MDM 등록 프로파일(`.mobileconfig`)은 **시스템 설정 → 일반 → 기기 관리**에서 열고 승인해야 합니다. 루트 권한으로 설치된 `.pkg`에 넣거나 Safari에서 연 ZIP에 포함하는 것만으로는 최신 Mac이 자동으로 등록되지 않습니다. [구성 프로파일 동작](../macos-auto-start-locations.md#configuration-profiles-mobileconfig)을 참고하세요.<sup>[[8]](#references)</sup>

Setup Assistant 중 수행되는 자동 기기 등록은 별도의 절차입니다. 필요한 조건이 다르므로 [다른 조직의 기기 불법 등록](macos-mdm/enrolling-devices-in-other-organisations.md)을 참고하세요.<sup>[[9]](#references)</sup>

**Mythic agent Orthrus**는 이 기법을 사용합니다.

### 관리 권한이 있는 MDM을 통한 패키지 배포

**macOS 26 이상을 실행하는 감독 대상 Mac**에서는 MDM 서비스를 제어할 수 있으면 시스템 범위에서 `com.apple.configuration.package` 선언을 사용할 수 있습니다.<sup>[[10]](#references)</sup> 패키지에는 기기가 검증할 수 있는 서명이 있어야 하지만, 앱에 별도의 Developer ID 서명이 필요하지는 않습니다. 기기 관리로 설치된 앱은 Gatekeeper가 검사하지 않습니다.<sup>[[11]](#references)</sup> 신뢰할 수 있는 서버 TLS 인증서만으로는 운영자에게 해당 패키지 서명에 필요한 개인 키나 서명 용도가 부여되지 않습니다.<sup>[[11]](#references)[[12]](#references)</sup>

서명된 테스트 패키지를 빌드하고 digest를 계산한 다음, 패키지와 `ManifestURL` plist를 HTTPS로 게시합니다. 매니페스트에는 URL과 SHA-256이 포함된 `software-package` asset 하나와 고유한 `bundle-identifier` 및 `bundle-version`이 필요합니다.<sup>[[11]](#references)</sup> 그런 다음 해당 매니페스트 URL을 지정하고 `InstallBehavior.Install`을 `Required`로 설정한 패키지 선언을 전송합니다. 설치 여부나 오류는 `package.list` 상태 항목에서 확인합니다.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

MDM 서비스를 통해 제출되는 최소 필수 설치 선언은 다음과 같습니다(URL과 두 UUID를 대체하세요).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### JAMF PRO 악용

JAMF는 **사용자 지정 스크립트**(시스템 관리자가 개발한 스크립트), **네이티브 페이로드**(로컬 계정 생성, EFI 암호 설정, 파일/프로세스 모니터링...) 및 **MDM**(기기 구성, 기기 인증서...)을 실행할 수 있습니다.<sup>[[5]](#references)</sup>

#### JAMF 자체 등록

`https://<company-name>.jamfcloud.com/enroll/` 같은 페이지로 이동하여 **자체 등록이 활성화되어 있는지** 확인하세요. 자체 등록이 활성화되어 있으면 **접속을 위해 인증 정보를 요구할 수 있습니다**.

스크립트 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)를 사용하여 password spraying 공격을 수행할 수 있습니다.

또한 유효한 인증 정보를 찾은 후에는 다음 양식을 사용해 다른 사용자 이름을 brute-force할 수 있습니다.

![JAMF PRO 악용 - JAMF 자체 등록: 또한 유효한 인증 정보를 찾은 후에는 다음 양식을 사용해 다른 사용자 이름을 brute-force할 수 있습니다](<../../images/image (107).png>)

#### JAMF 기기 인증

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 바이너리에는 키체인을 여는 데 사용되는 비밀 값이 포함되어 있었으며, 발견 당시 이 값은 모두가 **공유**하고 있었습니다. 해당 값은 **`jk23ucnq91jfu9aj`**였습니다.<sup>[[5]](#references)</sup>\
또한 jamf는 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에 있는 **LaunchDaemon**으로 persist합니다.

#### JAMF 기기 탈취

**`jamf`**가 사용할 **JSS**(Jamf Software Server) **URL**은 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 있습니다.\
이 파일에는 기본적으로 URL이 포함되어 있습니다:

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://subdomain-company.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```

따라서 공격자는 악성 패키지(`pkg`)를 배포해 설치 시 **이 파일을 덮어쓰고**, **Typhon agent가 사용할 Mythic C2 listener의 URL을 설정함으로써** JAMF를 C2로 악용할 수 있습니다.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF 사칭

기기와 JMF 간의 **통신을 사칭**하려면 다음이 필요합니다.

- 기기의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- 기기 인증서가 들어 있는 **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`

이 정보를 사용해 **탈취한** 하드웨어 **UUID**를 사용하고 **SIP가 비활성화된** VM을 **만든** 다음, **JAMF keychain**을 복사하고 Jamf **agent**에 **hook**을 설치해 정보를 탈취합니다.

#### Secrets 탈취

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

관리자가 Jamf를 통해 실행하려는 **사용자 지정 스크립트**가 `/Library/Application Support/Jamf/tmp/`에 배치된 후 실행되고 삭제되므로, 이 경로를 모니터링할 수도 있습니다. 이러한 스크립트에 **자격 증명**이 포함되어 있을 수 있습니다.

그러나 **자격 증명**이 스크립트에 **매개변수**로 전달될 수도 있으므로, `ps aux | grep -i jamf`를 모니터링해야 합니다(root 권한 없이도 가능합니다).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 스크립트는 새 파일이 추가되거나 새 프로세스 인수가 전달될 때 이를 감지할 수 있습니다.

### macOS 원격 액세스

또한 **MacOS**의 "특수한" **네트워크** **프로토콜**도 살펴보세요.


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

경우에 따라 **MacOS 컴퓨터가 AD에 연결되어 있는 것을 발견할 수 있습니다**. 이 경우 평소 하던 방식으로 Active Directory를 **열거**해 보세요. 다음 페이지에서 **도움말**을 확인할 수 있습니다.


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

도움이 될 수 있는 **로컬 MacOS 도구**로 `dscl`도 있습니다:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

또한 MacOS에서 AD를 자동으로 열거하고 kerberos를 다룰 수 있도록 준비된 도구도 있습니다.

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 MacOS 호스트에서 Active Directory 관계를 수집하고 가져올 수 있도록 Bloodhound auditing 도구를 확장한 도구입니다.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호작용하도록 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 대상에 다른 프레임워크나 패키지를 설치할 필요 없이 네이티브 API를 사용해 macOS 기기에서 Kerberos 보안 테스트를 더 효과적으로 수행하는 것입니다.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory 열거를 수행하는 JavaScript for Automation (JXA) 도구입니다.

### 도메인 정보

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### 사용자

MacOS 사용자 유형은 다음 세 가지입니다.

- **Local Users** — 로컬 OpenDirectory 서비스에서 관리되며, Active Directory와 어떤 방식으로도 연결되어 있지 않습니다.
- **Network Users** — 인증하려면 DC 서버에 연결해야 하는 휘발성 Active Directory 사용자입니다.
- **Mobile Users** — 자격 증명과 파일을 로컬에 백업해 둔 Active Directory 사용자입니다.

사용자와 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default._ 폴더에 저장됩니다.\
예를 들어, _mark_라는 사용자의 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되고, _admin_ 그룹의 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 저장됩니다.

HasSession 및 AdminTo 엣지 외에도 **MacHound는 Bloodhound 데이터베이스에 세 가지 새로운 엣지를 추가합니다**:<sup>[[2]](#references)</sup>

- **CanSSH** - 호스트에 SSH 접속할 수 있는 엔터티
- **CanVNC** - 호스트에 VNC 접속할 수 있는 엔터티
- **CanAE** - 호스트에서 AppleEvent 스크립트를 실행할 수 있는 엔터티

```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```

자세한 내용은 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ 비밀번호

다음 명령어를 사용해 비밀번호를 가져옵니다:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

System 키체인에서 **`Computer$`** 암호에 접근할 수 있습니다.

### Over-Pass-The-Hash

특정 사용자 및 서비스의 TGT를 가져옵니다:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

TGT를 수집한 후에는 다음을 사용해 현재 세션에 inject할 수 있습니다:

```bash
bifrost --action asktgt --username test_lab_admin \
       --hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
       --enctype aes256 --domain test.lab.local
```

### Kerberoasting

```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
       --username [user] --hash [hash] --enctype [enctype]
```

획득한 서비스 티켓으로 다른 컴퓨터의 공유에 접근을 시도할 수 있습니다:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Keychain에 액세스하기

Keychain에는 민감한 정보가 들어 있을 가능성이 매우 높습니다. 프롬프트를 표시하지 않고 이에 액세스할 수 있다면 red team exercise를 진행하는 데 도움이 될 수 있습니다:


{{#ref}}
macos-keychain.md
{{#endref}}

## 외부 서비스

MacOS Red Teaming은 일반적인 Windows Red Teaming과 다릅니다. 보통 **MacOS는 여러 외부 플랫폼과 직접 통합되어 있기 때문입니다**. MacOS의 일반적인 구성은 **OneLogin 동기화 자격 증명으로 컴퓨터에 액세스하고, OneLogin을 통해** github, aws 등의 여러 외부 서비스에 액세스하는 것입니다.

## 기타 Red Team 기법

### Safari

Safari에서 파일을 다운로드할 때 "안전한" 파일이면 **자동으로 열립니다**. 예를 들어 **zip 파일을 다운로드하면** 자동으로 압축이 풀립니다:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Apple 따기: 2021년 MacOS 환경 Red Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHound 소개: macOS Active Directory 기반 공격을 위한 솔루션](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - 도메인 열거 명령어 (dscl / net / ldapsearch에 해당)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [어둠의 편으로 오세요. 사과가 있습니다: macOS 관리를 악용하기](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Jamf 구성에 대한 공격자 관점" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Mac을 사용한 Active Directory 검색 - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — 기기 관리 서비스 및 기기의 인증서 관리](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Mac에서 구성 프로파일 사용하기](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — 기기 관리 등록 프로파일 배포하기](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — 패키지 선언](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — 패키지 설치](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — ID](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
