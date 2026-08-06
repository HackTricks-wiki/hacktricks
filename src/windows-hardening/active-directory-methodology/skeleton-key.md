# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

O **Skeleton Key attack** é uma técnica que permite aos atacantes **bypassar a autenticação do Active Directory** ao **injetar uma senha mestra** no processo LSASS de cada controlador de domínio. Após a injeção, a senha mestra (por padrão, **`mimikatz`**) pode ser usada para autenticar como **qualquer usuário do domínio**, enquanto as senhas reais continuam funcionando.<sup>[[1]](#references)[[2]](#references)</sup>

Principais fatos:

- Requer **Domain Admin/SYSTEM + SeDebugPrivilege** em cada DC e precisa ser **reaplicado após cada reinicialização**.<sup>[[2]](#references)</sup>
- Corrige os caminhos de validação **NTLM** e **Kerberos RC4 (etype 0x17)**; realms somente com AES ou contas que exigem AES **não aceitarão o skeleton key**.<sup>[[2]](#references)</sup>
- Pode entrar em conflito com pacotes de autenticação LSA de terceiros ou com provedores adicionais de smart card / MFA.<sup>[[2]](#references)</sup>
- O módulo do Mimikatz aceita o switch opcional `/letaes` para evitar tocar nos hooks do Kerberos/AES em caso de problemas de compatibilidade.<sup>[[3]](#references)</sup>

### Execução

LSASS clássico, não protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se o **LSASS estiver sendo executado como PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), será necessário um driver de kernel para remover a proteção antes de aplicar o patch no LSASS:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Após a injeção, autentique-se com qualquer conta de domínio, mas use a senha `mimikatz` (ou o valor definido pelo operador). Lembre-se de repetir em **todos os DCs** em ambientes com múltiplos DCs.

## Mitigações

- **Monitoramento de logs**
- **Event ID 7045** do sistema (instalação de serviço/driver) para drivers não assinados, como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (carregamento de driver) para `mimidrv.sys`; Event ID 10 para acesso suspeito a `lsass.exe` a partir de processos que não sejam do sistema.
- **Event ID 4673/4611** de segurança para uso de privilégios sensíveis ou anomalias no registro de pacotes de autenticação LSA; correlacione com logons 4624 inesperados usando RC4 (etype 0x17) a partir dos DCs.
- **Hardening do LSASS**
- Mantenha **RunAsPPL/Credential Guard/Secure LSASS** habilitados nos DCs para forçar os atacantes a realizar a implantação de drivers em modo kernel (mais telemetria e exploração mais difícil).
- Desabilite o **RC4** legado sempre que possível; tickets Kerberos limitados a AES impedem o caminho de hook RC4 usado pelo skeleton key.<sup>[[2]](#references)</sup>
- Buscas rápidas no PowerShell:
- Detectar instalações de drivers de kernel não assinados: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Procurar pelo driver do Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validar se o PPL está sendo aplicado após a reinicialização: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para obter orientações adicionais sobre hardening de credenciais, consulte [proteções de credenciais do Windows](../stealing-credentials/credentials-protections.md).

## Referências

- [1] [Netwrix – ataque Skeleton Key no Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – módulo misc::skeleton do Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
