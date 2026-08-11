# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

A **Skeleton Key attack** é uma técnica que permite que atacantes **contornem a autenticação do Active Directory** ao **injetar uma senha mestra** no processo LSASS de cada controlador de domínio. Após a injeção, a senha mestra (por padrão, **`mimikatz`**) pode ser usada para autenticar como **qualquer usuário do domínio**, enquanto as senhas reais continuam funcionando.<sup>[[1]](#references)[[2]](#references)</sup>

Fatos importantes:

- Requer **Domain Admin/SYSTEM + SeDebugPrivilege** em cada DC e precisa ser **reaplicado após cada reinicialização**.<sup>[[2]](#references)</sup>
- A implementação clássica do Mimikatz aplica patches nos caminhos de validação do **NTLM** e do **Kerberos RC4 (etype 0x17)**; a autenticação somente com AES **não aceita essa senha skeleton por meio do hook RC4**.<sup>[[2]](#references)</sup>
- Pode entrar em conflito com pacotes de autenticação LSA de terceiros ou com provedores adicionais de smart card / MFA.<sup>[[2]](#references)</sup>
- O módulo do Mimikatz aceita o switch opcional `/letaes` para evitar modificar os hooks do Kerberos/AES em caso de problemas de compatibilidade.<sup>[[3]](#references)</sup>

### Execution

LSASS clássico, não protegido por PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se o **LSASS estiver sendo executado como um protected process light (PPL)**, o acesso de depuração no user-mode será bloqueado. O procedimento histórico do Mimikatz abaixo carrega seu driver de kernel e remove a proteção antes de aplicar um patch no LSASS. Credential Guard é um controle de isolamento separado e não deve ser usado como sinônimo de PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Após a injeção, autentique-se com qualquer conta do domínio, mas use a senha `mimikatz` (ou o valor definido pelo operador). Lembre-se de repetir em **todos os DCs** em ambientes com vários DCs.

## Mitigações

- **Monitoramento de logs**
- **Event ID 7045** do sistema (instalação de serviço/driver) para drivers não assinados, como `mimidrv.sys`.
- **Sysmon**: Event ID 7 (carregamento de driver) para `mimidrv.sys`; Event ID 10 para acesso suspeito a `lsass.exe` por processos que não sejam do sistema.
- **Event ID 4673/4611** de segurança para uso de privilégios sensíveis ou anomalias no registro de pacotes de autenticação LSA; correlacione com logons 4624 inesperados usando RC4 (etype 0x17) provenientes de DCs.
- **Hardening do LSASS**
- Mantenha **RunAsPPL** e **Credential Guard** habilitados quando houver suporte. Eles oferecem proteções diferentes e, juntos, aumentam o custo e a telemetria de tentativas de modificar ou extrair secrets do LSASS.<sup>[[4]](#references)</sup>
- Desabilite o **RC4** legado quando possível; tickets Kerberos limitados a AES impedem o caminho de hook RC4 usado pelo skeleton key.<sup>[[2]](#references)</sup>
- Hunts rápidos em PowerShell:
- Detectar instalações de drivers de kernel não assinados: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Procurar o driver do Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validar se o PPL está sendo aplicado após a reinicialização: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Para obter orientações adicionais sobre hardening de credenciais, consulte [Proteções de credenciais do Windows](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Ataque Skeleton Key no Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Módulo misc::skeleton do Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configurar proteção LSA adicional](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
