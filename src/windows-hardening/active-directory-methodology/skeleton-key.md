# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Die **Skeleton Key attack** ist eine Technik, mit der Angreifer die **Authentifizierung in Active Directory umgehen** können, indem sie ein **Master-Passwort** in den LSASS-Prozess jedes Domain Controllers **injizieren**. Nach der Injektion kann das Master-Passwort (standardmäßig **`mimikatz`**) verwendet werden, um sich als **beliebiger Domain-Benutzer** zu authentifizieren, während dessen echtes Passwort weiterhin funktioniert.<sup>[[1]](#references)[[2]](#references)</sup>

Wichtige Fakten:

- Erfordert **Domain Admin/SYSTEM + SeDebugPrivilege** auf jedem DC und muss **nach jedem Neustart erneut angewendet werden**.<sup>[[2]](#references)</sup>
- Die klassische Mimikatz-Implementierung patcht die Validierungspfade von **NTLM** und **Kerberos RC4 (etype 0x17)**; eine reine AES-Authentifizierung akzeptiert dieses Skeleton-Passwort **nicht über den RC4-Hook**.<sup>[[2]](#references)</sup>
- Kann mit **LSA authentication packages** von Drittanbietern oder zusätzlichen Smartcard-/MFA-Providern in Konflikt geraten.<sup>[[2]](#references)</sup>
- Das Mimikatz-Modul akzeptiert den optionalen Schalter `/letaes`, um bei Kompatibilitätsproblemen Änderungen an Kerberos-/AES-Hooks zu vermeiden.<sup>[[3]](#references)</sup>

### Ausführung

Klassisches, nicht durch **PPL** geschütztes LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Wenn **LSASS als Protected Process Light (PPL)** ausgeführt wird, ist der Debug-Zugriff im User-Modus blockiert. Die historische Mimikatz-Prozedur lädt den Kernel-Treiber und entfernt den Schutz, bevor LSASS gepatcht wird. Credential Guard ist eine separate Isolationskontrolle und sollte nicht als Synonym für PPL verwendet werden.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nach der Injection authentifiziere dich mit einem beliebigen Domänenkonto, verwende jedoch das Passwort `mimikatz` (oder den vom Operator festgelegten Wert). Denke daran, dies in Umgebungen mit mehreren DCs auf **allen DCs** zu wiederholen.

## Gegenmaßnahmen

- **Protokollüberwachung**
- System-**Ereignis-ID 7045** (Installation von Service/Treiber) für nicht signierte Treiber wie `mimidrv.sys`.
- **Sysmon**: Ereignis-ID 7 (Laden von Treibern) für `mimidrv.sys`; Ereignis-ID 10 für verdächtigen Zugriff auf `lsass.exe` durch Nicht-Systemprozesse.
- Security-**Ereignis-ID 4673/4611** für die Verwendung sensibler Berechtigungen oder Anomalien bei der Registrierung von LSA-Authentifizierungspaketen; korreliere dies mit unerwarteten 4624-Anmeldungen unter Verwendung von RC4 (Etype 0x17) von DCs.
- **LSASS härten**
- Aktiviere **RunAsPPL** und **Credential Guard**, sofern unterstützt. Sie bieten unterschiedliche Schutzmechanismen und erhöhen zusammen den Aufwand sowie die Telemetrie bei Versuchen, LSASS-Geheimnisse zu ändern oder zu extrahieren.<sup>[[4]](#references)</sup>
- Deaktiviere **RC4**, sofern möglich; auf AES beschränkte Kerberos-Tickets verhindern den vom skeleton key verwendeten RC4-Hook-Pfad.<sup>[[2]](#references)</sup>
- Schnelle PowerShell-Suchen:
- Nicht signierte Kernel-Treiberinstallationen erkennen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Nach dem Mimikatz-Treiber suchen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Überprüfen, ob PPL nach dem Neustart erzwungen wird: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Weitere Hinweise zur Absicherung von Credentials findest du unter [Schutz von Windows-Credentials](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton-Key-Angriff in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton Key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz-Modul misc::skeleton](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Zusätzlichen LSA-Schutz konfigurieren](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
