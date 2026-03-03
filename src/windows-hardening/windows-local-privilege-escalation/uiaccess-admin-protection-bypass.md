# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Übersicht
- Windows AppInfo exponiert `RAiLaunchAdminProcess`, um UIAccess-Prozesse zu starten (gedacht für Accessibility). UIAccess umgeht die meisten User Interface Privilege Isolation (UIPI)-Nachrichtenfilter, sodass Accessibility-Software UI höherer IL steuern kann.
- UIAccess direkt zu aktivieren erfordert `NtSetInformationToken(TokenUIAccess)` mit **SeTcbPrivilege**, daher verlassen sich niedrig-privilegierte Aufrufer auf den Dienst. Der Dienst führt drei Prüfungen an der Ziel-Binärdatei durch, bevor UIAccess gesetzt wird:
- Eingebettetes Manifest enthält `uiAccess="true"`.
- Signiert von einem Zertifikat, dem der Local Machine root store vertraut (kein EKU/Microsoft-Erfordernis).
- Befindet sich in einem nur für Administratoren zugänglichen Pfad auf dem Systemlaufwerk (z. B. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, mit Ausnahme bestimmter beschreibbarer Unterpfade).
- `RAiLaunchAdminProcess` zeigt bei UIAccess-Starts keinen Consent-Prompt an (ansonsten könnte Accessibility-Tooling das Prompt nicht steuern).

## Token shaping und Integrity Levels
- Wenn die Prüfungen erfolgreich sind, **kopiert AppInfo den Aufrufer-Token**, aktiviert UIAccess und erhöht das Integrity Level (IL):
- Limited admin user (Benutzer ist in Administrators, läuft aber gefiltert) ➜ **High IL**.
- Non-admin user ➜ IL um **+16 Levels** erhöht bis zu einer **High**-Obergrenze (System IL wird nie vergeben).
- Wenn der Aufrufer-Token bereits UIAccess hat, bleibt das IL unverändert.
- „Ratchet“-Trick: ein UIAccess-Prozess kann UIAccess für sich selbst deaktivieren, sich über `RAiLaunchAdminProcess` neu starten und einen weiteren +16 IL-Increment erhalten. Medium➜High benötigt 255 Relaunches (laut, aber möglich).

## Warum UIAccess eine Admin-Protection-Umgehung ermöglicht
- UIAccess erlaubt einem Prozess mit niedrigerem IL, Window-Nachrichten an Fenster mit höherem IL zu senden (UIPI-Filter umgehen). Bei **gleichem IL** erlauben klassische UI-Primitiven wie `SetWindowsHookEx` **Code-Injektion/DLL-Laden** in jeden Prozess, der ein Fenster besitzt (einschließlich **message-only windows**, die von COM genutzt werden).
- Admin Protection startet den UIAccess-Prozess unter der Identität des **limited user**, aber mit **High IL**, stillschweigend. Sobald beliebiger Code in diesem High-IL UIAccess-Prozess ausgeführt wird, kann der Angreifer in andere High-IL Prozesse auf dem Desktop injizieren (sogar solche anderer Benutzer) und die beabsichtigte Trennung aufheben.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Ab Windows 10 1803+ wurde die API in Win32k verlagert (`NtUserGetWindowProcessHandle`) und kann ein Prozesshandle mit einem vom Aufrufer gelieferten `DesiredAccess` öffnen. Der Kernel-Pfad nutzt `ObOpenObjectByPointer(..., KernelMode, ...)`, was normale User-Mode-Zugriffsprüfungen umgeht.
- Praxis-Voraussetzungen: das Ziel-Fenster muss sich auf demselben Desktop befinden, und UIPI-Prüfungen müssen bestehen. Historisch konnte ein Aufrufer mit UIAccess UIPI-Fehler umgehen und trotzdem ein Kernel-Mode-Handle erhalten (gefixt als CVE-2023-41772).
- Auswirkung: ein Window-Handle wird zur **Capability**, ein mächtiges Prozess-Handle zu erhalten (typischerweise `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), das der Aufrufer normalerweise nicht öffnen könnte. Das ermöglicht Cross-Sandbox-Zugriffe und kann Protected Process / PPL-Grenzen brechen, wenn das Ziel irgendein Fenster exponiert (einschließlich message-only windows).
- Praktischer Missbrauchsablauf: HWNDs enumerieren oder finden (z. B. `EnumWindows`/`FindWindowEx`), die zugehörige PID ermitteln (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` aufrufen und das zurückgegebene Handle für Memory read/write oder Code-Hijack-Primitiven nutzen.
- Nach dem Fix: UIAccess gewährt keine Kernel-Mode-Opens mehr bei UIPI-Fehlern und erlaubte Zugriffsrechte sind auf das Legacy-Hook-Set beschränkt; Windows 11 24H2 fügt Prozess-Schutz-Prüfungen und feature-geflagte sicherere Pfade hinzu. Das systemweite Deaktivieren von UIPI (`EnforceUIPI=0`) schwächt diese Schutzmaßnahmen.

## Schwächen der Secure-directory-Validierung (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo löst den angegebenen Pfad über `GetFinalPathNameByHandle` auf und wendet dann **string allow/deny checks** gegen hartkodierte Wurzeln/Ausschlüsse an. Mehrere Bypass-Klassen resultieren aus dieser simplen Validierung:
- **Directory named streams**: Ausgeschlossene beschreibbare Verzeichnisse (z. B. `C:\Windows\tracing`) können mit einem Named Stream auf dem Verzeichnis selbst umgangen werden, z. B. `C:\Windows\tracing:file.exe`. Die String-Checks sehen `C:\Windows\` und übersehen den ausgeschlossenen Unterpfad.
- **Beschreibbare Datei/Verzeichnis innerhalb einer erlaubten Root**: `CreateProcessAsUser` erfordert **nicht** zwingend eine `.exe`-Erweiterung. Das Überschreiben irgendeiner beschreibbaren Datei unter einer erlaubten Root mit einem ausführbaren Payload funktioniert, oder das Kopieren einer signierten `uiAccess="true"` EXE in ein beschreibbares Unterverzeichnis (z. B. Update-Leftovers wie `Tasks_Migrated`, wenn vorhanden) lässt die Secure-Path-Prüfung passieren.
- **MSIX in `C:\Program Files\WindowsApps` (gefixt)**: Non-Admins konnten signierte MSIX-Pakete installieren, die in `WindowsApps` landeten, welches nicht ausgeschlossen war. Ein UIAccess-Binary in der MSIX zu verpacken und es dann via `RAiLaunchAdminProcess` zu starten, ergab einen **promptlosen High-IL UIAccess-Prozess**. Microsoft hat dies mitigiert, indem dieser Pfad ausgeschlossen wurde; die `uiAccess`-beschränkte MSIX-Fähigkeit selbst erfordert bereits Admin-Rechte für die Installation.

## Attack-Workflow (High IL ohne Prompt)
1. Eine **signierte UIAccess-Binärdatei** beschaffen/erstellen (Manifest `uiAccess="true"`).
2. Diese dort ablegen, wo AppInfo’s Allowlist sie akzeptiert (oder einen Pfad-Validierungs-Edge-Case/beschreibbares Artefakt wie oben ausnutzen).
3. `RAiLaunchAdminProcess` aufrufen, um sie **stillschweigend** mit UIAccess + erhöhtem IL zu starten.
4. Von diesem High-IL-Fuß in ein anderes High-IL-Prozess auf dem Desktop zielen, mithilfe von **window hooks/DLL injection** oder anderen Same-IL-Primitiven, um den Admin-Kontext vollständig zu kompromittieren.

## Auflisten potenzieller beschreibbarer Pfade
Führe das PowerShell-Helper-Skript aus, um aus Sicht eines gewählten Tokens beschreibbare/überschreibbare Objekte innerhalb nominell sicherer Roots zu entdecken:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Als Administrator ausführen für bessere Sichtbarkeit; `-ProcessId` auf einen low-priv Prozess setzen, um den Zugriff des Tokens zu spiegeln.
- Manuell filtern, um bekannte, nicht erlaubte Unterverzeichnisse auszuschließen, bevor Kandidaten mit `RAiLaunchAdminProcess` verwendet werden.

## Referenzen
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
