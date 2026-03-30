# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Übersicht
- Windows AppInfo stellt `RAiLaunchAdminProcess` bereit, um UIAccess-Prozesse zu starten (für Barrierefreiheitssoftware gedacht). UIAccess umgeht die meisten User Interface Privilege Isolation (UIPI) Nachrichtensperren, sodass Accessibility-Software UI mit höherem IL steuern kann.
- UIAccess direkt zu aktivieren erfordert `NtSetInformationToken(TokenUIAccess)` mit **SeTcbPrivilege**, daher verlassen sich niedrig privilegierte Aufrufer auf den Service. Der Service führt drei Prüfungen an der Ziel-Binärdatei durch, bevor er UIAccess setzt:
- Eingebettetes Manifest enthält `uiAccess="true"`.
- Signiert mit einem Zertifikat, das vom Local Machine root store vertraut wird (keine EKU/Microsoft-Anforderung).
- Befindet sich in einem nur für Administratoren zugänglichen Pfad auf dem Systemlaufwerk (z. B. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, mit Ausnahme bestimmter beschreibbarer Unterpfade).
- `RAiLaunchAdminProcess` zeigt keine Consent-Eingabeaufforderung für UIAccess-Starts (ansonsten könnte Accessibility-Software die Aufforderung nicht steuern).

## Token shaping und Integrity Levels
- Wenn die Prüfungen erfolgreich sind, kopiert AppInfo das Aufrufer-Token, aktiviert UIAccess und erhöht das Integrity Level (IL):
- Limited admin user (Benutzer ist in Administrators, läuft aber gefiltert) ➜ **High IL**.
- Non-admin user ➜ IL wird um **+16 Levels** erhöht bis zur Obergrenze **High** (System IL wird nie zugewiesen).
- Wenn das Aufrufer-Token bereits UIAccess hat, bleibt das IL unverändert.
- „Ratchet“-Trick: Ein UIAccess-Prozess kann UIAccess für sich selbst deaktivieren, über `RAiLaunchAdminProcess` neu starten und einen weiteren +16 IL-Inkrement gewinnen. Medium➜High benötigt 255 Neustarts (laut, aber funktional).

## Warum UIAccess einen Admin Protection-Escape ermöglicht
- UIAccess erlaubt einem Prozess mit niedrigerem IL, Window-Nachrichten an Fenster mit höherem IL zu senden (umgeht UIPI-Filter). Bei gleichem IL erlauben klassische UI-Primitiven wie `SetWindowsHookEx` tatsächlich Code-Injektion/DLL-Laden in jeden Prozess, der ein Fenster besitzt (einschließlich **message-only windows**, die von COM genutzt werden).
- Admin Protection startet den UIAccess-Prozess unter der Identität des **limited user** aber mit **High IL**, still. Sobald beliebiger Code in diesem High-IL UIAccess-Prozess ausgeführt wird, kann der Angreifer in andere High-IL-Prozesse auf dem Desktop injizieren (selbst wenn sie zu anderen Benutzern gehören) und die beabsichtigte Trennung aufheben.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Auf Windows 10 1803+ wurde die API in Win32k verschoben (`NtUserGetWindowProcessHandle`) und kann einen Prozess-Handle mit einem vom Aufrufer angegebenen `DesiredAccess` öffnen. Der Kernel-Pfad verwendet `ObOpenObjectByPointer(..., KernelMode, ...)`, was normale User-Mode-Zugriffsprüfungen umgeht.
- Praktische Voraussetzungen: Das Ziel-Fenster muss auf demselben Desktop liegen und die UIPI-Prüfungen müssen bestehen. Historisch konnte ein Aufrufer mit UIAccess UIPI-Fehler umgehen und trotzdem ein Kernel-Mode-Handle erhalten (behoben als CVE-2023-41772).
- Auswirkung: Ein Fenster-Handle wird zu einer Fähigkeit, ein mächtiges Prozess-Handle zu erhalten (üblich sind `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), das der Aufrufer normalerweise nicht öffnen könnte. Das ermöglicht Cross-Sandbox-Zugriff und kann Protected Process / PPL-Grenzen brechen, wenn das Ziel irgendein Fenster (einschließlich message-only windows) exponiert.
- Praktischer Missbrauchsablauf: HWNDs aufzählen oder finden (z. B. `EnumWindows`/`FindWindowEx`), die zugehörige PID auflösen (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` aufrufen und dann das zurückgegebene Handle für Memory Read/Write oder Code-Hijack-Primitiven verwenden.
- Nach dem Fix: UIAccess gewährt keine Kernel-Mode-Opens mehr bei UIPI-Fehlern und erlaubte Zugriffsrechte sind auf die Legacy-Hook-Menge beschränkt; Windows 11 24H2 fügt Process-Protection-Prüfungen und feature-flagged sicherere Pfade hinzu. Das globale Deaktivieren von UIPI (`EnforceUIPI=0`) schwächt diese Schutzmaßnahmen.

## Schwächen der Secure-directory-Validierung (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo löst den übergebenen Pfad über `GetFinalPathNameByHandle` auf und wendet dann **String-Allow/Deny-Prüfungen** gegen hardcodierte Wurzeln/Ausschlüsse an. Mehrere Umgehungsklassen resultieren aus dieser simplen Validierung:
- **Directory named streams**: Ausgeschlossene beschreibbare Verzeichnisse (z. B. `C:\Windows\tracing`) können mit einem named stream auf dem Verzeichnis selbst umgangen werden, z. B. `C:\Windows\tracing:file.exe`. Die String-Prüfungen sehen `C:\Windows\` und übersehen den ausgeschlossenen Unterpfad.
- **Beschreibbare Datei/Verzeichnis innerhalb einer erlaubten Wurzel**: `CreateProcessAsUser` erfordert **nicht** die `.exe`-Erweiterung. Das Überschreiben jeder beschreibbaren Datei unter einer erlaubten Wurzel mit einem ausführbaren Payload funktioniert, oder das Kopieren einer signierten `uiAccess="true"` EXE in ein beschreibbares Unterverzeichnis (z. B. Update-Reste wie `Tasks_Migrated`, wenn vorhanden) lässt die Secure-Path-Prüfung passieren.
- **MSIX in `C:\Program Files\WindowsApps` (behoben)**: Nicht-Admins konnten signierte MSIX-Pakete installieren, die in `WindowsApps` landeten, welches nicht ausgeschlossen war. Ein UIAccess-Binary in der MSIX zu verpacken und es dann über `RAiLaunchAdminProcess` zu starten führte zu einem **promptlosen High-IL UIAccess-Prozess**. Microsoft hat dies durch das Ausschließen dieses Pfads behoben; die `uiAccess`-eingeschränkte MSIX-Fähigkeit erfordert ohnehin Admin-Installation.

## Angriffsablauf (High IL ohne Prompt)
1. Eine **signierte UIAccess-Binärdatei** erhalten/erstellen (Manifest `uiAccess="true"`).
2. Diese dort platzieren, wo AppInfo’s Allowlist sie akzeptiert (oder einen Pfad-Validierungs-Edge-Case/beschreibbares Artefakt wie oben ausnutzen).
3. `RAiLaunchAdminProcess` aufrufen, um sie **still** mit UIAccess + erhöhtem IL zu starten.
4. Von diesem High-IL-Fuß in ein anderes High-IL-Programm auf dem Desktop mittels **Window Hooks/DLL-Injektion** oder anderen Same-IL-Primitiven zielen, um den Admin-Kontext vollständig zu kompromittieren.

## Auflisten möglicher beschreibbarer Pfade
Führe das PowerShell-Hilfsprogramm aus, um aus der Perspektive eines gewählten Tokens beschreibbare/überschreibbare Objekte innerhalb nominal sicherer Wurzeln zu entdecken:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Als Administrator ausführen, um größere Sichtbarkeit zu erhalten; setze `-ProcessId` auf einen low-priv Prozess, um den Zugriff dieses Tokens zu spiegeln.
- Manuell filtern, um bekannte nicht erlaubte Unterverzeichnisse auszuschließen, bevor Kandidaten mit `RAiLaunchAdminProcess` verwendet werden.

## Verwandte

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referenzen
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
