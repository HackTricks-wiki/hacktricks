# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Überblick
- Windows AppInfo stellt `RAiLaunchAdminProcess` bereit, um UIAccess-Prozesse zu starten (vorgesehen für Accessibility). UIAccess umgeht die meisten User Interface Privilege Isolation (UIPI) Message-Filter, sodass Accessibility-Software UI mit höherem IL ansteuern kann.
- UIAccess direkt zu aktivieren erfordert `NtSetInformationToken(TokenUIAccess)` mit **SeTcbPrivilege**, daher verlassen sich niedrig-privilegierte Aufrufer auf den Dienst. Der Dienst führt drei Prüfungen an der Ziel-Binärdatei durch, bevor UIAccess gesetzt wird:
- Eingebettetes Manifest enthält `uiAccess="true"`.
- Signiert von einem Zertifikat, das vom Local Machine Root-Store vertraut wird (keine EKU/Microsoft-Anforderung).
- Befindet sich in einem nur für Administratoren zugänglichen Pfad auf dem Systemlaufwerk (z. B. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, ausgenommen spezifische beschreibbare Unterpfade).
- `RAiLaunchAdminProcess` zeigt keinen Consent Prompt für UIAccess-Starts an (ansonsten könnten Accessibility-Tools die Aufforderung nicht ansteuern).

## Token shaping und Integrity Levels
- Wenn die Prüfungen bestehen, **kopiert** AppInfo das Caller-Token, aktiviert UIAccess und erhöht das Integrity Level (IL):
- Limited admin user (User ist in Administrators, läuft aber gefiltert) ➜ **High IL**.
- Non-admin user ➜ IL wird um **+16 levels** erhöht bis zu einer **High**-Obergrenze (System IL wird nie vergeben).
- Falls das Caller-Token bereits UIAccess hat, bleibt das IL unverändert.
- Ratchet trick: ein UIAccess-Prozess kann UIAccess für sich selbst deaktivieren, via `RAiLaunchAdminProcess` neu starten und einen weiteren +16 IL-Inkrement gewinnen. Medium➜High erfordert 255 Neustarts (laut, aber möglich).

## Warum UIAccess eine Admin Protection-Umgehung ermöglicht
- UIAccess erlaubt einem Prozess mit geringerem IL, Window-Messages an Fenster mit höherem IL zu senden (umgeht UIPI-Filter). Bei **gleichem IL** erlauben klassische UI-Primitiven wie `SetWindowsHookEx` **Code-Injection/DLL-Loading** in jeden Prozess, der ein Fenster besitzt (einschließlich **message-only windows**, die von COM benutzt werden).
- Admin Protection startet den UIAccess-Prozess unter der **Identität des eingeschränkten Benutzers**, jedoch mit **High IL**, stillschweigend. Sobald beliebiger Code in diesem High-IL UIAccess-Prozess ausgeführt wird, kann ein Angreifer in andere High-IL-Prozesse auf dem Desktop injizieren (auch von anderen Benutzern), wodurch die beabsichtigte Isolation gebrochen wird.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Auf Windows 10 1803+ wurde die API in Win32k verschoben (`NtUserGetWindowProcessHandle`) und kann ein Process-Handle mit einem vom Aufrufer angegebenen `DesiredAccess` öffnen. Der Kernel-Pfad nutzt `ObOpenObjectByPointer(..., KernelMode, ...)`, was normale User-Mode-Zugriffsprüfungen umgeht.
- Praktische Voraussetzungen: das Ziel-Fenster muss auf demselben Desktop liegen und UIPI-Prüfungen müssen passieren. Historisch konnte ein Caller mit UIAccess UIPI-Fehler umgehen und trotzdem ein Kernel-Mode-Handle erhalten (gefunden als CVE-2023-41772).
- Auswirkung: ein Window-Handle wird zu einer **Capability**, um ein mächtiges Process-Handle zu erhalten (häufig `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), das der Aufrufer normalerweise nicht öffnen könnte. Das ermöglicht Cross-Sandbox-Zugriff und kann Protected Process / PPL-Grenzen brechen, sofern das Ziel irgendein Fenster (inkl. message-only windows) exponiert.
- Praktischer Missbrauchsablauf: HWNDs aufzählen oder finden (z. B. `EnumWindows`/`FindWindowEx`), den zugehörigen PID ermitteln (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` aufrufen und das zurückgegebene Handle für Memory read/write oder Code-Hijack-Primitiven verwenden.
- Post-fix Verhalten: UIAccess gewährt keine Kernel-Mode-Opens mehr bei UIPI-Fehlern und die erlaubten Zugriffsrechte sind auf das legacy hook-Set beschränkt; Windows 11 24H2 fügt Process-Protection-Prüfungen und feature-flagged sicherere Pfade hinzu. Das systemweite Deaktivieren von UIPI (`EnforceUIPI=0`) schwächt diese Schutzmechanismen.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolved den übergebenen Pfad via `GetFinalPathNameByHandle` und wendet dann **string allow/deny checks** gegen hartkodierte Roots/Ausschlüsse an. Mehrere Umgehungsklassen resultieren aus dieser simplen Validierung:
- **Directory named streams**: Ausgeschlossene beschreibbare Verzeichnisse (z. B. `C:\Windows\tracing`) können mit einem Named Stream auf dem Verzeichnis selbst umgangen werden, z. B. `C:\Windows\tracing:file.exe`. Die String-Checks sehen `C:\Windows\` und verpassen den ausgeschlossenen Unterpfad.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` erfordert **nicht** zwingend eine `.exe`-Extension. Das Überschreiben einer beliebigen beschreibbaren Datei unter einem erlaubten Root mit einem ausführbaren Payload funktioniert, oder das Kopieren einer signierten `uiAccess="true"` EXE in ein beschreibbares Unterverzeichnis (z. B. Update-Reste wie `Tasks_Migrated`, wenn vorhanden) lässt die Secure-Path-Prüfung passieren.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins konnten signierte MSIX-Pakete installieren, die in `WindowsApps` landeten, welches nicht ausgeschlossen war. Ein UIAccess-Binary in der MSIX zu packen und es via `RAiLaunchAdminProcess` zu starten ergab einen **promptless High-IL UIAccess-Prozess**. Microsoft hat dies gemindert, indem der Pfad ausgeschlossen wurde; die `uiAccess`-eingeschränkte MSIX-Fähigkeit erfordert selbst bereits eine Admin-Installation.

## Attack workflow (High IL without a prompt)
1. Eine **signierte UIAccess-Binärdatei** erhalten/erstellen (Manifest `uiAccess="true"`).
2. Diese an einen Ort legen, den AppInfo’s Allowlist akzeptiert (oder einen Pfad-Validierungs-Edge-Case/beschreibbares Artefakt wie oben ausnutzen).
3. `RAiLaunchAdminProcess` aufrufen, um sie **stillschweigend** mit UIAccess + erhöhtem IL zu starten.
4. Von diesem High-IL-Fuß in, ein anderes High-IL-Prozess auf dem Desktop mit **window hooks/DLL injection** oder anderen same-IL-Primitiven anvisieren, um den Admin-Kontext vollständig zu kompromittieren.

## Enumerating candidate writable paths
Führe das PowerShell-Helper-Skript aus, um aus der Perspektive eines gewählten Tokens beschreibbare/überschreibbare Objekte innerhalb nominal sicherer Roots zu entdecken:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Als Administrator ausführen für bessere Sichtbarkeit; setze `-ProcessId` auf einen niederprivilegierten Prozess, um den Zugriff dieses Tokens zu spiegeln.
- Manuell filtern, um bekannte, nicht zulässige Unterverzeichnisse auszuschließen, bevor Kandidaten mit `RAiLaunchAdminProcess` verwendet werden.

## Referenzen
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
