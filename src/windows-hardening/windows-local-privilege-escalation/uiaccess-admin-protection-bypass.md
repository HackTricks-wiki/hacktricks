# Umgehungen des Admin-Schutzes via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Übersicht
- Windows AppInfo stellt `RAiLaunchAdminProcess` bereit, um UIAccess-Prozesse zu starten (für Barrierefreiheit vorgesehen). UIAccess umgeht den größten Teil der Nachrichtenfilterung durch User Interface Privilege Isolation (UIPI), damit Barrierefreiheitssoftware UI mit höherem IL steuern kann.
- Die direkte Aktivierung von UIAccess erfordert `NtSetInformationToken(TokenUIAccess)` mit **SeTcbPrivilege**. Daher verlassen sich Aufrufer mit niedrigen Berechtigungen auf den Dienst. Der Dienst führt drei Prüfungen an der Ziel-Binary durch, bevor er UIAccess setzt:
- Das eingebettete Manifest enthält `uiAccess="true"`.
- Die Binary ist mit einem von einem Zertifikat signiert, dem der Local Machine-Root-Store vertraut (keine EKU-/Microsoft-Anforderung).
- Sie befindet sich in einem ausschließlich für Administratoren zugänglichen Pfad auf dem Systemlaufwerk (z. B. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), wobei bestimmte beschreibbare Unterpfade ausgeschlossen sind.
- `RAiLaunchAdminProcess` zeigt bei UIAccess-Starts keinen Consent-Prompt an (andernfalls könnte Barrierefreiheitssoftware den Prompt nicht steuern).<sup>[[1]](#references)</sup>

## Token-Shaping und Integrity Levels
- Wenn die Prüfungen erfolgreich sind, **kopiert** AppInfo das Caller-Token, aktiviert UIAccess und erhöht das Integrity Level (IL):
- Eingeschränkter Admin-Benutzer (der Benutzer ist Mitglied der Administrators, läuft aber mit einem gefilterten Token) ➜ **High IL**.
- Nicht-Admin-Benutzer ➜ IL wird um **+16 Stufen** bis zu einem Limit von **High** erhöht (System IL wird niemals zugewiesen).
- Wenn das Caller-Token bereits UIAccess besitzt, bleibt das IL unverändert.
- „Ratchet“-Trick: Ein UIAccess-Prozess kann UIAccess für sich selbst deaktivieren, sich über `RAiLaunchAdminProcess` erneut starten und eine weitere Erhöhung um +16 IL erhalten. Medium➜High erfordert 255 Relaunches (auffällig, funktioniert aber).<sup>[[1]](#references)</sup>

## Warum UIAccess eine Umgehung des Admin-Schutzes ermöglicht
- UIAccess ermöglicht es einem Prozess mit niedrigerem IL, Fenstern mit höherem IL Fensternachrichten zu senden (unter Umgehung der UIPI-Filter). Bei **gleichem IL** erlauben klassische UI-Primitives wie `SetWindowsHookEx` **Code-Injection/DLL-Laden** in jeden Prozess, der ein Fenster besitzt (einschließlich **message-only windows**, die von COM verwendet werden).
- Admin Protection startet den UIAccess-Prozess unter der Identität des **eingeschränkten Benutzers**, jedoch mit **High IL**, und zwar ohne Prompt. Sobald beliebiger Code innerhalb dieses High-IL-UIAccess-Prozesses ausgeführt wird, kann der Angreifer in andere High-IL-Prozesse auf dem Desktop injizieren (auch wenn diese zu anderen Benutzern gehören), wodurch die beabsichtigte Trennung aufgehoben wird.<sup>[[1]](#references)</sup>

## HWND-to-process-Handle-Primitiv (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Unter Windows 10 1803+ wurde die API nach Win32k verschoben (`NtUserGetWindowProcessHandle`) und kann mithilfe eines vom Caller bereitgestellten `DesiredAccess` ein Process-Handle öffnen. Der Kernel-Pfad verwendet `ObOpenObjectByPointer(..., KernelMode, ...)`, wodurch normale Access-Checks im User-Mode umgangen werden.<sup>[[2]](#references)</sup>
- Voraussetzungen in der Praxis: Das Zielfenster muss sich auf demselben Desktop befinden, und die UIPI-Checks müssen erfolgreich sein. Historisch konnte ein Caller mit UIAccess einen UIPI-Fehler umgehen und trotzdem ein Handle im Kernel-Mode erhalten (durch CVE-2023-41772 behoben).
- Auswirkungen: Ein Window-Handle wird zu einer **Capability**, mit der ein mächtiges Process-Handle erlangt werden kann (typischerweise `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), das der Caller normalerweise nicht öffnen könnte. Dies ermöglicht Cross-Sandbox-Zugriff und kann Protected-Process-/PPL-Grenzen durchbrechen, wenn das Ziel irgendein Fenster bereitstellt (einschließlich message-only windows).
- Praktischer Abuse-Flow: HWNDs enumerieren oder lokalisieren (z. B. `EnumWindows`/`FindWindowEx`), die zugehörige PID auflösen (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` aufrufen und anschließend das zurückgegebene Handle für Memory-Read/Write oder Code-Hijack-Primitives verwenden.
- Verhalten nach dem Fix: UIAccess gewährt bei einem UIPI-Fehler keine Opens im Kernel-Mode mehr, und die zulässigen Access-Rechte sind auf den Legacy-Hook-Satz beschränkt. Windows 11 24H2 fügt Process-Protection-Checks und über Feature-Flags aktivierte, sicherere Pfade hinzu. Das systemweite Deaktivieren von UIPI (`EnforceUIPI=0`) schwächt diese Schutzmaßnahmen.<sup>[[2]](#references)</sup>

## Schwachstellen bei der Validierung sicherer Verzeichnisse (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo löst den angegebenen Pfad über `GetFinalPathNameByHandle` auf und wendet anschließend **String-Allow-/Deny-Checks** gegen fest codierte Roots/Exclusions an. Mehrere Bypass-Klassen ergeben sich aus dieser vereinfachten Validierung:
- **Benannte Streams von Verzeichnissen**: Ausgeschlossene beschreibbare Verzeichnisse (z. B. `C:\Windows\tracing`) können mit einem Named Stream auf dem Verzeichnis selbst umgangen werden, z. B. `C:\Windows\tracing:file.exe`. Die String-Checks sehen `C:\Windows\` und übersehen den ausgeschlossenen Unterpfad.
- **Beschreibbare Datei/Verzeichnis innerhalb eines erlaubten Roots**: `CreateProcessAsUser` erfordert keine `.exe`-Extension. Das Überschreiben einer beliebigen beschreibbaren Datei unter einem erlaubten Root mit einem ausführbaren Payload funktioniert. Alternativ kann das Kopieren einer signierten EXE mit `uiAccess="true"` in ein beliebiges beschreibbares Unterverzeichnis (z. B. Update-Überreste wie `Tasks_Migrated`, sofern vorhanden) dazu führen, dass sie den Secure-Path-Check besteht.
- **MSIX nach `C:\Program Files\WindowsApps` (behoben)**: Nicht-Admins konnten signierte MSIX-Pakete installieren, die in `WindowsApps` landeten, das nicht ausgeschlossen war. Wurde eine UIAccess-Binary in das MSIX gepackt und anschließend über `RAiLaunchAdminProcess` gestartet, entstand ein **High-IL-UIAccess-Prozess ohne Prompt**. Microsoft entschärfte dies, indem dieser Pfad ausgeschlossen wurde; die eingeschränkte `uiAccess`-MSIX-Capability selbst erfordert bereits eine Installation durch einen Administrator.<sup>[[1]](#references)</sup>

## Attack-Workflow (High IL ohne Prompt)
1. Eine **signierte UIAccess-Binary** beschaffen/erstellen (Manifest `uiAccess="true"`).
2. Sie an einem Ort ablegen, den AppInfos Allowlist akzeptiert (oder wie oben eine Edge-Case-/beschreibbare Path-Validation-Schwachstelle bzw. ein beschreibbares Artefakt ausnutzen).
3. `RAiLaunchAdminProcess` aufrufen, um sie **still** mit UIAccess + erhöhtem IL zu starten.
4. Von diesem High-IL-Foothold aus einen anderen High-IL-Prozess auf dem Desktop mit **Window Hooks/DLL-Injection** oder anderen Primitives bei gleichem IL angreifen, um den Admin-Kontext vollständig zu kompromittieren.<sup>[[1]](#references)</sup>

## Auflisten potenziell beschreibbarer Pfade
Führe den PowerShell-Helper aus, um aus der Perspektive eines ausgewählten Tokens beschreibbare/überschreibbare Objekte innerhalb nominell sicherer Roots zu ermitteln:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Als Administrator ausführen, um eine umfassendere Sichtbarkeit zu erhalten; `-ProcessId` auf einen Prozess mit niedrigen Berechtigungen setzen, um den Zugriff dieses Tokens nachzubilden.
- Manuell filtern, um bekannte nicht zulässige Unterverzeichnisse auszuschließen, bevor die Kandidaten mit `RAiLaunchAdminProcess` verwendet werden.

## Verwandt

Propagation von Accessibility-Registrierungseinträgen auf dem Secure Desktop LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referenzen

- [1] [Umgehen des Administrator-Schutzes durch Missbrauch von UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Tiefgehende Analyse von GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
