# Admin Protection-Umgehungen über UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Überblick
- Windows AppInfo stellt den internen Pfad `RAiLaunchAdminProcess` bereit, der zum Starten von UIAccess-Anwendungen für Barrierefreiheit verwendet wird. UIAccess ermöglicht ausgewählten Interaktionen über Grenzen der User Interface Privilege Isolation (UIPI) hinweg; es handelt sich nicht um eine allgemeine Umgehung jeder Prozesssicherheitsgrenze.<sup>[[1]](#references)[[3]](#references)</sup>
- Die direkte Aktivierung von UIAccess erfordert `NtSetInformationToken(TokenUIAccess)` mit **SeTcbPrivilege**; daher greifen Benutzer mit niedrigen Rechten auf den Dienst zurück. Der Dienst führt vor dem Setzen von UIAccess drei Prüfungen für die Zielbinärdatei durch:
- Das eingebettete Manifest enthält `uiAccess="true"`.
- Signiert durch ein beliebiges Zertifikat, dem der Local Machine-Rootstore vertraut (keine EKU-/Microsoft-Anforderung).
- Befindet sich in einem ausschließlich für Administratoren zugänglichen Pfad auf dem Systemlaufwerk (z. B. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), wobei bestimmte beschreibbare Unterpfade ausgeschlossen sind.
- `RAiLaunchAdminProcess` zeigt bei UIAccess-Starts keine Zustimmungsabfrage an (andernfalls könnten Barrierefreiheitswerkzeuge die Abfrage nicht steuern).<sup>[[1]](#references)</sup>

## Token-Formung und Integrity Levels
- Wenn die Prüfungen erfolgreich sind, **kopiert** AppInfo das Token des Aufrufers, aktiviert UIAccess und erhöht das Integrity Level (IL):
- Eingeschränkter Administratorbenutzer (Benutzer ist Mitglied der Administrators, läuft aber mit einem gefilterten Token) ➜ **High IL**.
- Nicht-Administratorbenutzer ➜ IL wird um **+16 Stufen** erhöht, bis zu einem **High**-Limit (System IL wird niemals zugewiesen).
- Wenn das Aufrufer-Token bereits über UIAccess verfügt, bleibt das IL unverändert.
- „Ratchet“-Trick: Ein UIAccess-Prozess kann UIAccess für sich selbst deaktivieren, über `RAiLaunchAdminProcess` neu gestartet werden und eine weitere Erhöhung des IL um +16 erhalten. Medium➜High erfordert 255 Neustarts (auffällig, funktioniert aber).<sup>[[1]](#references)</sup>

## Warum UIAccess eine Umgehung von Admin Protection ermöglicht
- UIAccess ermöglicht es einem Prozess mit niedrigerem IL, Fenstern mit höherem IL Fensternachrichten zu senden (unter Umgehung der UIPI-Filter). Bei **gleichem IL** erlauben klassische UI-Primitives wie `SetWindowsHookEx` **Code-Injection/DLL-Laden** in jeden Prozess, der ein Fenster besitzt (einschließlich **message-only windows**, die von COM verwendet werden).
- Admin Protection startet den UIAccess-Prozess unter der Identität des **eingeschränkten Benutzers**, jedoch mit **High IL**, und zwar ohne Abfrage. Sobald beliebiger Code innerhalb dieses High-IL-UIAccess-Prozesses ausgeführt wird, kann der Angreifer in andere High-IL-Prozesse auf dem Desktop injizieren (selbst wenn diese zu anderen Benutzern gehören), wodurch die beabsichtigte Trennung durchbrochen wird.<sup>[[1]](#references)</sup>

## HWND-zu-Prozess-Handle-Primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Unter Windows 10 1803+ wurde die API nach Win32k verschoben (`NtUserGetWindowProcessHandle`) und kann mithilfe eines vom Aufrufer bereitgestellten `DesiredAccess` ein Prozess-Handle öffnen. Der Kernelpfad verwendet `ObOpenObjectByPointer(..., KernelMode, ...)`, wodurch normale Zugriffskontrollen im User Mode umgangen werden.<sup>[[2]](#references)</sup>
- Voraussetzungen in der Praxis: Das Zielfenster muss sich auf demselben Desktop befinden und die UIPI-Prüfungen müssen erfolgreich sein. Historisch konnte ein Aufrufer mit UIAccess einen UIPI-Fehler umgehen und trotzdem ein Handle im Kernel Mode erhalten (durch CVE-2023-41772 behoben).
- Historische Auswirkungen: Ein Fenster-Handle wurde zu einer **Fähigkeit** für Prozesszugriffe wie `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` oder `PROCESS_VM_OPERATION`, die der Aufrufer normalerweise nicht erhalten konnte. Vor den dokumentierten Korrekturen konnte dies Sandbox- und Protected-Process-Grenzen überschreiten, wenn ein Ziel ein Fenster bereitstellte, einschließlich eines message-only windows.<sup>[[2]](#references)</sup>
- Praktischer Missbrauchsablauf: HWNDs auflisten oder suchen (z. B. mit `EnumWindows`/`FindWindowEx`), die zugehörige PID auflösen (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` aufrufen und anschließend das zurückgegebene Handle für Speicher-Lese-/Schreibzugriffe oder Code-Hijack-Primitives verwenden.
- Verhalten nach den Korrekturen: UIAccess gewährt bei einem UIPI-Fehler keine Open-Vorgänge im Kernel Mode mehr, und die zulässigen Zugriffsrechte sind auf den Legacy-Hook-Satz beschränkt; Windows 11 24H2 fügt Prozessschutzprüfungen und über Feature Flags aktivierte sicherere Pfade hinzu. Das systemweite Deaktivieren von UIPI (`EnforceUIPI=0`) schwächt diese Schutzmechanismen.<sup>[[2]](#references)</sup>

## Schwachstellen bei der Validierung sicherer Verzeichnisse (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo löst den angegebenen Pfad über `GetFinalPathNameByHandle` auf und wendet anschließend **String-Allow-/Deny-Prüfungen** gegen fest codierte Roots/Ausschlüsse an. Mehrere Bypass-Klassen entstehen durch diese vereinfachte Validierung:
- **Benannte Streams von Verzeichnissen**: Ausgeschlossene beschreibbare Verzeichnisse (z. B. `C:\Windows\tracing`) können mit einem benannten Stream für das Verzeichnis selbst umgangen werden, z. B. `C:\Windows\tracing:file.exe`. Die String-Prüfungen sehen `C:\Windows\` und übersehen den ausgeschlossenen Unterpfad.
- **Beschreibbare Datei/Verzeichnis innerhalb eines erlaubten Roots**: `CreateProcessAsUser` **erfordert keine `.exe`-Erweiterung**. Das Überschreiben einer beliebigen beschreibbaren Datei unter einem erlaubten Root mit einem ausführbaren Payload funktioniert; alternativ kann das Kopieren einer signierten EXE mit `uiAccess="true"` in jedes beschreibbare Unterverzeichnis (z. B. Update-Überreste wie `Tasks_Migrated`, sofern vorhanden) dazu führen, dass sie die Prüfung des sicheren Pfads besteht.
- **MSIX nach `C:\Program Files\WindowsApps` (behoben)**: Nicht-Administratoren konnten signierte MSIX-Pakete installieren, die in `WindowsApps` landeten, das nicht ausgeschlossen war. Wurde eine UIAccess-Binärdatei innerhalb des MSIX verpackt und anschließend über `RAiLaunchAdminProcess` gestartet, entstand ein **abfragefreier High-IL-UIAccess-Prozess**. Microsoft entschärfte dies durch den Ausschluss dieses Pfads; die eingeschränkte `uiAccess`-MSIX-Funktion selbst erfordert bereits eine Installation durch einen Administrator.<sup>[[1]](#references)</sup>

## Angriffsablauf (High IL ohne Abfrage)
1. Eine **signierte UIAccess-Binärdatei** beschaffen/erstellen (Manifest `uiAccess="true"`). Für eine realistische Bewertung mit ausdrücklich für das Lab autorisiertem Trust-Material und autorisierten Pfaden testen; kein Angreiferzertifikat zum Local Machine-Rootstore eines Produktionscomputers hinzufügen.
2. Sie an einem Ort ablegen, den AppInfos Allowlist akzeptiert (oder wie oben beschrieben eine Edge Case der Pfadvalidierung/ein beschreibbares Artefakt ausnutzen).
3. `RAiLaunchAdminProcess` aufrufen, um sie **still** mit UIAccess und erhöhtem IL zu starten.
4. Von diesem High-IL-Foothold aus einen anderen High-IL-Prozess auf dem Desktop mithilfe von **Window Hooks/DLL-Injection** oder anderen Primitives mit gleichem IL angreifen, um den Administratorkontext vollständig zu kompromittieren.<sup>[[1]](#references)</sup>

## Auflisten potenzieller beschreibbarer Pfade
Führen Sie den PowerShell-Helfer aus, um aus der Perspektive eines ausgewählten Tokens beschreibbare/überschreibbare Objekte innerhalb nominell sicherer Roots zu ermitteln:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Für eine umfassendere Sichtbarkeit als Administrator ausführen; `-ProcessId` auf einen Prozess mit niedrigen Berechtigungen setzen, um den Zugriff dieses Tokens nachzubilden.
- Manuell filtern, um bekannte nicht erlaubte Unterverzeichnisse auszuschließen, bevor die Kandidaten mit `RAiLaunchAdminProcess` verwendet werden.

## Verwandt

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Umgehen des Administrator Protection durch den Missbrauch von UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Tiefgehende Analyse von GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess-Anwendungen](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
