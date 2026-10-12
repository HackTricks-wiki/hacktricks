# Windows Double-Fetch in einem MDL-zugeordneten Benutzerpuffer

{{#include ../../banners/hacktricks-training.md}}

Ein Windows-Kerneltreiber verursacht einen double-fetch, wenn er Daten in vom Aufrufer bereitgestellten Seiten validiert und später einen Zeiger in dieselben Seiten an eine sicherheitskritische API übergibt. Das Sperren und Zuordnen der Seiten macht deren Inhalte nicht unveränderlich. CVE-2025-55680 in `cldflt.sys` veranschaulicht dieses Muster: Der Treiber validierte den relativen Namen eines Cloud Files-Platzhalters und erstellte dann das Objekt, während er weiterhin auf den veränderbaren Puffer des Aufrufers verwies.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` erstellt Dateien oder Verzeichnisse unterhalb eines registrierten Cloud Files-Synchronisierungsstamms. Im verwundbaren Pfad konnte eine Änderung des Namens nach der Validierung die privilegierte Erstellung aus diesem Stamm heraus umleiten.<sup>[[1]](#references)[[2]](#references)</sup>

## Warum das Sperren der Seiten nicht die Daten sperrte

Der verwundbare Pfad `HsmpOpCreatePlaceholders()` reservierte eine MDL für die Nutzlast des Aufrufers, rief `ProbeForRead()` und `MmProbeAndLockPages()` auf und ordnete diese Seiten dem virtuellen Kerneladressraum zu. Eine MDL beschreibt und sperrt die physischen Seiten, damit sie im Arbeitsspeicher bleiben. Sie erstellt **keinen** Schnappschuss ihrer Bytes. Der Benutzermodus kann daher denselben physischen Speicher verändern, während der Treiber ihn über die Systemzuordnung liest.<sup>[[1]](#references)[[3]](#references)</sup>

Der relevante Anforderungs- und Verwendungspfad sah so aus:<sup>[[1]](#references)</sup>

1. `cldapi.dll` sendete den Cloud Files-Steuerungscode `0x903BC` mit dem Tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) und der Create-Placeholder-Operation `0xC0000001`.
2. Jeder Nutzlastdatensatz enthielt 16-Bit-Offset-/Längenpaare für den relativen Namen und die Dateiidentität. Die meisten festen Felder wurden in einen Stack-Datensatz kopiert, der Name variabler Länge blieb jedoch in den zugeordneten Benutzerseiten.
3. Der Treiber durchsuchte den UTF-16-Namen und wies einen Backslash oder Doppelpunkt zurück.
4. Anschließend erstellte er eine `UNICODE_STRING`, deren `Buffer` weiterhin in die zugeordnete Nutzlast zeigte, und wies sie `OBJECT_ATTRIBUTES.ObjectName` zu.
5. `FltCreateFileEx2()` las diesen Zeiger erneut aus. Ein nebenläufiger Schreiber konnte daher bewirken, dass die Validierung einen String und die Dateierstellung einen anderen sah.

Dies ist ein **double-fetch**, obwohl beide Lesevorgänge eine virtuelle Kerneladresse verwenden: Die Sicherheitsgrenze hängt vom zugrunde liegenden Speicher ab, nicht davon, welche virtuelle Zuordnung der Treiber dereferenziert.<sup>[[1]](#references)</sup>

## Cloud Files-Race-Layout

Die offengelegte Exploit-Strategie nutzte wiederholte Anforderungen, Mutator-Threads und eine Junction, um den double-fetch in eine Pfadumleitung umzuwandeln:<sup>[[1]](#references)</sup>

1. Registriere mit `CfRegisterSyncRoot()` ein vom Angreifer kontrolliertes Verzeichnis und erstelle darunter `JUSTASTRING` als Junction zu einem geschützten Ziel.
2. Bereite einen gemeinsamen Platzhalterdatensatz mit dem gültigen, aus einer einzelnen Komponente bestehenden Namen `JUSTASTRINGDnewfile.dll` vor.
3. Lass Mutator-Threads das UTF-16-Code-Unit `D` zwischen `D` und `\` umschalten. Die zweite Darstellung lautet `JUSTASTRING\newfile.dll`.
4. Lass parallel Worker-Threads wiederholt Create-Placeholder-Anforderungen absenden, die auf dieselbe Nutzlast verweisen, während ein Monitor das geschützte Ziel überprüft.
5. Bei einem erfolgreichen Durchlauf wird die Darstellung ohne Trennzeichen validiert, anschließend wird der Junction gefolgt, wenn der spätere Erstellungsaufruf die Darstellung mit `\` sieht.

Das Primitive ermöglicht lediglich die Erstellung geschützter Dateien oder Verzeichnisse. Um daraus Codeausführung zu machen, müssen zusätzlich der Inhalt der erstellten Datei und ein privilegierter Verbraucher kontrolliert werden, etwa ein geeignetes Ziel für DLL-Sideloading. Die ursprüngliche Analyse verwendete diese letzte Kettenkomponente, veröffentlichte jedoch weder den Loader noch die Nutzlast oder einen vollständigen, eigenständigen Exploit.<sup>[[1]](#references)</sup>

Ergänzende Techniken, die Windows-Pfadauflösungs-Races gezielt verlängern, findest du unter [Ausnutzung von Kernel-Race-Conditions über langsame Object-Manager-Pfade](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence – TOCTOU-Privilege-Escalation im Microsoft-Windows-Cloud-Files-Minifilter](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn – CfCreatePlaceholders-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn – MmProbeAndLockPages-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
