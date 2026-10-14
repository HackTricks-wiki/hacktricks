# Umgehungen der Kernel-Mode-Dateizugriffsprüfung

{{#include ../../banners/hacktricks-training.md}}

## Verwundbares Treibermuster

Ein Treiber wahrt die Sicherheitsgrenze eines Aufrufers nicht allein dadurch, dass er diesen imitiert. Kernel-Mode-Objektöffnungen umgehen normalerweise Zugriffsprüfungen. `OBJ_KERNEL_HANDLE` macht das resultierende Handle lediglich im Kernel-Mode zugänglich. Wenn ein Treiber im Auftrag des User-Mode ein Objekt öffnet oder bearbeitet, muss er außerdem `OBJ_FORCE_ACCESS_CHECK` verwenden, damit der Object Manager den angeforderten Zugriff anhand des effektiven Tokens prüft.<sup>[[3]](#references)[[4]](#references)</sup>

Prüfe IOCTLs zur Dateiverarbeitung und Create-Callbacks auf diese Abfolge:<sup>[[3]](#references)[[4]](#references)</sup>

1. Der User-Mode gibt einen Pfad, ein Quell-Handle, den gewünschten Zugriff oder einen Operationstyp vor.
2. Der Treiber imitiert den Aufrufer, ruft aber `IoCreateFileEx`, `ZwCreateFile` oder eine ähnliche Routine ohne `OBJ_FORCE_ACCESS_CHECK` auf.
3. Ein nur im Kernel zugängliches Datei- oder Verzeichnis-Handle wird im Zustand pro Handle gespeichert.
4. Eine spätere Operation entscheidet anhand eines vom Angreifer beeinflussten Zustands, etwa der beim ersten Öffnen angeforderten Zugriffsmaske, ob der Aufrufer imitiert wird.
5. Der privilegierte Zweig führt eine Umbenennung oder Verknüpfung mit einer Informationsklasse `BypassAccessCheck` aus.

Dies ist ein **confused-deputy file primitive**, nicht unbedingt eine Speicherbeschädigung. Eine besonders gefährliche Zustandsumkehr lautet: „Schreibzugriff angefordert bedeutet, den Aufrufer zu imitieren; kein Schreibzugriff angefordert bedeutet, privilegiert zu bleiben.“ Bei diesem Design kann die absichtliche Anforderung von ausschließlich Lesezugriff den mächtigeren Pfad freischalten.<sup>[[3]](#references)</sup>

## vSMB-Beispiel: privilegierter Root plus privilegierte Umbenennung

`storvsp.sys` implementiert Virtual Server Message Block (vSMB). Wenn das Feature **Virtual Machine Platform** aktiviert ist, kann der User-Mode über `\\.\STORVSP` auf `\Device\STORVSP` zugreifen. Ein vSMB-Dateisystempfad hat die Form `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 und CVE-2025-64673 zeigten, wie zwei widersprüchliche Zugriffskontrollentscheidungen diese Schnittstelle in eine lokale Rechteausweitung verwandeln konnten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Die Zuordnung von Funktionen zu CVEs in der Quelle basiert auf Reverse Engineering der gepatchten Binärdatei und nicht auf Microsoft-Quellcode. Die Forscher warnen, dass die beiden Bezeichnungen möglicherweise den jeweils anderen Funktionen zugeordnet sind.<sup>[[3]](#references)</sup>

### 1. Eine schreibgeschützte Freigabe mit Root in einem geschützten Verzeichnis erstellen

Der verwundbare Create-Pfad speicherte angeforderte Rechte in persistenten Flags wie `HasReadAccess`, `HasWriteAccess` und `HasAppendAccess`. Anschließend öffnete er den zugrunde liegenden Pfad mit `OBJ_KERNEL_HANDLE`, aber ohne `OBJ_FORCE_ACCESS_CHECK`. Die versuchte Impersonation sorgte daher nicht dafür, dass beim Öffnen der Datei die NTFS-Berechtigungen des Aufrufers berücksichtigt wurden.<sup>[[3]](#references)[[4]](#references)</sup>

Fordere ausschließlich `FILE_READ_DATA` an. Dadurch bleibt `HasWriteAccess` deaktiviert, während weiterhin eine Freigabe erstellt wird, deren interner Root auf ein geschütztes Verzeichnis verweist:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Das wichtige Artefakt ist kein Handle für ein System32-Verzeichnis im User-Mode. Es ist ein vSMB-Geräte-Handle, das einem Treiberzustand zugeordnet ist, der ein privilegiertes Kernel-Root-Handle enthält.<sup>[[3]](#references)</sup>

### 2. Den Zustandsfehler für den Austausch einer geschützten Datei ausnutzen

IOCTL `0x240330` akzeptierte ein Quell-Datei-Handle, eine Informationsklasse und einen Puffer variabler Länge für Informationen:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Der verwundbare Handler akzeptierte `FileRenameInformation`, `FileLinkInformation` und `FileRenameInformationEx`. Bei einem normalen Umbenennungspfad trennte er den übergeordneten Pfad von der letzten Komponente und öffnete dann das übergeordnete Verzeichnis relativ zum gespeicherten Root-Handle. Auch bei diesem Öffnen wurde `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` ohne `OBJ_FORCE_ACCESS_CHECK` verwendet. Ein vom Angreifer bereitgestelltes, von null verschiedenes `RootDirectory` innerhalb der Umbenennungsstruktur wurde abgelehnt, sodass der Treiber sein eigenes privilegiertes Verzeichnis-Handle bereitstellte.<sup>[[3]](#references)</sup>

Der ausnutzbare Zweig wurde ausgewählt, indem in Phase 1 **kein Schreibzugriff angefordert** wurde:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: Den gespeicherten Root-Sicherheitskontext impersonieren.
- `HasWriteAccess == 0`: Impersonation überspringen und `FileRenameInformation` oder `FileRenameInformationEx` in die entsprechende `BypassAccessCheck`-Variante umwandeln.

Der Handler duplizierte das vom Angreifer bereitgestellte Quell-Handle in `PsInitialSystemProcess`, referenzierte es als Dateiobjekt, setzte das privilegierte Zielverzeichnis-Handle in die Umbenennungsstruktur ein und rief `ZwSetInformationFile` auf. Mit `ReplaceIfExists = TRUE` konnte eine vom Aufrufer kontrollierte Datei dadurch eine vorhandene Datei unterhalb des geschützten Stammverzeichnisses ersetzen.<sup>[[3]](#references)</sup>

Wenn Sie einen ähnlichen Handler überprüfen, verfolgen Sie **sowohl die Herkunft der Handles als auch den Sicherheitskontext** in jedem Zweig. Eingabevalidierung, Prüfungen auf Integer-Überlauf, `IO_STOP_ON_SYMLINK` und die Beschränkung der akzeptierten Informationsklassen gleichen ein privilegiertes Root-Handle in Kombination mit einer Operation zur Umgehung der Zugriffskontrolle nicht aus.<sup>[[3]](#references)</sup>

## Von geschütztem Schreibzugriff zur SYSTEM-Ausführung

Ein Mechanismus zum Ersetzen geschützter Dateien ermöglicht Codeausführung, wenn ein privilegierter Prozess später das ersetzte Modul lädt. In der gezeigten Angriffskette war das Ziel `C:\Windows\System32\wuapi.dll`. Die Aktivierung der lokalen COM-Serverklasse `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` für die Schnittstelle `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` und der Aufruf von `IWaaSRemediation::LaunchDetectionOnly()` bewirkten, dass ein SYSTEM-Prozess diese DLL lud.<sup>[[3]](#references)</sup>

Dieser COM-Aufruf ist ein **Aktivierungsauslöser**, keine [COM registry hijacking](com-hijacking.md). Der Dateimechanismus stellt das platzierte Modul bereit, der privilegierte Loader sorgt für die Ausführung. Identifizieren Sie bei anderen Angriffsketten mit geschütztem Schreibzugriff das genaue Image, den DLL-Pfad, die Signaturrichtlinie, die Bitness, die exportierten Funktionen und einen zuverlässigen Auslöser, bevor Sie ein Ziel auswählen. Der allgemeine Workflow zur Loader-Analyse ist unter [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) beschrieben.<sup>[[3]](#references)</sup>

### Ein Session-0-Token auf den interaktiven Desktop übertragen

Eine von einem Dienst geladene Payload wird normalerweise in Session 0 ausgeführt. Um einen interaktiven Prozess zu erstellen, kann sie mit `WTSGetActiveConsoleSessionId` die aktive Konsolensitzung ermitteln, die erforderlichen Token-Privilegien aktivieren, das aktuelle SYSTEM-Token als primäres Token duplizieren und dessen `TokenSessionId` auf die aktive Sitzung setzen. `CreateProcessAsUserW` verwendet dieses Token dann mit `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` ist in diesem Szenario erforderlich, um die Sitzungs-ID eines Tokens festzulegen. Die interaktive Window Station und der Desktop müssen dem Token ebenfalls Zugriff gewähren. Einen umfassenderen Ablauf zum Kopieren von Tokens findest du unter [Token-Duplizierung aus Session 0](sedebug-+-seimpersonate-copy-token.md).<sup>[[3]](#references)[[5]](#references)</sup>

## Hinweise zu Patches und Reviews

Die Updates von Microsoft vom Dezember 2025 haben die demonstrierte Angriffskette behoben. Reverse Engineering ergab, dass der gepatchte vSMB-Erstellungspfad nicht vertrauenswürdige Aufrufer zurückweist, die ein Share-Root ohne `FILE_WRITE_DATA` anfordern. Für relevante Operationen wurde außerdem eine erzwungene Zugriffsprüfung eingeführt. Dadurch wird die Zustandsumkehr verhindert, bevor ein nicht privilegierter Aufrufer das privilegierte Root erhalten kann.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Beachte für Treibercode diese Regeln:<sup>[[3]](#references)[[4]](#references)</sup>

- Füge `OBJ_FORCE_ACCESS_CHECK` hinzu, wenn ein Objekt im Auftrag einer User-Mode-Anfrage geöffnet wird. Betrachte `OBJ_KERNEL_HANDLE` nicht als Autorisierungskontrolle.<sup>[[4]](#references)</sup>
- Erfasse und validiere den Anforderungsmodus und den effektiven Sicherheitskontext. Lass angeforderte Rechte nicht darüber entscheiden, welcher privilegiertere Ausführungspfad verwendet wird.
- Validiere User-Handles mit dem korrekten Objekttyp, der Zugriffsmaske und `UserMode`. Das Duplizieren eines Handles in den Systemprozess validiert nicht die Berechtigung für die angeforderte Operation.
- Löse Ziele relativ zu einem vertrauenswürdigen Handle auf, stelle aber sicher, dass dieses Handle selbst unter der erzwungenen Zugriffsprüfung des Anforderers geöffnet wurde.
- Vermeide `File*BypassAccessCheck`-Klassen für benutzergesteuerte Operationen. Wenn interner Code sie tatsächlich benötigt, muss dieser Pfad durch eine Autorisierungsentscheidung abgesichert sein, die unabhängig von benutzergesteuerten Zugriffsflags ist.
- Spiele Patches auf betroffenen Systemen ein. Die verwundbare Angriffsfläche ist relevant, wenn Virtual Machine Platform `storvsp.sys` lädt.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Von Virtual Share zur Physical Shell: Windows' inkonsistente Zugriffskontrolle für LPE nutzen](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Objekt-Handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Funktion CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
