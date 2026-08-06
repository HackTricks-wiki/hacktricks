# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

As jy gevind het dat jy **in 'n System Path-lêergids kan skryf** (let daarop dat dit nie sal werk as jy in 'n User Path-lêergids kan skryf nie), is dit moontlik dat jy **voorregte in die stelsel kan eskaleer**.

Om dit te doen, kan jy 'n **Dll Hijacking** misbruik, waar jy 'n **library sal kaap wat gelaai word** deur 'n service of process met **meer voorregte** as jy, en omdat daardie service 'n Dll laai wat waarskynlik nie eens in die hele stelsel bestaan nie, sal dit probeer om dit te laai vanaf die System Path waarin jy kan skryf.

Vir meer inligting oor **wat Dll Hijackig is**, kyk na:


{{#ref}}
./
{{#endref}}

## Privesc met Dll Hijacking

### Vind 'n ontbrekende Dll

Die eerste ding wat jy nodig het, is om 'n **process te identifiseer** wat met **meer voorregte** as jy loop en probeer om 'n **Dll vanaf die System Path te laai** waarin jy kan skryf.

Onthou dat hierdie tegniek van 'n **Machine/System PATH**-inskrywing afhanklik is, nie slegs van jou **User PATH** nie. Daarom is dit die moeite werd om, voordat jy tyd aan Procmon bestee, die **Machine PATH**-inskrywings te enumerereer en te kontroleer watter daarvan skryfbaar is:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds loop. Om uit te vind watter DLLs deur die dienste benodig word, moet jy procmon so gou as moontlik begin (voordat prosesse gelaai word). Om ontbrekende .dlls te vind, doen die volgende:

- **Skep** die vouer `C:\privesc_hijacking` en voeg die pad `C:\privesc_hijacking` by die **System Path env variable**. Jy kan dit **handmatig** of met **PS** doen:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Launch **`procmon`** en gaan na **`Options`** --> **`Enable boot logging`** en druk **`OK`** in die prompt.
- **Herbegin** dan. Wanneer die rekenaar herbegin word, sal **`procmon`** so gou moontlik begin om gebeure **op te neem**.
- Sodra **Windows** **gestart** is, voer **`procmon`** weer uit. Dit sal aandui dat dit aan die loop was en jou **vra of jy die gebeure wil stoor** in ’n lêer. Sê **ja** en **stoor die gebeure in ’n lêer**.
- **Nadat** die **lêer** **gegenereer** is, **sluit** die oop **`procmon`**-venster en **maak die gebeurtenislêer oop**.
- Voeg hierdie **filters** by en jy sal al die Dlls vind wat ’n **proses probeer laai het** vanaf die skryfbare System Path-lêergids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is slegs nodig vir dienste wat te vroeg start** om andersins waar te neem. Indien jy die teikendiens/-program **op aanvraag kan trigger** (byvoorbeeld deur met sy COM-interface te interaksieer, die diens te herbegin, of ’n geskeduleerde taak weer te launch), is dit gewoonlik vinniger om ’n normale Procmon-capture te hou met filters soos **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, en **`Path begins with <writable_machine_path>`**.

### Gemiste Dlls

Toe ek dit in ’n gratis **virtuele (vmware) Windows 11-masjien** uitgevoer het, het ek hierdie resultate gekry:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is die .exe’s nutteloos, so ignoreer hulle; die gemiste DLLs was afkomstig van:

| Diens                         | Dll                | CMD line                                                             |
| ----------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nadat ek dit gevind het, het ek hierdie interessante blogplasing gevind wat ook verduidelik hoe om [**WptsExtensions.dll vir privesc te abuse**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Dit is wat ons **nou gaan doen**.<sup>[[3]](#references)</sup>

### Ander kandidate wat die moeite werd is om te triage

`WptsExtensions.dll` is ’n goeie voorbeeld, maar dit is nie die enigste herhalende **phantom DLL** wat in bevoorregte dienste voorkom nie. Moderne hunting-reëls en publieke hijack-katalogusse volg steeds name soos:<sup>[[2]](#references)</sup>

| Diens / Scenario | Ontbrekende DLL | Aantekeninge |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassieke **SYSTEM**-kandidaat op client-stelsels. Goed wanneer die skryfbare gids in die **Machine PATH** is en die diens vir die DLL tydens startup soek. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessant op **server editions**, omdat die diens as **SYSTEM** loop en in sommige builds **op aanvraag deur ’n normale gebruiker getrigger kan word**, wat dit beter maak as gevalle wat slegs met ’n reboot werk. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Lewer gewoonlik eers **`NT AUTHORITY\LOCAL SERVICE`**. Dit is dikwels steeds genoeg omdat die token **`SeImpersonatePrivilege`** het, sodat jy dit kan chain met [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Beskou hierdie name as **triage-wenke**, nie as gewaarborgde suksesse nie: hulle is **SKU/build-afhanklik**, en Microsoft kan die gedrag tussen releases verander. Die belangrike gevolgtrekking is om te soek na **ontbrekende DLLs in bevoorregte dienste wat deur die Machine PATH beweeg**, veral as die diens **weer getrigger kan word sonder om te reboot**.

### Exploitation

Om dus **privileges te eskaleer**, gaan ons die library **WptsExtensions.dll** hijack. Omdat ons die **path** en die **naam** het, hoef ons net die **malicious dll te genereer**.

Jy kan [**probeer om enige van hierdie voorbeelde te gebruik**](#creating-and-compiling-dlls). Jy kan payloads uitvoer soos: ’n rev shell kry, ’n gebruiker byvoeg, ’n beacon uitvoer...

> [!WARNING]
> Let daarop dat **nie al die dienste** met **`NT AUTHORITY\SYSTEM`** loop nie; sommige loop ook met **`NT AUTHORITY\LOCAL SERVICE`**, wat **minder privileges** het, en jy **sal nie ’n nuwe gebruiker kan skep** deur sy permissions te abuse nie.\
> Daardie gebruiker het egter die **`seImpersonate`**-privilege, sodat jy die[ **potato suite kan gebruik om privileges te eskaleer**](../roguepotato-and-printspoofer.md). In hierdie geval is ’n rev shell dus ’n beter opsie as om ’n gebruiker te probeer skep.

Ten tyde van die skryf hiervan loop die **Task Scheduler**-diens met **Nt AUTHORITY\SYSTEM**.

Nadat jy die **malicious Dll gegenereer** het (_in my geval het ek x64 rev shell gebruik en ’n shell teruggekry, maar defender het dit gekill omdat dit van msfvenom afkomstig was_), stoor dit in die skryfbare System Path met die naam **WptsExtensions.dll** en **herbegin** die rekenaar (of herbegin die diens, of doen wat ook al nodig is om die geaffekteerde diens/program weer te laat loop).

Wanneer die diens herbegin word, behoort die **dll gelaai en uitgevoer te word** (jy kan die **procmon**-trick weer gebruik om te kontroleer of die **library soos verwag gelaai is**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
