# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

As jy ontdek dat jy kan **skryf in 'n System Path folder** (let wel: dit sal nie werk as jy net in 'n User Path folder kan skryf nie) is dit moontlik dat jy die **privileges op die stelsel kan eskaleer**.

Daartoe kan jy 'n **Dll Hijacking** misbruik waar jy gaan **hijack a library being loaded** deur 'n diens of proses met **meer privileges** as joune, en aangesien daardie diens 'n Dll laai wat waarskynlik nie eens in die hele stelsel bestaan nie, sal dit probeer om dit vanaf die System Path te laai waar jy kan skryf.

Vir meer inligting oor **wat is Dll Hijackig** kyk:


{{#ref}}
./
{{#endref}}

## Privesc met Dll Hijacking

### Om 'n ontbrekende Dll te vind

Die eerste ding wat jy nodig het is om 'n proses te **identifiseer** wat loop met **meer privileges** as jy en wat probeer om 'n **Dll van die System Path** te laai waarin jy kan skryf.

Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds loop. Om te vind watter Dlls ontbreek, moet jy procmon so gou moontlik begin (voor prosesse gelaai word). Dus, om ontbrekende .dlls te vind, doen:

- **Skep** die folder `C:\privesc_hijacking` en voeg die pad `C:\privesc_hijacking` by die **System Path omgewingsveranderlike**. Jy kan dit **manueel** doen of met **PS**:
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
- Start **`procmon`** en gaan na **`Options`** --> **`Enable boot logging`** en druk **`OK`** in die prompt.
- Herbegin dan die rekenaar. Wanneer die rekenaar herbegin is sal **`procmon`** so gou as moontlik begin **opneem**.
- Sodra **Windows** opgestart is, voer **`procmon`** weer uit; dit sal jou vertel dat dit reeds aan die gang was en sal **vra of jy die events in 'n lêer wil stoor**. Sê **ja** en **stoor die events in 'n lêer**.
- **Nadat** die **lêer** gegenereer is, **sluit** die geopende **`procmon`**-venster en **open** die events-lêer.
- Voeg hierdie **filters** by en jy sal al die Dlls vind wat 'n **proses probeer laai** vanaf die skryfbare System Path-gids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Gemiste Dlls

Deur dit op 'n gratis **virtual (vmware) Windows 11**-masjien te laat loop het ek hierdie resultate gekry:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is die .exe's nutteloos, ignoreer hulle; die gemiste DLLs was van:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nadat ek dit gevind het, het ek hierdie interessante blogpos gevind wat ook verduidelik hoe om [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Dit is wat ons nou gaan doen.

### Eksploitasie

Dus, om voorregte te eskaleer gaan ons die biblioteek **WptsExtensions.dll** kap. Met die **pad** en die **naam** hoef ons net die kwaadwillige dll te genereer.

Jy kan [**probeer enige van hierdie voorbeelde te gebruik**](#creating-and-compiling-dlls). Jy kan payloads uitvoer soos: kry 'n rev shell, voeg 'n gebruiker by, voer 'n beacon uit...

> [!WARNING]
> Let wel dat **nie alle dienste met** **`NT AUTHORITY\SYSTEM`** uitgevoer word nie; sommige word ook met **`NT AUTHORITY\LOCAL SERVICE`** uitgevoer wat **minder voorregte** het en jy **sal nie in staat wees om 'n nuwe gebruiker te skep deur sy permissies te misbruik nie**.\
> Tog het daardie gebruiker die **`seImpersonate`** voorreg, so jy kan die[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) gebruik. Dus, in hierdie geval is 'n rev shell 'n beter opsie as om te probeer 'n gebruiker te skep.

Op die oomblik van skryf word die **Task Scheduler**-diens met **Nt AUTHORITY\SYSTEM** uitgevoer.

Nadat jy die kwaadwillige Dll gegenereer het (in my geval het ek 'n x64 rev shell gebruik en ek het 'n shell teruggekry, maar Defender het dit doodgemaak omdat dit vanaf msfvenom was), stoor dit in die skryfbare System Path met die naam **WptsExtensions.dll** en **herbegin** die rekenaar (of herbegin die diens of doen wat nodig is om die betrokke diens/program weer te laat loop).

Wanneer die diens herbegin is, behoort die **dll** gelaai en uitgevoer te word (jy kan die **procmon**-truk hergebruik om te kontroleer of die biblioteek soos verwag gelaai is).

{{#include ../../../banners/hacktricks-training.md}}
