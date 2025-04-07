# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

As jy gevind het dat jy **in 'n Stelselpaaie-gids kan skryf** (let daarop dat dit nie sal werk as jy in 'n Gebruikerspaaie-gids kan skryf nie), is dit moontlik dat jy **privileges kan eskaleer** in die stelsel.

Om dit te doen, kan jy 'n **Dll Hijacking** misbruik waar jy 'n **biblioteek wat deur 'n diens of proses gelaai word, gaan oorneem** met **meer privileges** as joune, en omdat daardie diens 'n Dll laai wat waarskynlik glad nie in die hele stelsel bestaan nie, gaan dit probeer om dit van die Stelselpaaie te laai waar jy kan skryf.

Vir meer inligting oor **wat Dll Hijacking is**, kyk:

{{#ref}}
./
{{#endref}}

## Privesc met Dll Hijacking

### Vind 'n ontbrekende Dll

Die eerste ding wat jy nodig het, is om 'n **proses te identifiseer** wat met **meer privileges** as jy loop en wat probeer om 'n **Dll van die Stelselpaaie** te laai waarin jy kan skryf.

Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds loop. Om te vind watter Dlls die dienste ontbreek, moet jy procmon so gou as moontlik begin (voordat prosesse gelaai word). So, om ontbrekende .dlls te vind, doen:

- **Skep** die gids `C:\privesc_hijacking` en voeg die pad `C:\privesc_hijacking` by die **Stelselpaaie omgewingsvariabele**. Jy kan dit **handmatig** doen of met **PS**:
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
- Begin **`procmon`** en gaan na **`Options`** --> **`Enable boot logging`** en druk **`OK`** in die prompt.
- Dan, **herbegin**. Wanneer die rekenaar herbegin, sal **`procmon`** begin **gebeurtenisse opneem** so gou as moontlik.
- Sodra **Windows** **begin** het, voer **`procmon`** weer uit, dit sal jou vertel dat dit aan die gang was en sal **vraag of jy die** gebeurtenisse in 'n lêer wil stoor. Sê **ja** en **stoor die gebeurtenisse in 'n lêer**.
- **Nadat** die **lêer** **gegenereer** is, **sluit** die oop **`procmon`** venster en **open die gebeurtenis lêer**.
- Voeg hierdie **filters** by en jy sal al die Dlls vind wat 'n **proses probeer het om te laai** vanaf die skryfbare Stelselpaaie-gids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Gemiste Dlls

Ek het hierdie resultate gekry deur dit in 'n gratis **virtuele (vmware) Windows 11 masjien** te loop:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is die .exe nutteloos, so ignoreer hulle, die gemiste DLLs was van:

| Diens                           | Dll                | CMD lyn                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Taak Skedule (Schedule)        | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostiese Beleid Diens (DPS)| Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nadat ek dit gevind het, het ek hierdie interessante blogpos gevind wat ook verduidelik hoe om [**WptsExtensions.dll vir privesc te misbruik**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Dit is wat ons **nou gaan doen**.

### Exploitatie

So, om **privileges te verhoog** gaan ons die biblioteek **WptsExtensions.dll** kaap. Met die **pad** en die **naam** moet ons net die **kwaadwillige dll** genereer.

Jy kan [**enige van hierdie voorbeelde probeer**](#creating-and-compiling-dlls). Jy kan payloads soos: kry 'n rev shell, voeg 'n gebruiker by, voer 'n beacon uit...

> [!WARNING]
> Let daarop dat **nie al die dienste** met **`NT AUTHORITY\SYSTEM`** gedraai word nie, sommige word ook met **`NT AUTHORITY\LOCAL SERVICE`** gedraai wat **minder privileges** het en jy **sal nie in staat wees om 'n nuwe gebruiker te skep** om sy toestemmings te misbruik.\
> Tog, daardie gebruiker het die **`seImpersonate`** voorreg, so jy kan die [**potato suite gebruik om privileges te verhoog**](../roguepotato-and-printspoofer.md). So, in hierdie geval is 'n rev shell 'n beter opsie as om te probeer om 'n gebruiker te skep.

Op die tyd van skryf word die **Taak Skedule** diens met **Nt AUTHORITY\SYSTEM** gedraai.

Nadat ek die **kwaadwillige Dll** (_in my geval het ek x64 rev shell gebruik en ek het 'n shell teruggekry maar defender het dit doodgemaak omdat dit van msfvenom was_), stoor dit in die skryfbare Stelselpaaie met die naam **WptsExtensions.dll** en **herbegin** die rekenaar (of herbegin die diens of doen wat ook al nodig is om die betrokke diens/program weer te laat loop).

Wanneer die diens weer begin, moet die **dll gelaai en uitgevoer** word (jy kan die **procmon** truuk hergebruik om te kyk of die **biblioteek soos verwag gelaai is**).

{{#include ../../../banners/hacktricks-training.md}}
