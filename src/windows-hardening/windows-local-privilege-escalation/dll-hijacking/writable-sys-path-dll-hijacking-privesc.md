# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

As jy **na 'n gids in die stelselwye `PATH`** kan **skryf** (nie bloot na jou gebruiker se `PATH` nie), kan jy moontlik **voorregte op die stelsel eskaleer**.

Dit kan deur **DLL hijacking** misbruik word wanneer 'n diens of proses met meer **voorregte** probeer om 'n DLL te laai wat nie in sy vroeëre soekliggings bestaan nie, en uiteindelik die skryfbare stelsel-`PATH`-gids deursoek.

Vir meer inligting oor **DLL hijacking**, sien:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

Identifiseer eers **'n proses** wat met **meer voorregte** loop en probeer om **'n DLL uit 'n skryfbare stelsel-`PATH`-gids te laai**.

Onthou dat hierdie tegniek van 'n **Machine/System PATH**-inskrywing afhanklik is, nie slegs van jou **User PATH** nie. Daarom is dit, voordat jy tyd aan Procmon bestee, die moeite werd om die **Machine PATH**-inskrywings te enumerasie en te kontroleer watter daarvan skryfbaar is:<sup>[[1]](#references)</sup>
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
Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds loop. Om DLLs te identifiseer wat dienste probeer laai maar nie daarin slaag nie, begin Procmon so vroeg as moontlik (voordat die prosesse begin), en dan:

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
- Begin **`procmon`** en gaan na **`Options`** --> **`Enable boot logging`**, en druk **`OK`** in die prompt.
- **Herlaai** die rekenaar. Wanneer die rekenaar herbegin is, sal **`procmon`** so gou moontlik begin om gebeurtenisse **op te neem**.
- Sodra **Windows** **begin het, voer `procmon`** weer uit. Dit sal jou meedeel dat dit reeds geloop het en jou **vra of jy die gebeurtenisse in ’n lêer wil stoor**. Sê **ja** en **stoor die gebeurtenisse in ’n lêer**.
- **Nadat** die **lêer** **gegenereer** is, **sluit** die oop **`procmon`**-venster en **maak die gebeurtenisselêer oop**.
- Voeg hierdie **filters** by om alle DLL's te vind wat ’n **proses probeer laai het** vanaf die writable System Path-lêergids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** word slegs benodig vir dienste wat **te vroeg begin** om andersins waargeneem te word. As jy die teikendiens/-program **op aanvraag kan aktiveer** (byvoorbeeld deur met sy COM-interface te kommunikeer, die diens te herbegin, of ’n geskeduleerde taak weer te begin), is dit gewoonlik vinniger om ’n normale Procmon-opname te hou met filters soos **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, en **`Path begins with <writable_machine_path>`**.

### Gemiste DLL's

Toe ek dit in ’n gratis **virtuele (vmware) Windows 11-masjien** uitgevoer het, het ek hierdie resultate gekry:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In hierdie geval, ignoreer die `.exe`-resultate. Die ontbrekende-DLL-probes het gekom van:

| Diens                         | DLL                | CMD line                                                             |
| ----------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Die volgende voorbeeld gebruik die tegniek wat in hierdie artikel beskryf word oor [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Ander kandidate wat die moeite werd is om te triage

`WptsExtensions.dll` is ’n goeie voorbeeld, maar dit is nie die enigste herhalende **phantom DLL** wat in bevoorregte dienste voorkom nie. Moderne hunting-reëls en publieke hijack-katalogusse volg steeds name soos die volgende:<sup>[[2]](#references)</sup>

| Diens / Scenario | Ontbrekende DLL | Aantekeninge |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassieke **SYSTEM**-kandidaat op kliëntstelsels. Goed wanneer die writable directory in die **Machine PATH** is en die diens tydens startup vir die DLL soek. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessant op **server editions**, omdat die diens as **SYSTEM** loop en in sommige builds **op aanvraag deur ’n normale gebruiker geaktiveer kan word**, wat dit beter maak as gevalle wat slegs ná ’n reboot werk. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Lewer gewoonlik eers **`NT AUTHORITY\LOCAL SERVICE`**. Dit is dikwels steeds voldoende, omdat die token **`SeImpersonatePrivilege`** het; jy kan dit dus aan [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) koppel. |

Beskou hierdie name as **triage-wenke**, nie as gewaarborgde suksesse nie: hulle is **SKU/build-afhanklik**, en Microsoft kan die gedrag tussen releases verander. Die belangrike wegneempunt is om te soek na **ontbrekende DLL's in bevoorregte dienste wat deur die Machine PATH beweeg**, veral as die diens **weer geaktiveer kan word sonder om te reboot**.

### Exploitation

Om **privileges te eskaleer**, hijack **`WptsExtensions.dll`**. Sodra die **pad** en **naam** bekend is, genereer die malicious DLL.

Jy kan [**probeer om enige van hierdie voorbeelde te gebruik**](#creating-and-compiling-dlls). Jy kan payloads uitvoer soos: ’n rev shell kry, ’n gebruiker byvoeg, ’n beacon uitvoer...

> [!WARNING]
> Let daarop dat **nie alle dienste** as **`NT AUTHORITY\SYSTEM`** loop nie. Sommige loop as **`NT AUTHORITY\LOCAL SERVICE`**, wat **minder privileges** het; daarom sal abusing van een van hierdie dienste jou moontlik nie toelaat om ’n nuwe gebruiker te skep nie.\
> Daardie rekening het egter die **`SeImpersonatePrivilege`**-gebruikersreg, sodat jy die [**Potato suite kan gebruik om privileges te eskaleer**](../roguepotato-and-printspoofer.md). In hierdie geval is ’n reverse shell ’n beter opsie as om ’n gebruiker te probeer skep.

Ten tyde van die skryf hiervan loop die **Task Scheduler**-diens met **Nt AUTHORITY\SYSTEM**.

Nadat jy die **malicious DLL gegenereer het** (_in my geval het ek x64 rev shell gebruik en ’n shell teruggekry, maar defender het dit beëindig omdat dit van msfvenom afkomstig was_), stoor dit in die writable System Path met die naam **WptsExtensions.dll** en **herbegin** die rekenaar (of herbegin die diens, of doen wat ook al nodig is om die geaffekteerde diens/program weer te laat loop).

Wanneer die diens herbegin word, behoort die **DLL gelaai en uitgevoer te word** (jy kan die **`procmon`**-truuk **hergebruik** om te kontroleer of die **library soos verwag gelaai is**).

## References

- [1] [Windows DLL Hijacking (Hopelik) Opgeklaar](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Verdagte DLL gelaai vir Persistence of Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
