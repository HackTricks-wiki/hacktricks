# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

As jy **na 'n gids in die stelselwye `PATH` kan skryf** (nie slegs na jou gebruiker se `PATH` nie), kan jy moontlik **voorregte op die stelsel eskaleer**.

Dit kan deur **DLL hijacking** misbruik word wanneer 'n diens of proses met meer voorregte probeer om 'n DLL te laai wat nie in sy vroeëre soekliggings bestaan nie, en uiteindelik die skryfbare stelsel-`PATH`-gids deursoek.

'n Skryfbare Machine `PATH`-inskrywing is slegs 'n **primitive**, nie bewys van kode-uitvoering nie. Vir 'n onverpakte toepassing wat die standaard soekvolgorde gebruik, word `PATH` bereik ná redirection, API sets, SxS, die lys van gelaaide modules, KnownDLLs, die toepassing- en Windows-gidse, en die huidige gids. 'n Volledige pad of `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories`-beleid kan `PATH` heeltemal uitsluit.<sup>[[4]](#references)</sup>

Vir meer inligting oor **DLL hijacking**, sien:

{{#ref}}
./
{{#endref}}

## Privesc met DLL Hijacking

### Vind 'n Ontbrekende DLL

Identifiseer eers **'n proses** wat met **meer voorregte** loop en probeer om **'n DLL uit 'n skryfbare stelsel-`PATH`-gids te laai**.

Onthou dat hierdie tegniek van 'n **Machine/System PATH**-inskrywing afhanklik is, nie slegs van jou **User PATH** nie. Daarom is dit die moeite werd om, voordat jy tyd aan Procmon bestee, die **Machine PATH**-inskrywings te enumeriseer en te kontroleer watter daarvan skryfbaar is:<sup>[[1]](#references)</sup>
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
ACL-teks kan misleidend wees omdat groeplidmaatskap, deny ACEs en geërfde permissions die resultaat beïnvloed. In ’n gemagtigde toets kontroleer ’n create/delete probe die **effektiewe toegang van die huidige token** (dit is intrusief en kan alerts genereer):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Bevestig die teiken se effektiewe `PATH`

Die Machine `PATH` wat uit die registry gelees word, is konfigurasiedata; die loader gebruik die environment block van die **target process**. Elke process besit ’n environment block, en ’n child erf normaalweg ’n kopie van sy parent se environment. Gevolglik kan ’n langlopende service ’n ouer waarde behou, en ’n service wat met ’n custom environment geloods word, kan verskil van die waarde wat in jou shell sigbaar is. Behandel ’n Procmon-probe van die presiese directory deur die target PID as die grondwaarheid; nadat jy `PATH` in ’n lab verander het, herbegin die relevante process tree of reboot voordat jy tot die gevolgtrekking kom dat die lookup nie plaasvind nie.<sup>[[5]](#references)</sup>

Die probleem in hierdie gevalle is dat daardie processes waarskynlik reeds loop. Om DLLs te identifiseer wat services probeer en nie daarin slaag om te laai nie, launch Procmon so vroeg as moontlik (voordat die processes start), en dan:

> [!WARNING]
> Deur ’n user-writable directory by die Machine `PATH` te voeg, **skep jy die kwesbare toestand**. Doen dit slegs in ’n geïsoleerde research VM om te onthul watter privileged processes die `PATH` bereik; op ’n assessed host, monitor die bestaande writable entry sonder om die system configuration te verander.<sup>[[1]](#references)</sup>

- **Skep** die folder `C:\privesc_hijacking` en voeg die path `C:\privesc_hijacking` by **System Path env variable**. Jy kan dit **manually** of met **PS** doen:
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
- **Herlaai** daarna. Wanneer die rekenaar herbegin word, sal **`procmon`** so gou moontlik begin om gebeurtenisse **op te neem**.
- Sodra **Windows** **begin is, voer `procmon`** weer uit. Dit sal aandui dat dit reeds geloop het en jou **vra of jy die gebeurtenisse wil stoor** in ’n lêer. Sê **ja** en **stoor die gebeurtenisse in ’n lêer**.
- **Nadat** die **lêer** **gegenereer** is, **maak** die oop **`procmon`**-venster **toe** en **maak die gebeurtenisselêer oop**.
- Voeg hierdie **filters** by om alle DLLs te vind wat ’n **process probeer het om te laai** vanaf die writable System Path-lêergids:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** is slegs nodig vir services wat **te vroeg begin** om andersins waargeneem te word. Indien jy die teiken-service/program **op aanvraag kan trigger** (byvoorbeeld deur met sy COM-interface te interaksie, die service te herbegin, of ’n scheduled task weer te begin), is dit gewoonlik vinniger om ’n normale Procmon-capture te hou met filters soos **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, en **`Path begins with <writable_machine_path>`**.

### DLLs wat gemis is

Toe ek dit in ’n gratis **virtuele (vmware) Windows 11-masjien** uitgevoer het, het ek hierdie resultate gekry:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Ignoreer in hierdie geval die `.exe`-resultate. Die ontbrekende-DLL-probes het gekom van:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Die volgende voorbeeld gebruik die tegniek wat in hierdie artikel beskryf word oor [**misbruik van `WptsExtensions.dll` vir privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Ander kandidate wat die moeite werd is om te triage

`WptsExtensions.dll` is ’n goeie voorbeeld, maar dit is nie die enigste herhalende **phantom DLL** wat in bevoorregte services voorkom nie. Moderne hunting-reëls en publieke hijack-katalogusse hou steeds name dop soos:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassieke **SYSTEM**-kandidaat op client-stelsels. Goed wanneer die writable directory in die **Machine PATH** is en die service die DLL tydens startup ondersoek. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessant op **server editions** omdat die service as **SYSTEM** loop en in sommige builds **op aanvraag deur ’n normale user getrigger kan word**, wat dit beter maak as gevalle wat slegs met ’n reboot werk. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Lewer gewoonlik eers **`NT AUTHORITY\LOCAL SERVICE`**. Dit is dikwels steeds voldoende omdat die token **`SeImpersonatePrivilege`** het, sodat jy dit kan chain met [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Behandel hierdie name as **triage-wenke**, nie as gewaarborgde suksesse nie: hulle is **afhanklik van die SKU/build**, en Microsoft kan die gedrag tussen releases verander. Die belangrike gevolgtrekking is om te soek na **ontbrekende DLLs in bevoorregte services wat deur die Machine PATH beweeg**, veral indien die service **weer getrigger kan word sonder om te reboot**.

### Valideer ’n kandidaat voordat jy dit weaponize

’n `NAME NOT FOUND`-gebeurtenis op sigself is nie genoeg nie. Voordat jy ’n payload plaas, verifieer die volledige ketting:<sup>[[1]](#references)[[4]](#references)</sup>

1. Die gebeurtenis behoort aan die verwagte **PID, command line, service account en integrity level**, en die ontbrekende path is die presiese writable Machine `PATH`-directory.
2. Vir dieselfde DLL-basename gee geen vroeëre directory `SUCCESS` terug nie, en die module word nie deur die loaded-module list, KnownDLLs, redirection of ’n SxS-manifest voorsien nie.
3. Die probe herhaal wanneer ’n low-privileged user die bedoelde trigger aanroep. ’n Lookup wat slegs tydens boot plaasvind, is bruikbaar, maar operasioneel baie slegter as een op aanvraag.
4. Die payload-argitektuur stem met die process ooreen. Indien die application later exports resolve, proxy die legitieme DLL of export die verwagte symbols; sien [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Gebruik eers ’n harmless canary DLL wat die PID, identity en timestamp aanteken. Vereis in Procmon ’n suksesvolle **`Load Image`** vanaf die planted path, eerder as om aan te neem dat ’n voorafgaande file probe execution veroorsaak het.

### Exploitation

Om **privileges te eskaleer**, hijack **`WptsExtensions.dll`**. Sodra die **path** en **name** bekend is, genereer die malicious DLL.

Jy kan [**probeer om enige van hierdie voorbeelde te gebruik**](README.md#creating-and-compiling-dlls). Jy kan payloads uitvoer soos: ’n rev shell kry, ’n user byvoeg, ’n beacon uitvoer...

> [!WARNING]
> Let daarop dat **nie alle services** as **`NT AUTHORITY\SYSTEM`** loop nie. Sommige loop as **`NT AUTHORITY\LOCAL SERVICE`**, wat **minder privileges** het, dus mag misbruik van een van hierdie services jou nie toelaat om ’n nuwe user te skep nie.\
> Daardie account het egter die **`SeImpersonatePrivilege`**-userreg, sodat jy die [**Potato suite kan gebruik om privileges te eskaleer**](../roguepotato-and-printspoofer.md). In hierdie geval is ’n reverse shell ’n beter opsie as om ’n user te probeer skep.

Die **Task Scheduler**-service loop normaalweg as **`NT AUTHORITY\SYSTEM`**, maar verifieer die werklike deployment en moenie die execution identity slegs uit die service se naam aflei nie:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Nadat jy die **malicious Dll gegenereer** het (_in my geval het ek x64 rev shell gebruik en ’n shell teruggekry, maar Defender het dit gekanselleer omdat dit van msfvenom afkomstig was_), stoor dit in die skryfbare System Path met die naam **WptsExtensions.dll** en **herbegin** die rekenaar (of herbegin die diens, of doen wat ook al nodig is om die betrokke diens/program weer uit te voer).

Wanneer die diens herbegin word, behoort die **DLL gelaai en uitgevoer te word** (jy kan die **Procmon**-truuk hergebruik om te kontroleer of die **library soos verwag gelaai is**).

> [!NOTE]
> Beplan opruiming voordat jy dit aktiveer. ’n Diens kan die DLL gemapped hou en die lêer sluit totdat dit stop; vir `WptsExtensions.dll` vereis die stop van Task Scheduler verhoogde regte. Nadat jy die beoogde konteks verkry het, stop die teiken veilig, verwyder die payload en herstel enige `PATH`-verandering wat slegs vir die lab gemaak is.<sup>[[1]](#references)</sup>

### Remediëring / opsporing

Verwyder swak skryftoestemmings uit elke Machine `PATH`-gids en verwyder verouderde inskrywings. Developers behoort trusted libraries met ’n volledige pad te laai of resolusie te beperk met `SetDefaultDllDirectories` / `LoadLibraryEx` search flags. Defenders kan veranderinge aan die Machine `PATH` korreleer met privileged processes wat DLLs vanaf nie-stelsel-, user-writable directories laai.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Hopelik) Toegelig](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Verdagte DLL Gelaai vir Persistence of Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
