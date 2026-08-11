# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler, **alt süreçler** tarafından devralınır.

Şu işlemi gerçekleştirerek mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişkene mevcut oturumlarınız ve bunların alt süreçleri tarafından erişilebilecektir.

Bir değişkeni **şu şekilde kaldırabilirsiniz**:
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
`/proc/*/environ` içerikleri **NUL-separated** olduğundan, bu varyantlar genellikle okunması daha kolaydır:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Devralınan ortamlar içinde **credentials** veya **ilgi çekici servis yapılandırmaları** arıyorsanız [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümünü de kontrol edin.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekran anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyicisi.
- **HISTFILESIZE** – history file içinde bulunan satırların maksimum sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history file'a eklenen satır sayısı.
- **HOME** – home directory'niz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual page'leri aramak için kullanılacak dizinlerin listesi.
- **OSTYPE** – işletim sisteminin türü.
- **PS1** – bash'teki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary dosyalarını içeren tüm dizinlerin path'ini saklar; böylece dosyanın adını belirterek, relative veya absolute path belirtmenize gerek kalmadan çalıştırabilirsiniz.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut command shell'in path'i (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – time zone'unuz.
- **USER** – mevcut username'iniz.

## hacking için ilgi çekici değişkenler

Her değişken eşit derecede kullanışlı değildir. Offensive açıdan, **search path'lerini**, **startup file'larını**, **dynamic linker davranışını** veya **audit/logging** işlemlerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Bu değişkenin değerini 0 olarak değiştirin**; böylece **oturumunuzu sonlandırdığınızda** **history file** (\~/.bash_history) **0 satıra kısaltılır**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellekteki geçmişte tutulmaması** ve **history file**'a (\~/.bash_history) yazılmaması için bu **değişkenin değerini 0 olarak değiştirin**.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**Bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanmışsa**, başına fazladan bir boşluk eklenen herhangi bir komut geçmişe kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**'ı **`/dev/null`**'a yönlendirin veya tamamen unset edin. Bu, yalnızca history boyutunu değiştirmekten genellikle daha güvenilirdir.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Process'ler, **proxy** üzerinden internete http veya https aracılığıyla bağlanmak için burada tanımlanan **proxy**'yi kullanır.
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
Araçlara bağlı olarak hem küçük harfli hem de büyük harfli varyantlar kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

İşlemler, **bu env variables** içinde belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya package manager'lar gibi araçların attacker tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script, komutları **absolute path** kullanmadan çalıştırıyorsa, `PATH` içindeki **saldırganın kontrol ettiği ilk directory** kazanır. Bu, `sudo`, cron jobs, shell wrappers ve custom SUID helpers içindeki birçok **PATH hijack** işleminin temel primitive'idir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper'ları arayın.
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
Tam privilege-escalation zincirleri için `PATH` abuse tekniklerini inceleyin: [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç **dotfiles**, **plugins** ve **per-user configuration** dosyalarını `$HOME` veya `$XDG_CONFIG_HOME` konumundan otomatik olarak yükler. Privileged bir workflow bu değerleri koruyorsa, **config injection** binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özgü dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH ve LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek paylaşılan nesnelerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Kütüphane arama dizinlerini öne ekler.
- `LD_AUDIT`: Kütüphane yüklemelerini ve sembol çözümlemesini gözlemleyen auditor kütüphanelerini yükler.

Ayrıcalıklı bir komut bu değişkenleri koruyorsa, bunlar **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidir. **secure-execution** modunda (`AT_SECURE`, ör. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken loader aşamasındaki parser hataları, hedef programdan **önce** çalıştıkları için hâlâ yüksek etkiye sahiptir.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken aşamadaki davranışını (örneğin allocator tunable'larını) değiştirir ve exploit laboratuvarlarında oldukça kullanışlıdır. Ayrıca **dynamic loader bunu çok erken ayrıştırdığı** için güvenlik açısından da önemlidir. 2023'teki **Looney Tunables** bug'ı, loader'da ayrıştırılan tek bir environment variable'ın SUID programlarına karşı bir **local privilege-escalation primitive** hâline gelebileceğini hatırlattı.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV ve ENV**

**Bash** **etkileşimsiz** olarak başlatılırsa, hedef script'i çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve belirtilen dosyayı kaynak olarak yükler. Bash, `sh` olarak veya POSIX tarzı etkileşimli modda çağrıldığında `ENV` değişkenine de başvurabilir. Bu, ortam saldırganın kontrolündeyse bir shell wrapper'ını code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını yok sayar; `-p` etkin kimliği korur ancak bu başlangıç dosyalarını etkinleştirmez; dolayısıyla kesin davranış, wrapper'ın shell'i nasıl başlattığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran ayrıcalıklı wrapper'lara dikkat edin: Kimlikler yeniden eşleştiğinde Bash, aksi durumda yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell durumuna güvenebilir.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python'un nasıl başlatıldığını değiştirir:

- `PYTHONPATH`: import arama yollarını öne ekler.
- `PYTHONHOME`: standart library ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: interactive prompt'tan önce bir dosyayı çalıştırır.
- `PYTHONINSPECT=1`: bir script tamamlandıktan sonra interactive mode'a geçer.

Bunlar, kontrol edilebilir bir environment ile Python çağıran maintenance script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Yakın tarihli gerçek dünya örneklerinden biri, Ubuntu/Debian sistemlerindeki 2024 **needrestart** LPE vakasıydı: root sahibi scanner, ayrıcalıksız bir process'in `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyaladı ve ardından Python'ı çalıştırdı. Yayınlanan exploit, attacker-controlled path içine `importlib/__init__.so` yerleştirdi; böylece Python, helper'ın hard-coded script'i önem kazanmadan önce, kendi initialization süreci sırasında attacker kodunu çalıştırdı.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'in de benzer şekilde kullanışlı startup variable'ları vardır:

- `PERL5LIB`: library directory'lerini öne ekler.
- `PERL5OPT`: switch'leri her `perl` command line'ında yer alıyormuş gibi inject eder.

Bu, target script ilginç bir işlem yapmadan önce **automatic module loading** işlemini zorlayabilir veya interpreter davranışını değiştirebilir. Perl, **taint / setuid / setgid** context'lerinde bu variable'ları yok sayar; ancak normal root-run wrapper'ları, CI işleri, installer'lar ve özel sudoers rule'ları için hâlâ oldukça önemlidir.
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

`NODE_OPTIONS`, ortamı devralan her `node` process'ine **Node.js CLI flags** ekler. Bu nedenle wrapper'lara, CI job'larına, Electron helper'larına ve sonunda Node çağıran sudo kurallarına karşı kullanışlıdır. Saldırı açısından en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını preload eder.
- `--import <module>`: hedef script'ten önce bir ES module'ü preload eder.

Node, bazı tehlikeli flag'lerin `NODE_OPTIONS` içinde kullanılmasını reddeder; ancak `--require` ve `--import` açıkça izin verilen flag'lerdir ve normal command-line argümanlarından **önce** işlenir.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Dolaylı olarak `NODE_OPTIONS` ayarlayan remote gadget chain'ler için (örneğin prototype-pollution ile RCE), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby de aynı startup abuse sınıfını sunar:

- `RUBYLIB`: Ruby'nin load path'inin başına dizinler ekler.
- `RUBYOPT`: Her `ruby` çağrısına `-r` gibi command-line option'lar enjekte eder.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 **needrestart** vulnerabilities, bunun yalnızca bir lab trick olmadığını gösterdi: `PYTHONPATH` abuse'a karşı vulnerable olan aynı root-owned helper, attacker-controlled bir `RUBYLIB` ile Ruby çalıştırmaya ve `enc/encdb.so` dosyasını attacker directory'den yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar environment'dan yalnızca bir path okumaz; değeri bir **shell**'e, **editor**'e veya bir **input preprocessor**'a iletir. Bu nedenle privileged bir wrapper `git`, `man`, `less` veya benzer text viewer'larını çalıştırdığında aşağıdaki variable'lar özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command'ını seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: çoğunlukla argument'larla birlikte editor command'ını seçer.
- `LESSOPEN`, `LESSCLOSE`: `less` bir file açtığında çalışan pre/post-processor'ları tanımlar.
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
Git ayrıca diske dokunmadan **env-only config injection** işlemini `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` değişkenleri aracılığıyla destekler:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation perspective'ten, devralınan ortamların sıklıkla **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` avcılığı için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç job](<../images/image (740).png>)

Arka plana alınmış bir, iki ve üç job:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç job](<../images/image (145).png>)

Bir arka plan job'ı, durdurulmuş bir job ve son komut doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Bir arka plan job'ı, durdurulmuş bir job ve son komut doğru şekilde tamamlanmadı](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart içindeki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Yaygın environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so'sunda Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
