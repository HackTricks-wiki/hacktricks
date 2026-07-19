# Linux Ortam Değişkenleri

{{#include ../../banners/hacktricks-training.md}}

## Global değişkenler

Global değişkenler **alt süreçler** tarafından miras alınır.

Mevcut oturumunuz için şu şekilde bir global değişken oluşturabilirsiniz:
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
## Mevcut değişkenleri listeleme
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` içeriği **NUL ile ayrılmıştır**, bu nedenle bu varyantların okunması genellikle daha kolaydır:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Eğer devralınan ortamlarda **credentials** veya **ilginç servis yapılandırması** arıyorsanız, ayrıca [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) bölümünü de kontrol edin.

## Yaygın değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır; bu, mevcut bilgisayardaki ilk ekran anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyici.
- **HISTFILESIZE** – history dosyasında bulunan satırların maksimum sayısı.
- **HISTSIZE** – kullanıcı oturumunu sonlandırdığında history dosyasına eklenen satır sayısı.
- **HOME** – ana dizininiz.
- **HOSTNAME** – bilgisayarın hostname'i.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual sayfaları için aranacak dizinlerin listesi.
- **OSTYPE** – işletim sistemi türü.
- **PS1** – bash'teki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary dosyaları içeren tüm dizinlerin path bilgisini depolar; böylece dosyanın adını belirterek, relative veya absolute path belirtmeden çalıştırabilirsiniz.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut command shell'in path'i (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – saat diliminiz.
- **USER** – mevcut kullanıcı adınız.

## Hacking için ilginç değişkenler

Her değişken eşit derecede kullanışlı değildir. Offensive perspektiften, **search path'lerini**, **startup dosyalarını**, **dynamic linker davranışını** veya **audit/logging** işlemlerini değiştiren değişkenlere öncelik verin.

### **HISTFILESIZE**

**Oturumunuzu sonlandırdığınızda** **history dosyasının** (\~/.bash_history) **0 satıra truncate edilmesi** için **bu değişkenin değerini 0** olarak değiştirin.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Komutların **bellek içi geçmişte tutulmaması** ve **geçmiş dosyasına** (\~/.bash_history) geri yazılmaması için bu değişkenin **değerini 0** olarak değiştirin.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**Bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanırsa**, başına fazladan bir boşluk eklenen herhangi bir komut geçmişe kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**Geçmiş dosyasını** **`/dev/null`** konumuna yönlendirin veya tamamen unset edin. Bu, yalnızca geçmiş boyutunu değiştirmekten genellikle daha güvenilirdir.
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
### all_proxy & no_proxy

- `all_proxy`: bunu destekleyen araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken, proxy'yi atlayacak ana bilgisayarlar/alan adları/CIDR'ler listesi.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Hem küçük hem de büyük harfli varyantlar, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Process'ler **bu env variable'larda** belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP client'ları veya package manager'lar gibi araçların attacker tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, interception proxy'sinin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ayrıcalıklı bir wrapper/script, komutları **absolute paths** olmadan çalıştırırsa, `PATH` içindeki saldırganın kontrol ettiği ilk directory kazanır. Bu, `sudo`, cron jobs, shell wrappers ve özel SUID helpers içindeki birçok **PATH hijack** işleminin temelindeki primitive'dir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` gibi komutları adlarıyla çağıran wrapper'ları arayın.
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
`PATH` kullanan tam privilege-escalation zincirleri için [Linux Privilege Escalation](linux-privilege-escalation/README.md) bölümüne bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç **dotfiles**, **plugins** ve **per-user configuration** dosyalarını `$HOME` veya `$XDG_CONFIG_HOME` konumundan otomatik olarak yükler. Privileged bir workflow bu değerleri koruyorsa, **config injection** binary hijacking işleminden daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi tool-specific dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker**'ı etkiler:

- `LD_PRELOAD`: Ek shared object'lerin önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: Library arama dizinlerini öne alır.
- `LD_AUDIT`: Library loading ve symbol resolution işlemlerini gözlemleyen auditor library'leri yükler.

Ayrıcalıklı bir komut bunları koruyorsa **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidirler. **secure-execution** modunda (`AT_SECURE`, ör. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu kaldırır veya kısıtlar. Ancak bu erken loader aşamasındaki parser hataları, hedef programdan **önce** çalıştıkları için hâlâ yüksek etkiye sahiptir.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`, glibc davranışını erken aşamada (örneğin allocator tunable'larını) değiştirir ve exploit lab'lerinde oldukça kullanışlıdır. Ayrıca güvenlik açısından da önemlidir; çünkü **dynamic loader bunu çok erken aşamada parse eder**. 2023'teki **Looney Tunables** bug'ı, loader tarafından parse edilen tek bir environment variable'ın SUID programlarına karşı nasıl bir **local privilege-escalation primitive** hâline gelebileceğini iyi bir şekilde hatırlattı.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** **non-interaktif** olarak başlatılırsa, hedef script'i çalıştırmadan önce `BASH_ENV` değişkenini kontrol eder ve bu dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX tarzı interaktif modda çalıştırıldığında, `ENV` de okunabilir. Bu, ortamın saldırgan tarafından kontrol edildiği durumlarda bir shell wrapper'ını code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, `-p` kullanılmadığı sürece **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını kendisi devre dışı bırakır; dolayısıyla kesin davranış, wrapper'ın shell'i nasıl çağırdığına bağlıdır.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP ve PYTHONINSPECT**

Bu değişkenler Python'ın nasıl başlatılacağını değiştirir:

- `PYTHONPATH`: Import arama yollarını başa ekler.
- `PYTHONHOME`: Standart kütüphane ağacının konumunu değiştirir.
- `PYTHONSTARTUP`: Etkileşimli istemden önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: Bir script tamamlandıktan sonra etkileşimli moda geçer.

Bunlar, Python'ı kontrol edilebilir bir ortamla çağıran bakım script'lerine, debugger'lara, shell'lere ve wrapper'lara karşı kullanışlıdır. `python -E` ve `python -I`, tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl'in de aynı derecede kullanışlı başlangıç değişkenleri vardır:

- `PERL5LIB`: kütüphane dizinlerini başa ekler.
- `PERL5OPT`: anahtarları her `perl` komut satırındaymış gibi enjekte eder.

Bu, hedef script herhangi bir ilginç işlem yapmadan önce **otomatik modül yüklemeyi** zorlayabilir veya interpreter davranışını değiştirebilir. Perl, **taint / setuid / setgid** bağlamlarında bu değişkenleri yok sayar; ancak normal root tarafından çalıştırılan wrapper'lar, CI job'ları, installer'lar ve özel sudoers kuralları için hâlâ büyük önem taşırlar.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Aynı fikir diğer runtime'larda da (`RUBYOPT`, `NODE_OPTIONS`, vb.) geçerlidir: bir interpreter privileged wrapper tarafından başlatıldığında, **module loading** veya **startup behavior**'ı değiştiren env var'ları arayın.

Post-exploitation açısından, miras alınan environment'ların genellikle **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` aramaları için [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) sayfasına bakın.

### PS1

Prompt'unuzun görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Bu bir örnektir](<../images/image (897).png>)

Normal kullanıcı:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç job](<../images/image (740).png>)

Arka planda çalışan bir, iki ve üç job:

![PERL5OPT & PERL5LIB - PS1: Arka planda çalışan bir, iki ve üç job](<../images/image (145).png>)

Bir arka plan job'ı, durdurulmuş bir job ve son command doğru şekilde tamamlanmadı:

![PERL5OPT & PERL5LIB - PS1: Bir arka plan job'ı, durdurulmuş bir job ve son command doğru şekilde tamamlanmadı](<../images/image (715).png>)

## Referanslar

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
