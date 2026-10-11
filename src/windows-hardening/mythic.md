# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic nedir?

Mythic, red teaming için tasarlanmış açık kaynaklı, modüler ve iş birliğine dayalı bir command and control (C2) framework'üdür. Operatörlerin Windows, Linux ve macOS dahil farklı işletim sistemlerinde agent'ları (payload'ları) yönetmesine ve dağıtmasına olanak tanır. Mythic; birden fazla operatörün görev ataması, dosya işlemleri, SOCKS/rpfwd yönetimi ve payload oluşturması için bir tarayıcı arayüzü sunar.

Monolitik framework'lerin aksine Mythic deposu, payload türlerini veya C2 profillerini **içermez**. Agent'lar, wrapper'lar ve C2 profilleri genellikle harici bileşenler olarak kurulur ve Mythic çekirdeğinden bağımsız olarak güncellenebilir.

### Kurulum

Mythic'i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin. Mythic dizininden yaygın bir başlangıç komutu şöyledir:

```bash
sudo make
sudo ./mythic-cli start
```

Mythic zaten çalışıyorsa, genellikle `./mythic-cli install github ...` komutuyla yeni bir agent veya profil ekleyebilir, ardından Mythic'i yeniden başlatabilir ya da yalnızca yeni bileşeni doğrudan başlatabilirsiniz.

### Agents

Mythic, ele geçirilmiş sistemlerde görevleri yerine getiren **payload'lar** olan birden fazla agent'ı destekler. Her agent belirli ihtiyaçlara göre özelleştirilebilir ve farklı işletim sistemlerinde çalışabilir.

Mythic'te varsayılan olarak yüklü agent bulunmaz. Açık kaynak topluluğunun agent'ları [**https://github.com/MythicAgents**](https://github.com/MythicAgents) adresinde bulunur ve [**topluluk özellik matrisi**](https://mythicmeta.github.io/overview/agent_matrix.html), desteklenen işletim sistemlerini, payload biçimlerini, wrapper'ları ve C2 profillerini hızlıca kontrol etmek için kullanışlıdır.<sup>[[1]](#references)</sup>

Bu kuruluştan bir agent yüklemek için şu komutu çalıştırabilirsiniz:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

`sudo -E` biçimi, root olmayan bir ortamdan kurulum yaparken kullanışlıdır. Mythic zaten çalışıyor olsa bile önceki komutla yeni agent'lar ekleyebilirsiniz.

### C2 Profiles

Mythic'teki C2 profiles, **agent'ların Mythic sunucusuyla nasıl iletişim kurduğunu** tanımlar. İletişim protokolünü, şifreleme yöntemlerini ve diğer ayarları belirtir. Mythic web arayüzü üzerinden C2 profiles oluşturabilir ve yönetebilirsiniz.

Mythic varsayılan olarak profiles olmadan kurulur; ancak [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) repo'sundan bazı profiles indirmek mümkündür. Bunun için şunu çalıştırın:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Operatörler açısından güncel ve akılda tutulması gereken profiller:

- [`http`](https://github.com/MythicC2Profiles/http): temel asenkron GET/POST trafiği.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): birden fazla callback domain'i, fail-over/round-robin rotation, özel headers/query parameters ve cookie'lere, headers'a, query parameters'a veya body'ye yerleştirilen message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) ile daha esnek HTTP trafiği.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): statik `http` profile fazla tanınabilir olduğunda JSON/TOML ile yönlendirilen HTTP message shaping.

### Güncel platform notları

- Birçok genel kullanıma açık agent ve profile artık önceden oluşturulmuş uzak container image'larıyla kurulur.
  Bir component'i fork ederseniz veya yerel olarak yamalarsanız ve Mythic eski
  davranışı kullanmaya devam ederse, oluşturulan `.env` girdilerinde
  `*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` ve `*_USE_VOLUME` değerlerini inceleyin;
  `*_USE_BUILD_CONTEXT="true"` ayarını etkinleştirmek, Mythic'in uzak image'ı
  fark ettirmeden yeniden kullanmak yerine genellikle yerel Docker context'inizden
  yeniden build etmesini sağlar.
- Browser scripts, operatörler için Mythic'in en kullanışlı özelliklerinden
  biridir: ham command output'u tablolara, screenshot görüntüleyicilerine,
  download bağlantılarına, arama bağlantılarına ve doğrudan UI üzerinden yeni
  tasking gönderen butonlara dönüştürebilirler. Güncel Mythic build'leri her
  operatörün kendi script'lerini kullanmasına, bunları genel olarak veya görev
  başına açıp kapatmasına olanak tanır. En iyi sonuçlar, agent'lar plaintext
  yerine yapılandırılmış JSON döndürdüğünde elde edilir. Bu özellik özellikle
  tekrarlanan `ls`, `ps`, triage ve file-browser iş akışlarında kullanışlıdır.<sup>[[4]](#references)[[6]](#references)</sup>
- Daha yeni Mythic build'leri, PTY/SOCKS/rpfwd ağırlıklı operasyonlarda
  `sleep 0` polling ihtiyacını azaltan interactive tasking ve Push C2
  pattern'lerini de destekler. Agent/profile destekliyorsa bu, sırf interactive
  channel kullanılabilir kalsın diye sunucuyu sürekli check-in'lerle
  zorlamaktan genellikle daha düşük overhead sağlar.<sup>[[3]](#references)</sup>
- Güncel 3.4 dönemi Mythic builder'ları, eski yazıların ima ettiğinden daha
  fazla context-aware'dir: build parameters artık seçilen OS veya diğer build
  seçeneklerine göre gruplanabilir ya da gizlenebilir; payload type'ları bir
  build'de birden fazla C2 profile'ı veya aynı C2'nin birden fazla instance'ını
  destekleyip desteklemediklerini belirtebilir; C2 parameter deviation'ları ise
  bir agent'ın gerçekten implement etmediği alanları gizlemesine olanak tanır.
  `http`, `httpx`, `smb`, `tcp` ve `websocket` arasında geçiş yaparken bu
  önemlidir; çünkü güvenli/geçerli build seçenekleri artık düz, statik bir form
  değildir.<sup>[[5]](#references)</sup>
- Özel bir agent/profile çifti oluşturuyorsanız ve Mythic'in JSON message
  formatını veya varsayılan crypto'yu wire üzerinde kullanmak istemiyorsanız,
  `translation_container` kullanın: Mythic UUID'yi çıkarır, şifrelenmiş blob'u
  ve key material'ı gRPC üzerinden translator'a iletir ve karşılığında
  agent-native byte'lar bekler. Sunucunun tamamını yeniden yazmadan binary
  protocol'leri, özel framing'i veya agent tarafında şifrelemeyi desteklemenin
  temiz yolu budur.
- Linked/P2P callback'lerin yalnızca tasking'i iletmediğini unutmayın.
  Mythic'in `get_tasking` akışı responses ile birlikte `delegates`, `socks`,
  `rpfwd` ve `interactive` verilerini de taşıyabilir. Uygulamada, tek bir
  egress callback aynı polling loop içinde inner callback'lere ve pivot
  channel'larına hizmet verebilir; child agent'lar kendi periyodik check-in'lerini
  yapıyorsa `get_delegate_tasks=false` ayarı parent'ın inner callback'in
  kuyruğa alınmış işlerini yanlışlıkla tüketmesini önler.

### Wrapper payload'ları

Wrapper payload'ları, teslim edilen veya diske kaydedilen gösterimi değiştirirken aynı agent mantığını korumanıza olanak tanır.

- `service_wrapper`: başka bir payload'ı Windows service executable'ına dönüştürür; bu, execution path geçerli bir service binary gerektirdiğinde kullanışlıdır.
- `scarecrow_wrapper`: uyumlu shellcode'u ScareCrow loader ile sararak EXE/DLL/CPL gibi loader destekli çıktılar oluşturur.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps eğitim programlarında kullanılmak üzere tasarlanmış, 4.0 .NET Framework'ü kullanan C# ile yazılmış bir Windows agent'ıdır.<sup>[[2]](#references)</sup>

Şu komutla kurun:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Güncel build/profile notları

- Apollo şu anda `WinExe`, `Shellcode`, `Service` ve `Source` payload'ları üretebilir.
- Yaygın olarak kullanılan Apollo profilleri `http`, `httpx`, `smb`, `tcp` ve `websocket`'tir.
- Domain rotation, proxy desteği, özel mesaj yerleşimi ve message transform'larına ihtiyaç duyduğunuzda `httpx`, eski statik `http` profiline kıyasla genellikle daha esnek bir seçenektir.
- Apollo, topluluk ajanları arasında özellikleri en kapsamlı olanlardan biridir ve şu anda Mythic tarafında browser scripts, file/process browser görünümleri, screenshots, keylogging, SOCKS, rpfwd, Push C2 ve P2P routing gibi entegrasyonlar sunar.
- Apollo, `service_wrapper` ve `scarecrow_wrapper` gibi wrapper payload'larını destekler.
- Apollo, dinamik command loading'i destekler; böylece ilk payload'ı küçük tutabilir, her post-ex kabiliyetini ilk build'e derlemek yerine daha sonra ek komutlar veya Forge modules yükleyebilirsiniz.
- Shellcode çıktısı oluştururken Apollo'nun güncel builder'ı Donut formatı seçeneklerini (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) ve Donut bypass davranışlarını (`None`, `Abort on fail`, `Continue on fail`) da sunar. Bu, shellcode'u `service_wrapper`, `scarecrow_wrapper` veya özel bir loader ile yeniden sarmalamak istediğinizde kullanışlıdır.
- `register_file` ve `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` ve `powerpick` için staging primitive'leridir. Güncel Apollo build'lerinde bu staged artifact'ler istemci tarafında DPAPI korumalı AES256 blob'ları olarak önbelleğe alınır.
- `ls` ve `ps` sonuçları Mythic'in browser scripts ve file/process browser özellikleriyle özellikle iyi entegre olur; bu da iş birliğine dayalı operasyonlarda operatör triyajını belirgin ölçüde hızlandırır.
- Apollo'nun fork-and-run işleri, sacrificial process ayarlarını
  `spawnto_x86` / `spawnto_x64`'ten devralır, üst process seçimini `ppid`'den
  devralır ve ardından o anda seçili injection primitive'ini kullanır. Uygulamada
  bu, tek bir komut için yaptığınız OPSEC ayarlarının çoğu zaman aynı anda
  `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` ve
  `spawn` komutlarını da etkilediği anlamına gelir.
- Belgelenmiş güncel Apollo injection backend'leri arasında `CreateRemoteThread`,
  syscalls üzerinden `QueueUserAPC` (early-bird tarzı) ve `NtCreateThreadEx`
  bulunur. Gürültülü post-exploitation işlemlerinden önce
  `get_injection_techniques` kullanın; hedefle veya çalıştırmak istediğiniz
  komutla çakışan bir primitive'den vazgeçmeniz gerekiyorsa
  `set_injection_technique` kullanın.
- `blockdlls` yalnızca post-exploitation işleri için oluşturulan sacrificial
  process'leri etkiler. Bunu, varsayılan yalın `rundll32.exe` yerine daha az
  şüpheli bir `spawnto_x64` hedefiyle birlikte kullanmak, assembly/PowerShell
  ağırlıklı tasking'i çalıştırmadan önce Apollo tarafında yapabileceğiniz en
  kolay değişikliklerden biridir.

### Detection-aware .NET agent build pipeline

Detection-aware bir Apollo fork'u, son aşamadaki bir **`obfuscate.exe` adımı** olarak değil, **bütün bir build-system sorunu** olarak ele alınmalıdır. Bu vaka çalışması, genel [AV evasion methodology](av-bypass.md) ve [.NET inspection tools](../reversing/reversing-tools-basic-methods/README.md) konularını tamamlar: wire identifier'larda, IL metadata'da, dependency packaging'de, reflection'da ve dinamik olarak derlenen task'lerde yapılan değişiklikler tek bir uyumluluk sınırı oluşturur.<sup>[[8]](#references)</sup>

#### YARA-aware protocol mutation

Kodu değiştirmeden önce herkese açık file/memory rule'larını denetleyin. Örneğin, Elastic'ın `Multi_Trojan_Mythic_4beb7e17` kuralı; `task_id`, `post_response`, `c2_profile`, `get_tasking` ve `get_delegate_tasks` dahil Mythic JSON/action string'lerinden herhangi **7'si 11'inin** bulunduğunda eşleşir. Yeterli sayıda alanı yeniden adlandırmak bu eşiği aşabilir; ancak bunlar kozmetik semboller değil, protocol değerleridir: agent ve ilgili server/profile implementasyonu birlikte değiştirilmelidir.<sup>[[7]](#references)[[8]](#references)</sup>

Bu, yalnızca tek bir statik özellik kümesini ortadan kaldırır. Check-in sıklığı, mesaj yapısı, task/response akışı ve runtime string reconstruction davranışsal veya bellek göstergeleri olarak kalabilir; bu nedenle temiz bir string taramasını başarı saymak yerine hem build edilmiş artifact'i hem de çalıştırılmış bir callback'i doğrulayın.<sup>[[8]](#references)</sup>

#### Global transform'ları uygulamadan önce merge edin

Costura gibi araçlarla resource embedding yapıldığında companion assembly'ler sıkıştırılmış resource'lar olarak kalır. Yalnızca dış module'ü inceleyen bir obfuscator bu nedenle onların type name'lerini ve metadata'sını gözden kaçırır; her DLL'i bağımsız obfuscate etmek ise assembly'ler arası contract'lara uyumsuz adlar atanmasına yol açabilir. Önce build çıktılarınızı IL seviyesinde merge edin (örneğin [ILRepack](https://github.com/gluck/il-repack) ile), ardından ortaya çıkan module'e tek bir rename map uygulayın.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

A custom pass, yönetilen IL/metadata dönüşümleri için [dnlib](https://github.com/0xd4d/dnlib), yazma sonrası PE/kaynak yaması içinse [AsmResolver](https://github.com/Washi1337/AsmResolver) kullanabilir. Vaka çalışmasında, uygun `ldstr` talimatları, yeni oluşturulmuş 16 baytlık rolling-XOR anahtarıyla desteklenen integer-token/decryptor çağrılarına dönüştürüldü; semboller ve namespace'ler ise kısa, sıralı tanımlayıcılar yerine makul kurumsal tarzda adlarla eşlendi. Diğer pass'ler seçili derleyici/hata ayıklayıcı özniteliklerini kaldırdı, birleştirme/gömme referanslarını temizledi, kaynakları yeniden adlandırdı ve sürüm bilgilerini yamaladı. Her bağımsız derlemede adları, ölü kodu ve şifreleme materyalini yeniden üretin: şifreli metni değiştirmek kararlı baytları ortadan kaldırır, ancak kararlı bir decryptor veya tanınabilir bir dönüşüm deseni başlı başına bir imzadır.<sup>[[8]](#references)</sup>

#### Dinamik görevleri payload ile eşzamanlı tutun

Apollo, görev kaynak kodunu sunucu tarafında derleyebilir, DLL baytlarını gönderebilir ve bunları `Assembly.Load()` ile yükleyebilir. Temel agent'ın genel türleri yeniden adlandırıldıktan sonra, özgün API'ye göre derlenen sonraki görevler artık çözümlenmez. Dışa aktarılan yeniden adlandırma eşlemesini payload'a özgü bir ABI artefaktı olarak değerlendirin:<sup>[[8]](#references)</sup>

1. Eşlemeyi ve tür bağlamını tam payload/derleme tanımlayıcısına bağlayın.
2. Her görev derlemesinde bu eşlemeyi alın ve geçici bir kaynak ağacını yeniden yazın.
3. Yalnızca çözümlenmiş namespace, tür, iç içe/genel tür, alan ve özellik referanslarını yeniden yazın; ardından obfuscation uygulanmış birleştirilmiş assembly'ye göre derleyin.
4. Görev tesliminden önce eksik veya eşleşmeyen eşlemeleri reddedin ve derleme sonrasında başlatma testi çalıştırın.

Körlemesine genel değiştirme güvenli değildir; çünkü bir tanımlayıcı dizgede, yerel bildirimde, üye erişiminde, framework türünde veya ilgisiz bir namespace'te de geçebilir. Metin/regex tabanlı bir yeniden yazıcı kullanmaya devam edilecekse bu bağlamları açıkça koruyun ve eşleme şeması veya yeniden adlandırma pass'i değiştiğinde regresyon testleri çalıştırın.<sup>[[8]](#references)</sup>

#### Reflection sözleşmelerini namespace'ten bağımsız hale getirin

`t.FullName.StartsWith("Tasks.")` denetimi yapan keşif kodu, namespace'i zorunlu kılar ve namespace yeniden eşlendikten sonra başarısız olur. Bunun yerine kararlı bir tür ilişkisine göre keşif yapın; dağıtım hâlâ `t.Name` kullanıyorsa komut sınıfı adlarını koruyun:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Yansıma tarafından görülebilen ve yeniden adlandırılmaması gereken adlar, serializer alanları, giriş noktaları ve assembly'ler arası API'ler için açık bir allowlist tutun. Son olarak, sonucu ILSpy/dnSpy ile decompile edin, hem dosya hem de bellek temsillerini tarayın ve bir EDR lab ortamında tüm command/loader yollarını deneyin; başarıyla başlayan bir build'de bile yeniden adlandırma nedeniyle bozulmuş task'lar veya yalnızca çalıştırma sonrasında tespit edilen davranışlar bulunabilir.<sup>[[8]](#references)</sup>

Bu agent, pek çok command'e sahip olduğundan bazı ek özelliklerle Cobalt Strike'ın Beacon'ına çok benzer. Desteklediği command'lerden bazıları:

### Common actions

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Geçerli çalışma dizinini değiştirir
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyalar
- `ls`: Geçerli dizindeki veya belirtilen yoldaki dosya ve dizinleri listeler
- `ifconfig`: Ağ bağdaştırıcılarını ve arayüzlerini getirir
- `netstat`: TCP ve UDP bağlantı bilgilerini getirir
- `pwd`: Geçerli çalışma dizinini yazdırır
- `ps`: Hedef sistemde çalışan process'leri listeler (ek bilgilerle)
- `jobs`: Uzun süren task'larla ilişkili çalışan tüm job'ları listeler
- `download`: Hedef sistemdeki bir dosyayı yerel makineye indirir
- `upload`: Yerel makinedeki bir dosyayı hedef sisteme yükler
- `reg_query`: Hedef sistemdeki registry key'lerini ve değerlerini sorgular
- `reg_write_value`: Belirtilen registry key'ine yeni bir değer yazar
- `sleep`: Agent'ın Mythic server'a ne sıklıkta check-in yapacağını belirleyen bekleme aralığını değiştirir
- Ve daha pek çok command; kullanılabilir command'lerin tam listesini görmek için `help` kullanın.

### Privilege escalation

- `getprivs`: Geçerli thread token'ında mümkün olduğunca çok privilege etkinleştirir
- `getsystem`: winlogon'a bir handle açar ve token'ı kopyalayarak privilege'ları SYSTEM seviyesine yükseltir
- `make_token`: Yeni bir logon session oluşturur ve bunu agent'a uygular; başka bir kullanıcıyı taklit etmeyi sağlar
- `steal_token`: Başka bir process'ten primary token çalar; agent'ın o process'in kullanıcısını taklit etmesini sağlar
- `pth`: Pass-the-Hash saldırısı; plaintext parolaya gerek kalmadan kullanıcının NTLM hash'ini kullanarak kimlik doğrulamayı sağlar
- `mimikatz`: Bellekten veya SAM database'inden credential'ları, hash'leri ve diğer hassas bilgileri çıkarmak için Mimikatz command'lerini çalıştırır
- `rev2self`: Agent'ın token'ını primary token'ına döndürür; böylece privilege'ları özgün seviyesine indirir
- `ppid`: Yeni bir parent process ID belirterek post-exploitation job'larının parent process'ini değiştirir ve job yürütme bağlamı üzerinde daha fazla kontrol sağlar
- `printspoofer`: Print spooler güvenlik önlemlerini atlatmak, privilege escalation veya code execution sağlamak için PrintSpoofer command'lerini çalıştırır
- `dcsync`: Kullanıcının Kerberos key'lerini yerel makineyle senkronize ederek offline parola kırma veya başka saldırılar yapılmasını sağlar
- `ticket_cache_add`: Kerberos ticket'ını geçerli veya belirtilen bir logon session'a ekleyerek ticket'ın yeniden kullanılmasını veya kullanıcı taklidini sağlar

### Process execution

- `assembly_inject`: Uzak bir process'e .NET assembly loader enjekte eder
- `blockdlls`: Post-exploitation job'larına Microsoft tarafından imzalanmamış DLL'lerin yüklenmesini engeller
- `execute_assembly`: Agent bağlamında bir .NET assembly çalıştırır
- `execute_coff`: Derlenmiş kodun bellekte çalıştırılmasını sağlayarak bir COFF dosyasını bellekte çalıştırır
- `execute_pe`: Yönetilmeyen bir executable (PE) çalıştırır
- `keylog_inject`: Başka bir process'e keylogger enjekte eder ve tuş vuruşlarını Mythic'in keylog görünümüne aktarır
- `screenshot` / `screenshot_inject`: Geçerli masaüstünün görüntüsünü doğrudan yakalar veya
  hedef process/session'a bir screenshot assembly enjekte ederek yakalar
- `get_injection_techniques`: Kullanılabilir injection tekniklerini ve o anda seçili olanı gösterir
- `inline_assembly`: Kodun agent'ın ana process'ini etkilemeden geçici olarak çalıştırılmasını sağlayarak bir .NET assembly'yi geçici bir AppDomain'de çalıştırır
- `register_assembly`: Daha sonra çalıştırmak üzere bir .NET assembly kaydeder
- `register_file`: Daha sonra `execute_*` veya PowerShell task'ları için agent cache'ine bir dosya kaydeder
- `run`: Executable'ı bulmak için sistemin PATH'ini kullanarak hedef sistemde bir binary çalıştırır
- `set_injection_technique`: Post-exploitation job'larının kullandığı injection primitive'ini değiştirir
- `shinject`: Bellekte rastgele kod çalıştırılmasını sağlayarak uzak bir process'e shellcode enjekte eder
- `inject`: Bellekte agent kodunun çalıştırılmasını sağlayarak uzak bir process'e agent shellcode'u enjekte eder
- `spawn`: Yeni bir process'te shellcode çalıştırılmasını sağlayarak belirtilen executable'da yeni bir agent session başlatır
- `spawnto_x64` ve `spawnto_x86`: Post-exploitation job'larında kullanılacak varsayılan binary'yi, çok gürültülü olan paramsız `rundll32.exe` yerine belirtilen bir yolla değiştirir.

### Mythic Forge

Bu, hedef sistemde çalıştırılabilen önceden derlenmiş payload ve araçlardan oluşan bir repository olan Mythic Forge'dan **COFF/BOF** dosyalarının yüklenmesini sağlar. Yüklenebilecek tüm command'lerle, ayrı bir process başlatmaya kıyasla genellikle daha iyi OPSEC sağlayan BOF'lar olarak geçerli agent process'inde çalıştırılarak yaygın işlemler gerçekleştirilebilir.

Kuruluma şununla başlayın:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Then, Mythic Forge'daki COFF/BOF modüllerini görüntülemek ve seçip yürütme için agent'ın belleğine yüklemek üzere `forge_collections` kullanın. Apollo'da varsayılan olarak aşağıdaki 2 collection eklenir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir modül yüklendikten sonra listede `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir komut olarak görünür.

BOF'lar için Forge'un Apollo'ya yalnızca tek bir düz argüman dizesi iletmediğini unutmayın. BOF parametrelerini Mythic'in typed-array biçimine eşler ve ardından Apollo'nun `execute_coff` akışına iletir. Forge ile yüklenen bir BOF garip davranıyorsa yalnızca yazdığınız komut satırını değil, beklenen BOF argüman türlerini ve entrypoint'i de kontrol edin. Ayrıca Apollo'nun daha yeni BOF loader'ının, çok daha eski 2.3.1 dönemi derlemelerine kıyasla argüman işleme biçimini değiştirdiğini unutmayın. Bu nedenle eski BOF'lar veya collection'lar, yalnızca marshaling beklentileri değiştiği için çalışmayabilir.

### PowerShell ve script yürütme

- `powershell_import`: Daha sonra yürütülmek üzere yeni bir PowerShell script'ini (.ps1) agent önbelleğine aktarır
- `powershell`: Agent bağlamında bir PowerShell komutu yürütür; gelişmiş scripting ve otomasyon olanağı sağlar
- `powerpick`: PowerShell loader assembly'sini feda edilebilir bir sürece inject eder ve bir PowerShell komutu yürütür (powershell logging olmadan).
- `psinject`: PowerShell'i belirtilen bir süreçte yürütür; başka bir sürecin bağlamında script'lerin hedefli yürütülmesini sağlar
- `shell`: Agent bağlamında, cmd.exe'de komut çalıştırmaya benzer şekilde bir shell komutu yürütür

### Lateral Movement

- `jump_psexec`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp yürütmek suretiyle, PsExec tekniğini kullanarak yeni bir host'a lateral olarak geçer.
- `jump_wmi`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp yürütmek suretiyle, WMI tekniğini kullanarak yeni bir host'a lateral olarak geçer.
- `link` ve `unlink`: Callback'ler arasında (örneğin SMB/TCP üzerinden) P2P bağlantıları oluşturur ve sonlandırır.
- `wmiexecute`: Impersonation için isteğe bağlı kimlik bilgileri kullanarak yerel veya belirtilen uzak sistemde bir komut yürütür.
- `net_dclist`: Belirtilen domain için domain controller listesini alır; lateral movement için olası hedefleri belirlemede kullanışlıdır.
- `net_localgroup`: Belirtilen bilgisayardaki yerel grupları listeler; bilgisayar belirtilmezse localhost kullanılır.
- `net_localgroup_member`: Yerel veya uzak bilgisayardaki belirtilen grubun üyelerini alır; belirli gruplardaki kullanıcıları enumerate etmeyi sağlar.
- `net_shares`: Belirtilen bilgisayardaki uzak share'leri ve bunlara erişilebilirliği listeler; lateral movement için olası hedefleri belirlemede kullanışlıdır.
- `socks`: Hedef ağda SOCKS 5 uyumlu bir proxy etkinleştirerek trafiğin ele geçirilmiş host üzerinden tünellenmesini sağlar. proxychains gibi araçlarla uyumludur.
- `rpfwd`: Hedef host'ta belirtilen bir portu dinlemeye başlar ve trafiği Mythic üzerinden uzak bir IP ve porta yönlendirerek hedef ağdaki servislere uzaktan erişim sağlar.
- `listpipes`: Yerel sistemdeki tüm named pipe'ları listeler; IPC mekanizmalarıyla etkileşim kurarak lateral movement veya privilege escalation için kullanışlı olabilir.

`jump_wmi` veya `wmiexecute` altında kullanılan düşük seviyeli WMI yürütme primitive'leri için [WmiExec](lateral-movement/wmiexec.md) sayfasına bakın. Daha geniş pivoting örüntüleri için [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) sayfasına bakın.

### Çeşitli komutlar
- `help`: Belirli komutlar veya agent'daki tüm kullanılabilir komutlar hakkında ayrıntılı bilgi görüntüler.
- `clear`: Görevleri 'cleared' olarak işaretler; böylece agent'lar tarafından alınamazlar. Tüm görevleri temizlemek için `all`, belirli bir görevi temizlemek için `task Num` belirtebilirsiniz.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon, **Linux ve macOS** executable'larına derlenen bir Golang agent'ıdır.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Güncel build/profil notları

- Güncel Poseidon build'leri hem `x86_64` hem de `arm64` üzerinde Linux ve macOS'u hedefler.
- Desteklenen çıktı biçimleri arasında yerel çalıştırılabilir dosyaların yanı sıra `dylib` ve `so` gibi shared library tarzı çıktılar bulunur.
- Poseidon `http`, `websocket`, `tcp` ve `dynamichttp` destekler; güncel builder'lar `egress_order` ve failover eşikleri gibi çoklu egress ayarlarını da sunar.
- Poseidon'ın güncel capability metadata'sı browser scripts, file/process browser entegrasyonu, interaktif tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd ve P2P özelliklerini de duyurur. Bu sayede basit bir remote shell olmanın ötesinde, gerçek bir Linux/macOS pivot node olarak çalışabilir.
- Daha temiz ağ davranışına veya ek Go binary obfuscation'a ihtiyaç duyduğunuzda `proxy_bypass` ve `garble` gibi build-time seçeneklerini incelemeye değer.
- `pty`, Linux/macOS işlemleri için en kullanışlı yeni yaşam kalitesi komutlarından biridir; interaktif bir PTY açar ve eski `sleep 0` + SOCKS workaround'una başvurmadan daha kapsamlı terminal etkileşimi için Mythic tarafında bir port sunabilir.
- Poseidon'ın güncel dokümanları özellikle macOS ağırlıklı tradecraft için ilgi çekicidir: `jxa`, JavaScript for Automation'ı bellekte çalıştırır; `screencapture`, oturum açmış kullanıcının masaüstünü yakalar; `clipboard_monitor`, pasteboard değişikliklerini aktarır; `execute_library`, yerel bir dylib yükleyip içindeki bir fonksiyonu çağırır; `libinject` ise uzak bir process'in diskteki bir dylib'i yüklemesini sağlar.
- Uzun süre çalışan işler için Poseidon'ın post-exploitation çalışmalarını zorla sonlandırılabilir olmayan, işbirliğine dayalı goroutine/thread'lerde yürüttüğünü unutmayın. Dokümanlarda ayrıca yerleşik agent obfuscation bulunmadığı açıkça belirtilir. Bu nedenle build/profil düzeyindeki tradecraft, yoğun obfuscation kullanan ticari implantlara kıyasla daha önemlidir.

Mythic destekli işlemler, JAMF abuse veya MDM-as-C2 fikirleriyle ilgili macOS'a özgü tradecraft için [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) sayfasına bakın.

Linux veya macOS'ta kullanıldığında bazı ilgi çekici komutları vardır:

### Yaygın işlemler

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Geçerli çalışma dizinini değiştirir
- `chmod`: Bir dosyanın izinlerini değiştirir
- `config`: Geçerli yapılandırmayı ve host bilgilerini görüntüler
- `cp`: Bir dosyayı bir konumdan diğerine kopyalar
- `curl`: İsteğe bağlı headers ve method ile tek bir web isteği gerçekleştirir
- `upload`: Hedefe dosya yükler
- `download`: Hedef sistemden yerel makineye dosya indirir
- Ve daha fazlası

### Hassas bilgileri arama

- `triagedirectory`: Bir host üzerindeki dizinde hassas dosyalar veya credentials gibi ilgi çekici dosyaları bulur.
- `getenv`: Geçerli tüm environment variables değerlerini alır.

### macOS'a özgü tradecraft

- `jxa`: `OSAScript` üzerinden JavaScript for Automation'ı bellekte çalıştırır. Ayrı script dosyaları bırakmadan yerel macOS post-exploitation işlemleri için kullanışlıdır.
- `clipboard_monitor`: Pasteboard'u yoklar ve değişiklikleri Mythic'e bildirir; kopyala/yapıştır kullanımına dayanan credential/token hırsızlığı iş akışlarında kullanışlıdır.
- `screencapture`: macOS'ta kullanıcının masaüstünü yakalar.
- `execute_library`: Diskten bir dylib yükler ve belirli bir exported function'ı çağırır.
- `libinject`: Başka bir macOS process'inin diskten bir dylib yüklemesini sağlayan bir shellcode stub enjekte eder.
- `persist_launchd`: Agent üzerinden doğrudan LaunchAgent / LaunchDaemon persistence oluşturur.

### Yatay hareket

- `ssh`: Belirlenen credentials bilgilerini kullanarak host'a SSH ile bağlanır ve ssh'yi başlatmadan bir PTY açar.
- `sshauth`: Belirlenen credentials bilgilerini kullanarak belirtilen host'lara SSH ile bağlanır. Bunu uzak host'larda belirli bir komutu çalıştırmak veya dosyaları SCP ile aktarmak için de kullanabilirsiniz.
- `link_tcp`: Agent'ler arasında doğrudan iletişim kurulmasını sağlayarak başka bir agent'a TCP üzerinden bağlanır.
- `link_webshell`: Uzak erişim için webshell P2P profilini kullanarak bir agent'a bağlanır.
- `rpfwd`: Hedef ağdaki servislere uzaktan erişim sağlamak için Reverse Port Forward'ı başlatır veya durdurur.
- `socks`: Ele geçirilmiş host üzerinden trafik tünellemek için hedef ağda bir SOCKS5 proxy başlatır veya durdurur. proxychains gibi araçlarla uyumludur.
- `portscan`: Host'ları açık portlar için tarar; yatay hareket veya daha ileri saldırılar için olası hedefleri belirlemeye yarar.

### Process yürütme

- `shell`: Hedef sistemde komutları doğrudan çalıştırmak için `/bin/sh` üzerinden tek bir shell komutu yürütür.
- `run`: Hedef sistemde binary veya script çalıştırmak için diskten bir komutu argümanlarıyla yürütür.
- `pty`: Hedef sistemdeki shell ile doğrudan etkileşim kurmak için interaktif bir PTY açar.

## References

- [1] [Mythic Community Agent Özellik Matrisi](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Öne Çıkanlar: İnteraktif Tasking, Push C2 ve Dinamik File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Dokümantasyonu](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Güncellemeleri](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Mythic'in Gizli Cevherleriyle Red Team Operasyonlarını Dönüştürmek: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Multi_Trojan_Mythic YARA kuralları](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Fork'tan Framework'e: Apollo'yu Değiştirmenin Agent Invasion Hakkında Öğrettikleri](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
