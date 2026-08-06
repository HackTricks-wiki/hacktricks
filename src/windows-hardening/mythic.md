# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic nedir?

Mythic, red teaming için tasarlanmış açık kaynaklı, modüler ve iş birliğine dayalı bir command and control (C2) framework'üdür. Operatörlerin Windows, Linux ve macOS dahil olmak üzere farklı işletim sistemlerinde agent'ları (payload'ları) yönetmesine ve dağıtmasına olanak tanır. Mythic; birden fazla operatör için tasking, dosya işleme, SOCKS/rpfwd yönetimi ve payload oluşturma özelliklerine sahip bir tarayıcı arayüzü sunar.

Monolitik framework'lerin aksine Mythic repository'si payload türlerini veya C2 profillerini kendisi içermez. Agent'lar, wrapper'lar ve C2 profilleri genellikle harici bileşenler olarak yüklenir ve Mythic core'dan bağımsız şekilde güncellenebilir.

### Kurulum

Mythic'i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin. Mythic dizininden yaygın bir bootstrap işlemi şöyledir:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic zaten çalışıyorsa genellikle `./mythic-cli install github ...` ile yeni bir agent veya profile ekleyebilir, ardından Mythic'i yeniden başlatabilir ya da yeni component'i doğrudan başlatabilirsiniz.

### Agents

Mythic, **ele geçirilmiş sistemlerde görevleri gerçekleştiren payload'lar** olan birden fazla agent'ı destekler. Her agent belirli ihtiyaçlara göre özelleştirilebilir ve farklı işletim sistemlerinde çalışabilir.

Mythic'te varsayılan olarak hiçbir agent yüklü değildir. Open-source topluluk agent'ları [**https://github.com/MythicAgents**](https://github.com/MythicAgents) adresinde bulunur ve [**topluluk feature matrix'i**](https://mythicmeta.github.io/overview/agent_matrix.html), desteklenen işletim sistemlerini, payload formatlarını, wrapper'ları ve C2 profillerini hızlıca kontrol etmek için kullanışlıdır.<sup>[[1]](#references)</sup>

Bu org'dan bir agent yüklemek için şunu çalıştırabilirsiniz:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` formu, root olmayan bir ortamdan kurulum yaparken kullanışlıdır. Mythic zaten çalışıyor olsa bile, önceki komutla yeni agent'lar ekleyebilirsiniz.

### C2 Profiles

Mythic'teki C2 profiles, **agent'ların Mythic server ile nasıl iletişim kuracağını** tanımlar. İletişim protokolünü, şifreleme yöntemlerini ve diğer ayarları belirtirler. C2 profiles'ı Mythic web arayüzü üzerinden oluşturabilir ve yönetebilirsiniz.

Mythic varsayılan olarak hiçbir profile sahip olmadan kurulur; ancak [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) repo'sundan bazı profilleri şu komutu çalıştırarak indirmek mümkündür:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Akılda tutulması gereken mevcut operator-relevant profiller:

- [`http`](https://github.com/MythicC2Profiles/http): temel asynchronous GET/POST trafiği.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): birden fazla callback domain'i, fail-over/round-robin rotation, custom headers/query parameters ve cookies, headers, query parameters veya body içine yerleştirilen message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) ile daha esnek HTTP trafiği.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static `http` profile fazla tanınabilir olduğunda JSON/TOML-driven HTTP message shaping.

### Mevcut platform notları

- Birçok public agent ve profile artık önceden oluşturulmuş remote container images ile yükleniyor.
Bir component'i fork eder veya yerel olarak patch'lerseniz ve Mythic eski
davranışı kullanmaya devam ederse, oluşturulan `.env` girdilerinde
`*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` ve `*_USE_VOLUME` değerlerini inceleyin;
`*_USE_BUILD_CONTEXT="true"` etkinleştirmek genellikle Mythic'in remote image'ı
sessizce yeniden kullanmak yerine yerel Docker context'inizden rebuild etmesini sağlar.
- Browser scripts, operator'ler için Mythic'in en değerli quality-of-life özelliklerinden
biridir: ham command output'u tables, screenshot viewers, download links, search links
ve doğrudan UI üzerinden follow-on tasking gönderen buttons'a dönüştürebilirler. Mevcut
Mythic build'leri her operator'ün kendi script'lerini tutmasına, bunları global olarak
veya task başına açıp kapatmasına izin verir ve en iyi sonuçlar agent'lar plaintext yerine
structured JSON döndürdüğünde elde edilir. Bu özellik özellikle tekrarlanan `ls`, `ps`,
triage ve file-browser workflow'ları için kullanışlıdır.<sup>[[4]](#references)[[6]](#references)</sup>
- Daha yeni Mythic build'leri ayrıca interactive tasking ve Push C2 patterns desteği
sunar; bu da PTY/SOCKS/rpfwd ağırlıklı operation'larda `sleep 0` polling ihtiyacını
azaltır. Bir agent/profile bunu desteklediğinde, interactive channel'ı kullanılabilir
tutmak için sürekli check-in göndererek server'ı hammer'lamaktan genellikle daha düşük
overhead'li olur.<sup>[[3]](#references)</sup>
- Mevcut 3.4-era Mythic builder'ları, eski writeup'ların ima ettiğinden daha
context-aware'dir: build parameters artık seçilen OS veya diğer build options'a göre
gruplanabilir veya gizlenebilir, payload types bir build içinde birden fazla C2 profile
veya aynı C2'nin birden fazla instance'ını destekleyip desteklemediklerini belirtebilir
ve C2 parameter deviations, bir agent'ın gerçekte implement etmediği field'ları
gizlemesine izin verir. `http`, `httpx`, `smb`, `tcp` ve `websocket` arasında geçiş
yaparken bu önemlidir; çünkü güvenli/geçerli build surface artık düz, static bir form
değildir.<sup>[[5]](#references)</sup>
- Custom bir agent/profile pair oluşturuyorsanız ve Mythic'in JSON message format'ını
veya wire üzerindeki default crypto'yu kullanmak istemiyorsanız bir
`translation_container` kullanın: Mythic UUID'yi çıkarır, encrypted blob ile key
material'ı gRPC üzerinden translator'a iletir ve agent-native bytes bekler. Bu yöntem,
binary protocols, custom framing veya agent-side encryption desteği sağlamak için
tüm server'ı yeniden yazmadan kullanılabilecek temiz yoldur.
- Linked/P2P callbacks'in yalnızca tasking taşımadığını unutmayın. Mythic'in
`get_tasking` flow'u responses'ın yanı sıra `delegates`, `socks`, `rpfwd` ve
`interactive` data da taşıyabilir. Uygulamada tek bir egress callback, aynı polling
loop içinde inner callbacks ve pivot channels'a hizmet verebilir; child agents kendi
periodic check-in'lerini gerçekleştiriyorsa `get_delegate_tasks=false`, parent'ın
inner callback'in queued jobs'larını yanlışlıkla tüketmesini önler.

### Wrapper payload'ları

Wrapper payload'ları, aynı agent logic'i korurken teslim edilen veya persist edilen on-disk representation'ı değiştirmenizi sağlar.

- `service_wrapper`: başka bir payload'ı Windows service executable'a dönüştürür; execution path'in geçerli bir service binary gerektirdiği durumlarda kullanışlıdır.
- `scarecrow_wrapper`: uyumlu shellcode'u ScareCrow loader ile wrap ederek EXE/DLL/CPL gibi loader-backed outputs oluşturur.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps training offerings içinde kullanılmak üzere 4.0 .NET Framework kullanan C# ile yazılmış bir Windows agent'tır.<sup>[[2]](#references)</sup>

Şununla yükleyin:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Güncel build/profile notları

- Apollo şu anda `WinExe`, `Shellcode`, `Service` ve `Source` payload'larını oluşturabilir.
- Yaygın olarak kullanılan Apollo profilleri `http`, `httpx`, `smb`, `tcp` ve `websocket`'tir.
- `httpx`, eski statik `http` profili yerine domain rotation, proxy desteği, özel message placement ve message transforms gerektiğinde genellikle daha esnek seçenektir.
- Apollo, daha eksiksiz özelliklere sahip community agent'larından biridir ve şu anda browser scripts, file/process browser görünümleri, screenshots, keylogging, SOCKS, rpfwd, Push C2 ve P2P routing gibi Mythic-side integrations özelliklerini sunar.
- Apollo, `service_wrapper` ve `scarecrow_wrapper` gibi wrapper payload'larını destekler.
- Apollo, dynamic command loading özelliğini destekler. Böylece ilk payload'ı yalın tutabilir ve her post-ex yeteneğini ilk build'e derlemek yerine daha sonra ek commands veya Forge modules yükleyebilirsiniz.
- Shellcode output oluşturulurken Apollo'nun mevcut builder'ı ayrıca Donut format seçeneklerini (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) ve Donut bypass davranışlarını (`None`, `Abort on fail`, `Continue on fail`) sunar. Bu, shellcode'u `service_wrapper`, `scarecrow_wrapper` veya özel bir loader ile yeniden wrap etmek istediğinizde kullanışlıdır.
- `register_file` ve `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` ve `powerpick` için staging primitive'leridir. Güncel Apollo build'lerinde bu staged artifact'ler client-side olarak DPAPI-protected AES256 blob'ları şeklinde cache'lenir.
- `ls` ve `ps` sonuçları Mythic'in browser scripts ve file/process browser özellikleriyle özellikle iyi entegre olur; bu da collaborative operations sırasında operator triage işlemini belirgin şekilde hızlandırır.
- Apollo'nun fork-and-run jobs işlemleri sacrificial process ayarlarını
`spawnto_x86` / `spawnto_x64` değerlerinden devralır, parent selection işlemini `ppid` değerinden devralır
ve ardından o anda seçili injection primitive'i kullanır. Pratikte bu, tek bir command için yaptığınız
OPSEC ayarlarının çoğu zaman aynı anda `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` ve `spawn` işlemlerini
etkilemesi anlamına gelir.
- Güncel belgelenmiş Apollo injection backend'leri arasında `CreateRemoteThread`,
`QueueUserAPC` (early-bird style) ve syscall'lar üzerinden `NtCreateThreadEx` bulunur.
Gürültülü post-exploitation işlemlerinden önce `get_injection_techniques` kullanın ve
hedefle veya çalıştırmak istediğiniz command ile çakışan bir primitive'den uzaklaşmanız
gerekiyorsa `set_injection_technique` kullanın.
- `blockdlls`, yalnızca post-exploitation jobs için oluşturulan sacrificial process'leri etkiler.
Varsayılan çıplak `rundll32.exe` hedefinden daha az şüpheli bir `spawnto_x64` hedefiyle
birlikte kullanıldığında bu, assembly/PowerShell ağırlıklı tasking çalıştırmadan önce
Apollo tarafında yapılabilecek en kolay değişikliklerden biridir.

Bu agent, bazı ek özelliklerle birlikte Cobalt Strike's Beacon'a oldukça benzeyen çok sayıda command içerir. Bunlar arasında şunları destekler:

### Yaygın işlemler

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Geçerli çalışma dizinini değiştirir
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyalar
- `ls`: Geçerli dizindeki veya belirtilen path'teki dosya ve dizinleri listeler
- `ifconfig`: Network adapter'larını ve interface'lerini alır
- `netstat`: TCP ve UDP connection bilgilerini alır
- `pwd`: Geçerli çalışma dizinini yazdırır
- `ps`: Hedef sistemde çalışan process'leri listeler (ek bilgilerle)
- `jobs`: Long-running tasking ile ilişkili çalışan tüm job'ları listeler
- `download`: Hedef sistemden local machine'a bir dosya indirir
- `upload`: Local machine'dan hedef sisteme bir dosya yükler
- `reg_query`: Hedef sistemdeki registry key'lerini ve value'larını sorgular
- `reg_write_value`: Belirtilen registry key'e yeni bir value yazar
- `sleep`: Agent'ın sleep interval'ını değiştirir; bu aralık agent'ın Mythic server'a ne sıklıkla check-in yaptığını belirler
- Ve daha birçok command bulunur; kullanılabilir command'ların tam listesini görmek için `help` kullanın.

### Privilege escalation

- `getprivs`: Mevcut thread token'ı üzerindeki mümkün olduğunca çok privilege'ı etkinleştirir
- `getsystem`: winlogon'a bir handle açar ve token'ı duplicate ederek privilege'ları etkili biçimde SYSTEM seviyesine yükseltir
- `make_token`: Yeni bir logon session oluşturur ve bunu agent'a uygular; böylece başka bir user'ın impersonation'ına izin verir
- `steal_token`: Başka bir process'ten primary token çalar; böylece agent, o process'in user'ını impersonate edebilir
- `pth`: Pass-the-Hash attack; agent'ın plaintext password'e ihtiyaç duymadan NTLM hash kullanarak bir user olarak authenticate olmasını sağlar
- `mimikatz`: Credential'ları, hash'leri ve memory veya SAM database içindeki diğer hassas bilgileri çıkarmak için Mimikatz command'larını çalıştırır
- `rev2self`: Agent'ın token'ını primary token'ına geri döndürür; privilege'ları etkili biçimde başlangıç seviyesine düşürür
- `ppid`: Yeni bir parent process ID belirleyerek post-exploitation jobs için parent process'i değiştirir; böylece job execution context üzerinde daha iyi kontrol sağlar
- `printspoofer`: Print spooler security önlemlerini bypass etmek ve privilege escalation veya code execution sağlamak için PrintSpoofer command'larını çalıştırır
- `dcsync`: Bir user'ın Kerberos key'lerini local machine'a sync eder; böylece offline password cracking veya sonraki attack'ler mümkün olur
- `ticket_cache_add`: Bir Kerberos ticket'ını mevcut veya belirtilen logon session'a ekler; böylece ticket reuse veya impersonation mümkün olur

### Process execution

- `assembly_inject`: Bir .NET assembly loader'ını remote process'e inject eder
- `blockdlls`: Microsoft tarafından imzalanmamış DLL'lerin post-exploitation jobs içine yüklenmesini engeller
- `execute_assembly`: Bir .NET assembly'yi agent context'inde çalıştırır
- `execute_coff`: Bir COFF file'ı memory'de çalıştırır; derlenmiş code'un in-memory execution'ını sağlar
- `execute_pe`: Unmanaged executable (PE) çalıştırır
- `keylog_inject`: Bir keylogger'ı başka bir process'e inject eder ve keystroke'ları Mythic'in keylog view'ına stream eder
- `screenshot` / `screenshot_inject`: Mevcut desktop'ın görüntüsünü doğrudan alır veya
bir screenshot assembly'sini hedef process/session'a inject ederek görüntü alır
- `get_injection_techniques`: Kullanılabilir injection technique'leri ve şu anda seçili olanı gösterir
- `inline_assembly`: Bir .NET assembly'yi disposable AppDomain içinde çalıştırır; böylece agent'ın ana process'ini etkilemeden code'u geçici olarak çalıştırır
- `register_assembly`: Daha sonra çalıştırılmak üzere bir .NET assembly'yi register eder
- `register_file`: Daha sonra `execute_*` veya PowerShell tasking için agent cache'ine bir file register eder
- `run`: Executable'ı bulmak için system PATH'ini kullanarak hedef sistemde bir binary çalıştırır
- `set_injection_technique`: Post-exploitation jobs tarafından kullanılan injection primitive'i değiştirir
- `shinject`: Bir remote process'e shellcode inject eder; böylece arbitrary code'un in-memory execution'ını sağlar
- `inject`: Agent shellcode'unu bir remote process'e inject eder; böylece agent code'unun in-memory execution'ını sağlar
- `spawn`: Belirtilen executable içinde yeni bir agent session başlatır; böylece shellcode'un yeni bir process'te çalıştırılmasını sağlar
- `spawnto_x64` ve `spawnto_x86`: Post-exploitation jobs için kullanılan default binary'yi, params olmadan kullanılan ve oldukça gürültülü olan `rundll32.exe` yerine belirtilen path ile değiştirir.

### Mythic Forge

Bu özellik, hedef sistemde çalıştırılabilen pre-compiled payload ve tool repository'si olan Mythic Forge'dan **COFF/BOF** file'larını yüklemeyi sağlar. Yüklenebilen tüm command'larla, bunları BOF olarak mevcut agent process'inde çalıştırarak yaygın işlemleri gerçekleştirmek mümkün olur (genellikle ayrı bir process spawn etmeye kıyasla daha iyi OPSEC ile).

Bunları şu şekilde yüklemeye başlayın:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Ardından, Mythic Forge'daki COFF/BOF modüllerini göstermek ve bunları seçip çalıştırılmak üzere agent'ın belleğine yüklemek için `forge_collections` kullanın. Varsayılan olarak Apollo'ya aşağıdaki 2 collection eklenir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir modül yüklendikten sonra listede `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir komut olarak görünür.

BOF'lar için Forge'un Apollo'ya yalnızca tek bir düz argüman dizesi
göndermediğini unutmayın. BOF parametrelerini Mythic'in typed-array formatına eşler ve ardından bunları Apollo'nun `execute_coff` akışına iletir. Forge ile yüklenen bir BOF beklenmedik şekilde davranıyorsa yalnızca yazdığınız komut satırını değil, beklenen BOF argüman türlerini / entrypoint'i de kontrol edin. Ayrıca Apollo'nun daha yeni BOF loader'ının, çok daha eski 2.3.1 dönemi build'lere kıyasla argüman işleme yöntemini değiştirdiğini unutmayın. Bu nedenle eski BOF'lar veya eski collection'lar, yalnızca marshaling beklentileri değiştiği için başarısız olabilir.

### PowerShell ve scripting çalıştırma

- `powershell_import`: Daha sonra çalıştırılmak üzere yeni bir PowerShell script'ini (.ps1) agent cache'ine aktarır
- `powershell`: Agent bağlamında bir PowerShell komutu çalıştırarak gelişmiş scripting ve otomasyona olanak tanır
- `powerpick`: Bir PowerShell loader assembly'sini sacrificial process'e inject eder ve bir PowerShell komutu çalıştırır (powershell logging olmadan).
- `psinject`: PowerShell'i belirtilen bir process içinde çalıştırarak script'lerin başka bir process bağlamında hedefli şekilde yürütülmesine olanak tanır
- `shell`: Agent bağlamında bir shell komutu çalıştırır; cmd.exe'de komut çalıştırmaya benzer

### Lateral Movement

- `jump_psexec`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp çalıştırarak PsExec tekniğini kullanır ve yeni bir host'a lateral movement gerçekleştirir.
- `jump_wmi`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp çalıştırarak WMI tekniğini kullanır ve yeni bir host'a lateral movement gerçekleştirir.
- `link` ve `unlink`: Callback'ler arasında P2P bağlantıları (örneğin SMB/TCP üzerinden) oluşturur ve sonlandırır.
- `wmiexecute`: Impersonation için isteğe bağlı credential'lar kullanarak WMI aracılığıyla local veya belirtilen remote system üzerinde bir komut çalıştırır.
- `net_dclist`: Belirtilen domain için domain controller listesini alır; lateral movement için potansiyel hedefleri belirlemede kullanışlıdır.
- `net_localgroup`: Belirtilen computer üzerindeki local group'ları listeler; computer belirtilmezse varsayılan olarak localhost kullanılır.
- `net_localgroup_member`: Belirtilen group için local veya remote computer üzerindeki local group membership bilgilerini alarak belirli group'lardaki kullanıcıların enumeration'ına olanak tanır.
- `net_shares`: Belirtilen computer üzerindeki remote share'leri ve bunların erişilebilirliğini listeler; lateral movement için potansiyel hedefleri belirlemede kullanışlıdır.
- `socks`: Target network üzerinde SOCKS 5 uyumlu bir proxy etkinleştirerek trafiğin compromised host üzerinden tünellenmesine olanak tanır. Proxychains gibi tool'larla uyumludur.
- `rpfwd`: Target host üzerinde belirtilen bir portu dinlemeye başlar ve trafiği Mythic üzerinden remote IP ve port'a forward eder; target network üzerindeki servislere remote access sağlar.
- `listpipes`: Local system üzerindeki tüm named pipe'ları listeler; IPC mekanizmalarıyla etkileşime girerek lateral movement veya privilege escalation gerçekleştirmek için kullanışlı olabilir.

`jump_wmi` veya `wmiexecute` altında kullanılan lower-level WMI execution primitive'leri için [WmiExec](lateral-movement/wmiexec.md) sayfasına bakın. Daha geniş pivoting pattern'leri için [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) sayfasına bakın.

### Miscellaneous Commands
- `help`: Belirli komutlar hakkında ayrıntılı bilgi veya agent'da kullanılabilir tüm komutlar hakkında genel bilgi görüntüler.
- `clear`: Task'leri 'cleared' olarak işaretleyerek agent'lar tarafından alınmalarını engeller. Tüm task'leri temizlemek için `all`, belirli bir task'i temizlemek için `task Num` belirtebilirsiniz.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon, **Linux ve macOS** executable'larına derlenen bir Golang agent'ıdır.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Mevcut build/profile notları

- Mevcut Poseidon build'leri hem `x86_64` hem de `arm64` üzerinde Linux ve macOS'u hedefler.
- Desteklenen çıktı formatları arasında native executable'ların yanı sıra `dylib` ve `so` gibi shared-library tarzı çıktılar da bulunur.
- Poseidon `http`, `websocket`, `tcp` ve `dynamichttp` destekler; mevcut builder'lar `egress_order` ve failover eşikleri gibi multi-egress ayarlarını sunar.
- Poseidon'un mevcut capability metadata'sı browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd ve P2P özelliklerini de duyurur. Bu nedenle yalnızca basit bir remote shell olmak yerine gerçek bir Linux/macOS pivot node olarak çalışabilir.
- `proxy_bypass` ve `garble` gibi build-time seçenekleri, daha temiz network behavior veya ekstra Go binary obfuscation gerektiğinde kontrol etmeye değer.
- `pty`, Linux/macOS operations için en kullanışlı yeni quality-of-life command'lerden biridir; interactive PTY açar ve eski `sleep 0` + SOCKS workaround'una başvurmadan daha kapsamlı terminal interaction için Mythic-side port sunabilir.
- Poseidon'un mevcut docs'u macOS ağırlıklı tradecraft için özellikle ilgi çekicidir: `jxa`, JavaScript for Automation'ı in-memory olarak çalıştırır, `screencapture` logged-in desktop'ı yakalar, `clipboard_monitor` pasteboard değişikliklerini stream eder, `execute_library` local bir dylib yükleyip içindeki bir function'ı çağırır ve `libinject` remote bir process'in diskteki bir dylib'ı yüklemesini zorlar.
- Long-running jobs için Poseidon'un post-exploitation çalışmalarını hard-kill edilemeyen, cooperative goroutines/threads içinde çalıştırdığını unutmayın. Docs ayrıca şu anda built-in agent obfuscation bulunmadığını açıkça belirtir; bu nedenle build/profile-level tradecraft, heavily obfuscated commercial implants'lara kıyasla daha önemlidir.

Mythic-backed operations, JAMF abuse veya MDM-as-C2 fikirleri çevresindeki macOS-specific tradecraft için [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) bölümüne bakın.

Linux veya macOS üzerinde kullanıldığında bazı ilginç command'lere sahiptir:

### Common actions

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Mevcut working directory'yi değiştirir
- `chmod`: Bir dosyanın permissions'larını değiştirir
- `config`: Mevcut config'i ve host bilgilerini görüntüler
- `cp`: Bir dosyayı bir konumdan diğerine kopyalar
- `curl`: İsteğe bağlı headers ve method ile tek bir web request çalıştırır
- `upload`: Target'a bir dosya yükler
- `download`: Target system'dan local machine'e bir dosya indirir
- Ve çok daha fazlası

### Sensitive Information arama

- `triagedirectory`: Bir host üzerindeki directory içinde sensitive files veya credentials gibi ilgi çekici dosyaları bulur.
- `getenv`: Mevcut tüm environment variables'ları alır.

### macOS-specific tradecraft

- `jxa`: `OSAScript` üzerinden JavaScript for Automation'ı in-memory olarak çalıştırır; ayrı script dosyaları bırakmadan native macOS post-exploitation için kullanışlıdır.
- `clipboard_monitor`: Pasteboard'u poll eder ve değişiklikleri Mythic'e bildirir; copy/paste'e dayanan credential/token theft workflow'ları için kullanışlıdır.
- `screencapture`: macOS üzerinde kullanıcının desktop'ını capture eder.
- `execute_library`: Diskten bir dylib yükler ve belirli bir exported function'ı çağırır.
- `libinject`: Başka bir macOS process'inin diskten bir dylib yüklemesini zorlayan bir shellcode stub inject eder.
- `persist_launchd`: Doğrudan agent üzerinden LaunchAgent / LaunchDaemon persistence oluşturur.

### Lateral movement

- `ssh`: Belirlenen credentials'ları kullanarak host'a SSH ile bağlanır ve ssh spawn etmeden bir PTY açar.
- `sshauth`: Belirlenen credentials'ları kullanarak belirtilen host(lar)a SSH ile bağlanır. Bunu remote host'lar üzerinde SSH aracılığıyla belirli bir command çalıştırmak veya SCP ile dosya transfer etmek için de kullanabilirsiniz.
- `link_tcp`: Agent'lar arasında doğrudan communication sağlayarak başka bir agent'a TCP üzerinden link oluşturur.
- `link_webshell`: Webshell P2P profile kullanarak bir agent'a link oluşturur ve agent'ın web interface'ine remote access sağlar.
- `rpfwd`: Reverse Port Forward'ı başlatır veya durdurur ve target network üzerindeki service'lere remote access sağlar.
- `socks`: Target network üzerinde bir SOCKS5 proxy başlatır veya durdurur ve compromised host üzerinden traffic tunneling yapılmasını sağlar. Proxychains gibi tool'larla uyumludur.
- `portscan`: Open port'ları bulmak için host(lar)ı tarar; lateral movement veya further attacks için potential target'ları belirlemede kullanışlıdır.

### Process execution

- `shell`: `/bin/sh` üzerinden tek bir shell command çalıştırır ve target system üzerinde doğrudan command execution sağlar.
- `run`: Arguments ile diskten bir command çalıştırır ve target system üzerinde binaries veya scripts çalıştırılmasını sağlar.
- `pty`: Interactive PTY açar ve target system üzerindeki shell ile doğrudan interaction sağlar.

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
