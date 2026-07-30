# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic nedir?

Mythic, red teaming için tasarlanmış, açık kaynaklı, modüler ve işbirliğine dayalı bir command and control (C2) framework'üdür. Operatörlerin Windows, Linux ve macOS dahil olmak üzere farklı işletim sistemlerinde agent'ları (payload'ları) yönetmesine ve dağıtmasına olanak tanır. Mythic; çok operatörlü tasking, dosya işlemleri, SOCKS/rpfwd yönetimi ve payload oluşturma için bir browser UI sağlar.

Monolithic framework'lerin aksine Mythic repository'si payload türlerini veya C2 profile'larını içermez. Agent'lar, wrapper'lar ve C2 profile'ları genellikle harici bileşenler olarak yüklenir ve Mythic core'dan bağımsız şekilde güncellenebilir.

### Kurulum

Mythic'i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin. Mythic directory'si içinden yaygın bir bootstrap işlemi şöyledir:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic zaten çalışıyorsa genellikle `./mythic-cli install github ...` komutuyla yeni bir agent veya profile ekleyebilir, ardından Mythic'i yeniden başlatabilir ya da yalnızca yeni component'i doğrudan başlatabilirsiniz.

### Agents

Mythic, **compromised sistemlerde görevleri gerçekleştiren payload'lar** olan birden fazla agent'ı destekler. Her agent belirli ihtiyaçlara göre özelleştirilebilir ve farklı işletim sistemlerinde çalışabilir.

Mythic varsayılan olarak herhangi bir agent yüklü şekilde gelmez. Open-source community agent'ları [**https://github.com/MythicAgents**](https://github.com/MythicAgents) adresinde bulunur. [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html), desteklenen işletim sistemlerini, payload formatlarını, wrapper'ları ve C2 profile'larını hızlıca kontrol etmek için kullanışlıdır.

Bu org'dan bir agent yüklemek için şunu çalıştırabilirsiniz:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` formu, root olmayan bir ortamdan kurulum yaparken kullanışlıdır. Mythic zaten çalışıyor olsa bile önceki komutla yeni agent'lar ekleyebilirsiniz.

### C2 Profiles

Mythic'teki C2 profiles, **agent'ların Mythic server ile nasıl iletişim kuracağını** tanımlar. İletişim protokolünü, şifreleme yöntemlerini ve diğer ayarları belirtirler. C2 profiles oluşturabilir ve yönetebilirsiniz Mythic web interface üzerinden.

Varsayılan olarak Mythic hiçbir profile sahip olmadan kurulur; ancak şu komutu çalıştırarak repodan bazı profilleri indirmek mümkündür:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): temel asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters ve cookies, headers, query parameters veya body içinde yer alan message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) ile daha esnek HTTP traffic.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static `http` profile fazla tanınabilir olduğunda JSON/TOML-driven HTTP message shaping.

### Current platform notes

- Birçok public agent ve profile artık pre-built remote container images ile kuruluyor.
Bir component'i fork eder veya yerel olarak patch'lerseniz ve Mythic eski
davranışı kullanmaya devam ederse, oluşturulan `.env` içindeki
`*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` ve `*_USE_VOLUME` entries değerlerini
inceleyin; `*_USE_BUILD_CONTEXT="true"` değerini etkinleştirmek genellikle
Mythic'in remote image'ı sessizce yeniden kullanmak yerine yerel
Docker context'inizden yeniden build etmesini sağlar.
- Browser scripts, operator'lar için Mythic'in en değerli quality-of-life
özelliklerinden biridir: ham command output'u tables, screenshot
viewers, download links, search links ve doğrudan UI üzerinden follow-on
tasking gönderen buttons haline getirebilirler. Current Mythic builds, her
operator'ın kendi scripts'lerini saklamasına, bunları globally veya task
başına toggle etmesine izin verir ve en iyi sonuçlar agent'lar plaintext
yerine structured JSON döndürdüğünde elde edilir. Bu, tekrarlanan `ls`, `ps`,
triage ve file-browser workflows için özellikle kullanışlıdır.
- Daha yeni Mythic builds, interactive tasking ve Push C2 patterns'ı da
destekler; bunlar PTY/SOCKS/rpfwd-heavy operations sırasında `sleep 0`
polling ihtiyacını azaltır. Bir agent/profile bunu desteklediğinde bu yöntem,
interactive channel'ı kullanılabilir tutmak için server'a constant
check-in göndererek yük bindirmekten genellikle daha düşük overhead'lıdır.
- Current 3.4-era Mythic builders, eski writeup'ların ima ettiğinden daha
context-aware'dir: build parameters artık selected OS veya diğer build
options'a göre gruplanabilir veya gizlenebilir, payload types bir build
içinde multiple C2 profiles veya aynı C2'nin multiple instances'ını
destekleyip desteklemediklerini belirtebilir ve C2 parameter deviations,
agent'ın gerçekten implement etmediği fields'ları gizlemesine olanak tanır.
Bu, `http`, `httpx`, `smb`, `tcp` ve `websocket` arasında geçiş yaparken
önemlidir; çünkü safe/valid build surface artık flat static bir form değildir.
- Custom bir agent/profile pair build ediyorsanız ve Mythic'in JSON message
format'ını veya default crypto'sunu wire üzerinde kullanmak istemiyorsanız,
bir `translation_container` kullanın: Mythic UUID'yi çıkarır, encrypted
blob'u ve key material'ı gRPC üzerinden translator'a iletir ve agent-native
bytes bekler. Bu, tüm server'ı yeniden yazmadan binary protocols, custom
framing veya agent-side encryption desteklemenin temiz yoludur.
- Linked/P2P callbacks'in yalnızca tasking taşımadığını unutmayın. Mythic'in
`get_tasking` flow'u responses ile birlikte `delegates`, `socks`,
`rpfwd` ve `interactive` data da taşıyabilir. Pratikte tek bir egress
callback, aynı polling loop içinde inner callbacks ve pivot channels'a
hizmet verebilir; child agents kendi periodic check-in'lerini
gerçekleştiriyorsa `get_delegate_tasks=false`, parent'ın inner callback'in
queued jobs'larını yanlışlıkla tüketmesini engeller.

### Wrapper payloads

Wrapper payloads, aynı agent logic'i korurken delivered veya persisted
on-disk representation'ı değiştirmenizi sağlar.

- `service_wrapper`: başka bir payload'ı Windows service executable'a
dönüştürür; execution path geçerli bir service binary gerektirdiğinde
kullanışlıdır.
- `scarecrow_wrapper`: compatible shellcode'u ScareCrow loader ile wrap
ederek EXE/DLL/CPL gibi loader-backed outputs oluşturur.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps training offerings içinde kullanılmak üzere 4.0 .NET
Framework kullanan C# ile yazılmış bir Windows agent'tır.

Şununla kurun:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Mevcut build/profile notları

- Apollo şu anda `WinExe`, `Shellcode`, `Service` ve `Source` payload'larını üretebilir.
- Yaygın olarak kullanılan Apollo profilleri `http`, `httpx`, `smb`, `tcp` ve `websocket`'tir.
- Domain rotation, proxy desteği, özel mesaj yerleşimi ve eski statik `http` profili yerine message transform'larına ihtiyaç duyduğunuzda `httpx` genellikle daha esnek seçenektir.
- Apollo, daha fazla özelliğe sahip community agent'larından biridir ve şu anda Mythic tarafında browser scripts, file/process browser görünümleri, screenshots, keylogging, SOCKS, rpfwd, Push C2 ve P2P routing gibi entegrasyonları kullanıma sunar.
- Apollo, `service_wrapper` ve `scarecrow_wrapper` gibi wrapper payload'larını destekler.
- Apollo dynamic command loading özelliğini destekler; böylece ilk payload'u yalın tutabilir ve her post-ex yeteneğini ilk build'e derlemek yerine ek command'ları veya Forge module'lerini daha sonra yükleyebilirsiniz.
- Shellcode output oluşturulurken Apollo'nun mevcut builder'ı ayrıca Donut format seçeneklerini (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) ve Donut bypass davranışını (`None`, `Abort on fail`, `Continue on fail`) sunar. Bu, shellcode'u `service_wrapper`, `scarecrow_wrapper` veya özel bir loader ile yeniden sarmalamak istediğiniz durumlarda kullanışlıdır.
- `register_file` ve `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` ve `powerpick` için staging primitive'leridir. Mevcut Apollo build'lerinde bu stage edilmiş artifact'ler client-side olarak DPAPI-korumalı AES256 blob'ları şeklinde cache'lenir.
- `ls` ve `ps` sonuçları Mythic'in browser scripts ve file/process browser özellikleriyle özellikle iyi entegre olur; bu da collaborative operations sırasında operator triage işlemini belirgin biçimde hızlandırır.
- Apollo'nun fork-and-run job'ları sacrificial process ayarlarını
`spawnto_x86` / `spawnto_x64` değerlerinden devralır, parent seçimini `ppid` değerinden alır ve
ardından o anda seçili injection primitive'ini kullanır. Uygulamada bu, tek bir command için
yaptığınız OPSEC ayarlarının aynı anda `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` ve `spawn`
işlemlerini de sıklıkla etkilemesi anlamına gelir.
- Güncel olarak belgelenen Apollo injection backend'leri arasında `CreateRemoteThread`,
`QueueUserAPC` (early-bird tarzı) ve syscall'lar aracılığıyla `NtCreateThreadEx` bulunur. Gürültülü post-exploitation işlemlerinden önce
`get_injection_techniques` kullanın; hedefle veya çalıştırmak istediğiniz command'la
çakışan bir primitive'den uzaklaşmanız gerekiyorsa `set_injection_technique` kullanın.
- `blockdlls`, yalnızca post-exploitation job'ları için oluşturulan sacrificial process'leri etkiler. Bunu varsayılan
çıplak `rundll32.exe` hedefinden daha az şüpheli bir `spawnto_x64` hedefiyle
birleştirmek, assembly/PowerShell ağırlıklı tasking çalıştırmadan önce Apollo tarafında yapılabilecek en kolay değişikliklerden biridir.

Bu agent, bazı ek özelliklerle birlikte Cobalt Strike'ın Beacon'ına oldukça benzeyen çok sayıda command'a sahiptir. Bunlar arasında şunları destekler:

### Yaygın işlemler

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Mevcut çalışma dizinini değiştirir
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyalar
- `ls`: Mevcut dizindeki veya belirtilen path'teki dosya ve dizinleri listeler
- `ifconfig`: Network adapter'larını ve interface'leri alır
- `netstat`: TCP ve UDP connection bilgilerini alır
- `pwd`: Mevcut çalışma dizinini yazdırır
- `ps`: Hedef sistemde çalışan process'leri listeler (ek bilgilerle)
- `jobs`: Uzun süreli tasking ile ilişkili çalışan tüm job'ları listeler
- `download`: Hedef sistemdeki bir dosyayı local machine'a indirir
- `upload`: Local machine'daki bir dosyayı hedef sisteme yükler
- `reg_query`: Hedef sistemdeki registry key'lerini ve değerlerini sorgular
- `reg_write_value`: Belirtilen bir registry key'ine yeni bir değer yazar
- `sleep`: Agent'ın Mythic server'a ne sıklıkta check-in yapacağını belirleyen sleep interval'ını değiştirir
- Ve daha birçok command bulunur; kullanılabilir command'ların tam listesini görmek için `help` kullanın.

### Privilege escalation

- `getprivs`: Mevcut thread token'ında mümkün olduğunca çok privilege'ı etkinleştirir
- `getsystem`: winlogon'a bir handle açar ve token'ı duplicate eder; bu şekilde privilege'ları etkili biçimde SYSTEM seviyesine yükseltir
- `make_token`: Yeni bir logon session oluşturur ve bunu agent'a uygular; böylece başka bir user'ın impersonation'ına olanak tanır
- `steal_token`: Başka bir process'ten primary token çalar; böylece agent'ın o process'in user'ını impersonate etmesini sağlar
- `pth`: Pass-the-Hash attack; agent'ın plaintext password'e ihtiyaç duymadan NTLM hash kullanarak bir user olarak authenticate olmasını sağlar
- `mimikatz`: Credential'ları, hash'leri ve diğer hassas bilgileri memory'den veya SAM database'inden çıkarmak için Mimikatz command'larını çalıştırır
- `rev2self`: Agent'ın token'ını primary token'ına geri döndürür; privilege'ları etkili biçimde ilk seviyesine düşürür
- `ppid`: Yeni bir parent process ID belirleyerek post-exploitation job'ları için parent process'i değiştirir ve job execution context üzerinde daha iyi kontrol sağlar
- `printspoofer`: Print spooler security önlemlerini aşmak ve privilege escalation veya code execution sağlamak için PrintSpoofer command'larını çalıştırır
- `dcsync`: Bir user'ın Kerberos key'lerini local machine'a sync eder; böylece offline password cracking veya daha ileri attack'lere olanak tanır
- `ticket_cache_add`: Bir Kerberos ticket'ını mevcut veya belirtilen logon session'a ekler; böylece ticket reuse veya impersonation'a olanak tanır

### Process execution

- `assembly_inject`: Bir .NET assembly loader'ını remote process'e inject eder
- `blockdlls`: Microsoft tarafından imzalanmamış DLL'lerin post-exploitation job'larına yüklenmesini engeller
- `execute_assembly`: Bir .NET assembly'ini agent context'inde çalıştırır
- `execute_coff`: Bir COFF file'ını memory'de çalıştırır ve derlenmiş code'un memory içinden execution'ını sağlar
- `execute_pe`: Unmanaged bir executable'ı (PE) çalıştırır
- `keylog_inject`: Bir keylogger'ı başka bir process'e inject eder ve tuş vuruşlarını Mythic'in keylog görünümüne aktarır
- `screenshot` / `screenshot_inject`: Mevcut desktop'ın görüntüsünü doğrudan alır veya
bir screenshot assembly'sini hedef process/session'a inject ederek görüntü alır
- `get_injection_techniques`: Kullanılabilir injection technique'leri ve o anda seçili olanı gösterir
- `inline_assembly`: Bir .NET assembly'ini disposable bir AppDomain'de çalıştırır; böylece agent'ın ana process'ini etkilemeden code'un geçici olarak çalıştırılmasını sağlar
- `register_assembly`: Daha sonra çalıştırılmak üzere bir .NET assembly'sini register eder
- `register_file`: Daha sonra `execute_*` veya PowerShell tasking için agent cache'inde bir file register eder
- `run`: Executable'ı bulmak için system PATH'ini kullanarak hedef sistemde bir binary çalıştırır
- `set_injection_technique`: Post-exploitation job'ları tarafından kullanılan injection primitive'ini değiştirir
- `shinject`: Bir remote process'e shellcode inject eder ve arbitrary code'un memory içinden çalıştırılmasını sağlar
- `inject`: Agent shellcode'unu bir remote process'e inject eder ve agent code'unun memory içinden çalıştırılmasını sağlar
- `spawn`: Belirtilen executable içinde yeni bir agent session oluşturur ve shellcode'un yeni bir process'te çalıştırılmasını sağlar
- `spawnto_x64` ve `spawnto_x86`: Post-exploitation job'larında kullanılacak varsayılan binary'yi, params olmadan kullanılan ve oldukça gürültülü olan `rundll32.exe` yerine belirtilen bir path olarak değiştirir.

### Mythic Forge

Bu özellik, hedef sistemde çalıştırılabilen pre-compiled payload ve tool repository'si olan Mythic Forge'dan **COFF/BOF** file'larını yüklemeyi sağlar. Yüklenebilen tüm command'larla birlikte, bunları BOF olarak mevcut agent process'inde çalıştırarak yaygın işlemleri gerçekleştirmek mümkün olur (genellikle ayrı bir process spawn etmeye kıyasla daha iyi OPSEC ile).

Şunları yükleyerek başlayın:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Ardından, Mythic Forge'daki COFF/BOF modüllerini göstermek ve bunları seçerek execution için agent'ın memory'sine yüklemek amacıyla `forge_collections` kullanın. Varsayılan olarak Apollo'ya aşağıdaki 2 collection eklenir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir modül yüklendikten sonra listede `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir command olarak görünür.

BOF'lar için Forge'un Apollo'ya yalnızca tek bir düz argument string'i iletmediğini unutmayın. Forge, BOF parameter'larını Mythic'in typed-array formatına dönüştürür ve ardından bunları Apollo'daki `execute_coff` flow'una iletir. Forge ile yüklenen bir BOF garip davranıyorsa yalnızca yazdığınız command line'ı değil, beklenen BOF argument type'larını / entrypoint'i de kontrol edin. Ayrıca Apollo'nun daha yeni BOF loader'ının, çok daha eski 2.3.1-era build'lere kıyasla argument handling'i değiştirdiğini unutmayın; bu nedenle eski BOF'lar veya old collection'lar yalnızca marshaling beklentileri değiştiği için başarısız olabilir.

### PowerShell ve scripting execution

- `powershell_import`: Yeni bir PowerShell script'ini (.ps1) daha sonra execution için agent cache'ine import eder
- `powershell`: Agent context'inde bir PowerShell command'i execute ederek gelişmiş scripting ve automation olanağı sağlar
- `powerpick`: Bir sacrificial process'e PowerShell loader assembly'si inject eder ve bir PowerShell command'i execute eder (powershell logging olmadan).
- `psinject`: PowerShell'i belirtilen bir process'te execute ederek script'lerin başka bir process context'inde hedefli biçimde çalıştırılmasını sağlar
- `shell`: Agent context'inde, cmd.exe'de bir command çalıştırmaya benzer şekilde bir shell command'i execute eder

### Lateral Movement

- `jump_psexec`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp execute ederek yeni bir host'a lateral movement gerçekleştirmek için PsExec tekniğini kullanır.
- `jump_wmi`: Önce Apollo agent executable'ını (apollo.exe) kopyalayıp execute ederek yeni bir host'a lateral movement gerçekleştirmek için WMI tekniğini kullanır.
- `link` ve `unlink`: Callback'ler arasında (örneğin SMB/TCP üzerinden) P2P link'leri oluşturur ve sonlandırır.
- `wmiexecute`: Impersonation için isteğe bağlı credential'lar kullanarak WMI aracılığıyla local veya belirtilen remote system üzerinde bir command execute eder.
- `net_dclist`: Belirtilen domain için domain controller listesini getirir; lateral movement için potansiyel target'ları belirlemede kullanışlıdır.
- `net_localgroup`: Belirtilen computer'daki local group'ları listeler; bir computer belirtilmezse varsayılan olarak localhost kullanılır.
- `net_localgroup_member`: Local veya remote computer'da belirtilen bir group'un local group membership bilgisini getirerek belirli group'lar içindeki user'ların enumeration'ını sağlar.
- `net_shares`: Belirtilen computer'daki remote share'leri ve bunların erişilebilirliğini listeler; lateral movement için potansiyel target'ları belirlemede kullanışlıdır.
- `socks`: Target network üzerinde SOCKS 5 compliant bir proxy etkinleştirerek traffic'in compromised host üzerinden tunnel'lanmasını sağlar. proxychains gibi tool'larla uyumludur.
- `rpfwd`: Target host üzerinde belirtilen bir port'u dinlemeye başlar ve traffic'i Mythic üzerinden remote IP ve port'a forward eder; target network üzerindeki service'lere remote access sağlar.
- `listpipes`: Local system'deki tüm named pipe'ları listeler; IPC mechanism'larıyla etkileşime girerek lateral movement veya privilege escalation için yararlı olabilir.

`jump_wmi` veya `wmiexecute` tarafından kullanılan lower-level WMI execution primitive'leri için [WmiExec](lateral-movement/wmiexec.md) sayfasına bakın. Daha kapsamlı pivoting pattern'leri için [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) sayfasına bakın.

### Miscellaneous Commands
- `help`: Belirli command'ler hakkında ayrıntılı bilgi veya agent'ta kullanılabilen tüm command'ler hakkında genel bilgi görüntüler.
- `clear`: Task'leri 'cleared' olarak işaretler; böylece agent'lar tarafından alınamazlar. Tüm task'leri temizlemek için `all`, belirli bir task'i temizlemek için `task Num` belirtebilirsiniz.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon, **Linux ve macOS** executable'larına compile edilen bir Golang agent'ıdır.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Mevcut build/profile notları

- Mevcut Poseidon build'leri hem `x86_64` hem de `arm64` üzerinde Linux ve macOS'u hedefler.
- Desteklenen çıktı formatları arasında native executable'ların yanı sıra `dylib` ve `so` gibi shared-library tarzı çıktılar da bulunur.
- Poseidon `http`, `websocket`, `tcp` ve `dynamichttp` destekler; mevcut builder'lar `egress_order` ve failover eşikleri gibi multi-egress ayarlarını sunar.
- Poseidon'un mevcut capability metadata'sı browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd ve P2P özelliklerini de duyurur. Bu nedenle basit bir remote shell yerine gerçek bir Linux/macOS pivot node olarak çalışabilir.
- `proxy_bypass` ve `garble` gibi build-time seçenekleri, daha temiz network davranışına veya ek Go binary obfuscation'a ihtiyaç duyduğunuzda kontrol etmeye değerdir.
- `pty`, Linux/macOS operasyonları için en kullanışlı yeni quality-of-life komutlarından biridir; interactive PTY açar ve eski `sleep 0` + SOCKS workaround'una başvurmadan daha kapsamlı terminal etkileşimi için Mythic-side port açabilir.
- Poseidon'un mevcut docs'u macOS ağırlıklı tradecraft için özellikle ilgi çekicidir: `jxa`, JavaScript for Automation'ı bellekte çalıştırır; `screencapture`, logged-in desktop'ı yakalar; `clipboard_monitor`, pasteboard değişikliklerini stream eder; `execute_library`, local bir dylib yükleyip içindeki bir function'ı çağırır; `libinject` ise remote bir process'i disk üzerindeki dylib'ı yüklemeye zorlar.
- Uzun süre çalışan job'lar için Poseidon'un post-exploitation işlerini hard-kill edilemeyen, cooperative goroutine/thread'lerde yürüttüğünü unutmayın. Docs ayrıca şu anda built-in agent obfuscation bulunmadığını açıkça belirtir; bu nedenle build/profile düzeyindeki tradecraft, yoğun şekilde obfuscated commercial implant'lara kıyasla daha önemlidir.

Mythic-backed operasyonlar, JAMF abuse veya MDM-as-C2 fikirleri etrafındaki macOS-specific tradecraft için [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) sayfasına bakın.

Linux veya macOS üzerinde kullanıldığında bazı ilgi çekici komutları vardır:

### Common actions

- `cat`: Bir file'ın içeriğini yazdırır
- `cd`: Mevcut working directory'yi değiştirir
- `chmod`: Bir file'ın permissions'larını değiştirir
- `config`: Mevcut config'i ve host bilgilerini görüntüler
- `cp`: Bir file'ı bir konumdan diğerine kopyalar
- `curl`: İsteğe bağlı headers ve method ile tek bir web request'i çalıştırır
- `upload`: Target'a bir file upload eder
- `download`: Target system'dan local machine'e bir file download eder
- Ve daha fazlası

### Sensitive Information arama

- `triagedirectory`: Bir host üzerindeki directory içinde sensitive file'lar veya credentials gibi ilgi çekici file'ları bulur.
- `getenv`: Mevcut tüm environment variable'ları alır.

### macOS-specific tradecraft

- `jxa`: `OSAScript` üzerinden JavaScript for Automation'ı bellekte çalıştırır; ayrı script file'ları bırakmadan native macOS post-exploitation için kullanışlıdır.
- `clipboard_monitor`: Pasteboard'u poll eder ve değişiklikleri Mythic'e bildirir; copy/paste'e dayanan credential/token theft workflow'ları için kullanışlıdır.
- `screencapture`: macOS'ta kullanıcının desktop'ını capture eder.
- `execute_library`: Diskten bir dylib yükler ve belirli bir exported function'ı çağırır.
- `libinject`: Başka bir macOS process'ini diskten bir dylib yüklemeye zorlayan bir shellcode stub inject eder.
- `persist_launchd`: Doğrudan agent üzerinden LaunchAgent / LaunchDaemon persistence oluşturur.

### Lateral movement

- `ssh`: Belirlenen credentials'ları kullanarak host'a SSH yapar ve ssh spawn etmeden bir PTY açar.
- `sshauth`: Belirlenen credentials'ları kullanarak belirtilen host(lar)a SSH yapar. Bunu remote host'larda SSH üzerinden belirli bir command execute etmek veya SCP ile file transfer etmek için de kullanabilirsiniz.
- `link_tcp`: Agent'lar arasında doğrudan iletişim sağlayarak başka bir agent'a TCP üzerinden link oluşturur.
- `link_webshell`: Webshell P2P profile kullanarak bir agent'a link oluşturur ve agent'ın web interface'ine remote access sağlar.
- `rpfwd`: Reverse Port Forward başlatır veya durdurur ve target network'teki service'lere remote access sağlar.
- `socks`: Target network'te bir SOCKS5 proxy başlatır veya durdurur ve compromised host üzerinden traffic tunneling'i sağlar. Proxychains gibi tools ile uyumludur.
- `portscan`: Açık port'lar için host(lar)ı scan eder; lateral movement veya further attacks için potential target'ları belirlemede kullanışlıdır.

### Process execution

- `shell`: `/bin/sh` üzerinden tek bir shell command çalıştırır ve target system üzerinde command'ların doğrudan execute edilmesini sağlar.
- `run`: Arguments ile birlikte diskten bir command çalıştırır ve target system üzerinde binary veya script'lerin execute edilmesini sağlar.
- `pty`: Interactive PTY açar ve target system üzerindeki shell ile doğrudan etkileşim kurulmasını sağlar.






## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
