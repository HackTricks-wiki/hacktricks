# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic nedir?

Mythic, red teaming için tasarlanmış açık kaynaklı, modüler, işbirlikçi bir command and control (C2) framework’üdür. Operatörlerin Windows, Linux ve macOS dahil olmak üzere farklı işletim sistemleri genelinde agent’ları (payload’lar) yönetmesine ve dağıtmasına olanak tanır. Mythic, çoklu operatör tasking, file handling, SOCKS/rpfwd management ve payload generation için bir browser UI sağlar.

Monolitik framework’lerin aksine, Mythic repository’si kendi başına **payload type** veya C2 profiles ile gelmez. Agent’lar, wrapper’lar ve C2 profiles genellikle harici bileşenler olarak kurulur ve Mythic core’dan bağımsız olarak güncellenebilir.

### Kurulum

Mythic’i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin. Mythic directory’sinden yaygın bir bootstrap şöyledir:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic zaten çalışıyorsa, normalde `./mythic-cli install github ...` ile yeni bir agent veya profile ekleyebilir ve ardından ya Mythic'i yeniden başlatabilir ya da yeni bileşeni doğrudan başlatabilirsiniz.

### Agents

Mythic birden fazla agent destekler; bunlar, **ele geçirilmiş sistemlerde görevleri yerine getiren payloads**'tır. Her agent, belirli ihtiyaçlara göre uyarlanabilir ve farklı işletim sistemlerinde çalışabilir.

Varsayılan olarak Mythic'te yüklü hiçbir agent yoktur. Açık kaynak topluluk agent'ları [**https://github.com/MythicAgents**](https://github.com/MythicAgents) içinde bulunur ve [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html), desteklenen işletim sistemlerini, payload formats, wrappers ve C2 profiles'ı hızlıca kontrol etmek için kullanışlıdır.

O org'dan bir agent kurmak için şunu çalıştırabilirsiniz:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` formu, root olmayan bir ortamdan kurulum yaparken kullanışlıdır. Mythic zaten çalışıyor olsa bile önceki komutla yeni agent'lar ekleyebilirsiniz.

### C2 Profiles

Mythic içindeki C2 profiles, **agent'ların Mythic server ile nasıl iletişim kurduğunu** tanımlar. Communication protocol, encryption methods ve diğer ayarları belirtirler. C2 profiles oluşturabilir ve Mythic web interface üzerinden yönetebilirsiniz.

Varsayılan olarak Mythic profiles olmadan kurulur, ancak repodan bazı profilleri indirmek mümkündür [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) çalıştırarak:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Birçok public agent ve profile artık önceden derlenmiş remote container image’ları ile kurulur.
Bir bileşeni fork ederseniz veya yerelde patch’lerseniz ve Mythic eski davranışı kullanmaya devam ederse, oluşturulan `.env` girdilerinde `*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` ve `*_USE_VOLUME` değerlerini inceleyin; `*_USE_BUILD_CONTEXT="true"` etkinleştirmek genellikle Mythic’in remote image’ı sessizce yeniden kullanmak yerine local Docker context’inizden yeniden build etmesini sağlar.
- Browser script’leri, operator’lar için Mythic’in en değerli quality-of-life özelliklerinden biridir: raw command output’u tabloya, screenshot görüntüleyicilerine, download link’lerine ve doğrudan UI’dan follow-on tasking gönderen button’lara dönüştürebilirler. Bu, özellikle tekrarlayan `ls`, `ps`, triage ve file-browser workflow’ları için kullanışlıdır.
- Daha yeni Mythic build’leri, `sleep 0` polling ihtiyacını azaltan interactive tasking ve Push C2 pattern’lerini de destekler; özellikle PTY/SOCKS/rpfwd ağırlıklı operasyonlarda. Bir agent/profile bunu desteklediğinde, interactive channel’ı kullanılabilir tutmak için sunucuya sürekli check-in yapmak genellikle daha düşük overhead’lidir.

### Wrapper payloads

Wrapper payloads, teslim edilen veya kalıcı hale getirilen on-disk representation’ı değiştirirken aynı agent logic’ini korumanıza izin verir.

- `service_wrapper`: başka bir payload’u Windows service executable’a dönüştürür; execution path geçerli bir service binary gerektirdiğinde kullanışlıdır.
- `scarecrow_wrapper`: uyumlu shellcode’u ScareCrow loader ile sararak EXE/DLL/CPL gibi loader-backed output’lar üretir.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps training offerings içinde kullanılmak üzere tasarlanmış, 4.0 .NET Framework kullanan C# ile yazılmış bir Windows agent’ıdır.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo şu anda `WinExe`, `Shellcode`, `Service`, ve `Source` payloads üretebilir.
- Yaygın kullanılan Apollo profiles şunlardır: `http`, `httpx`, `smb`, `tcp`, ve `websocket`.
- `httpx`, domain rotation, proxy desteği, custom message placement ve eski statik `http` profile yerine message transforms gerektiğinde genellikle daha esnek seçenektir.
- Apollo, `service_wrapper` ve `scarecrow_wrapper` gibi wrapper payloads destekler.
- `register_file` ve `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, ve `powerpick` için staging primitive'leridir. Mevcut Apollo builds içinde, bu staged artifacts client-side DPAPI-protected AES256 blobs olarak cached edilir.
- `ls` ve `ps` sonuçları, Mythic'in browser scripts ve file/process browser ile özellikle iyi entegre olur; bu da collaborative operations sırasında operator triage işlemini belirgin şekilde hızlandırır.
- Apollo'nun fork-and-run jobs, sacrificial process ayarlarını `spawnto_x86` / `spawnto_x64` üzerinden miras alır, parent selection'ı `ppid` üzerinden alır ve ardından mevcut seçili injection primitive'i kullanır. Pratikte bu, tek bir command için yaptığınız OPSEC tuning'in çoğu zaman aynı anda `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, ve `spawn` üzerinde de etkili olduğu anlamına gelir.
- Documented Apollo injection backends arasında `CreateRemoteThread`, `QueueUserAPC` (early-bird style), ve syscalls üzerinden `NtCreateThreadEx` bulunur. Gürültülü post-exploitation öncesi `get_injection_techniques` kullanın ve hedefle ya da çalıştırmak istediğiniz command ile çakışan bir primitive'den uzaklaşmanız gerekiyorsa `set_injection_technique` kullanın.
- `blockdlls` yalnızca post-exploitation jobs için oluşturulan sacrificial processes üzerinde etki eder. Varsayılan çıplak `rundll32.exe` yerine daha az şüpheli bir `spawnto_x64` target ile birleştiğinde, assembly/PowerShell ağırlıklı tasking çalıştırmadan önce Apollo tarafında yapılabilecek en kolay değişikliklerden biridir.

Bu agent, Cobalt Strike's Beacon'e çok benzeyen ve bazı extras içeren birçok command'a sahiptir. Bunlar arasında şunları destekler:

### Common actions

- `cat`: Bir file içeriğini yazdır
- `cd`: Mevcut çalışma dizinini değiştir
- `cp`: Bir file'ı bir konumdan başka bir konuma kopyala
- `ls`: Mevcut dizindeki veya belirtilen path'teki file ve directories listesini göster
- `ifconfig`: Network adapters ve interfaces bilgilerini al
- `netstat`: TCP ve UDP connection information al
- `pwd`: Mevcut çalışma dizinini yazdır
- `ps`: Target system üzerindeki çalışan processes'leri listele (ek bilgiyle birlikte)
- `jobs`: Long-running tasking ile ilişkili tüm running jobs'ları listele
- `download`: Target system'dan local machine'e bir file indir
- `upload`: Local machine'den target system'e bir file yükle
- `reg_query`: Target system üzerindeki registry keys ve values sorgula
- `reg_write_value`: Belirtilen bir registry key'e yeni bir value yaz
- `sleep`: Agent'ın sleep interval'ini değiştir; bu, Mythic server'a ne sıklıkla check in yapacağını belirler
- Ve daha fazlası; mevcut commands'ın tam listesini görmek için `help` kullanın.

### Privilege escalation

- `getprivs`: Mevcut thread token üzerinde mümkün olduğunca çok privilege etkinleştir
- `getsystem`: winlogon'a bir handle açar ve token'ı duplicate eder, böylece privileges fiilen SYSTEM seviyesine yükselir
- `make_token`: Yeni bir logon session oluşturur ve agent'a uygular, başka bir user'ı impersonation etmeye izin verir
- `steal_token`: Başka bir process'ten bir primary token çalar, agent'ın o process'in user'ını impersonate etmesine izin verir
- `pth`: Pass-the-Hash attack, NTLM hash kullanarak plaintext password gerekmeden bir user olarak authenticate etmeye izin verir
- `mimikatz`: Memory'den veya SAM database'den credentials, hashes ve diğer hassas bilgileri çıkarmak için Mimikatz commands çalıştırır
- `rev2self`: Agent'ın token'ını primary token'ına geri döndürür, böylece privileges'ı fiilen orijinal seviyeye indirir
- `ppid`: Yeni bir parent process ID belirterek post-exploitation jobs için parent process'i değiştirir; job execution context üzerinde daha iyi kontrol sağlar
- `printspoofer`: Print spooler security measures'ı bypass etmek için PrintSpoofer commands çalıştırır; privilege escalation veya code execution sağlar
- `dcsync`: Bir user'ın Kerberos keys'lerini local machine'e sync eder; offline password cracking veya ek attacks sağlar
- `ticket_cache_add`: Current logon session'a veya belirtilen bir session'a bir Kerberos ticket ekler; ticket reuse veya impersonation sağlar

### Process execution

- `assembly_inject`: Remote process'e bir .NET assembly loader enjekte etmeye izin verir
- `blockdlls`: Post-exploitation jobs içine Microsoft imzalı olmayan DLL'lerin yüklenmesini engeller
- `execute_assembly`: Agent context'inde bir .NET assembly çalıştırır
- `execute_coff`: Memory içinde bir COFF file çalıştırır; compiled code'un in-memory execution'ına izin verir
- `execute_pe`: Bir unmanaged executable (PE) çalıştırır
- `keylog_inject`: Başka bir process'e bir keylogger enjekte eder ve keystrokes'ları Mythic'in keylog view'una geri stream eder
- `screenshot` / `screenshot_inject`: Mevcut desktop'u doğrudan ya da
hedef bir process/session içine screenshot assembly enjekte ederek yakalar
- `get_injection_techniques`: Mevcut injection techniques'leri ve şu anda seçili olanı gösterir
- `inline_assembly`: Disposable bir AppDomain içinde bir .NET assembly çalıştırır; agent'ın ana process'ini etkilemeden geçici code execution sağlar
- `register_assembly`: Daha sonra çalıştırmak için bir .NET assembly kaydet
- `register_file`: Daha sonra `execute_*` veya PowerShell tasking için agent cache'e bir file kaydet
- `run`: Executable'ı bulmak için system'in PATH'ini kullanarak target system üzerinde bir binary çalıştırır
- `set_injection_technique`: Post-exploitation jobs tarafından kullanılan injection primitive'ini değiştirir
- `shinject`: Remote process'e shellcode enjekte eder; arbitrary code'un in-memory execution'ına izin verir
- `inject`: Agent shellcode'unu remote process'e enjekte eder; agent'ın code'unun in-memory execution'ına izin verir
- `spawn`: Belirtilen executable içinde yeni bir agent session başlatır; yeni bir process içinde shellcode execution sağlar
- `spawnto_x64` and `spawnto_x86`: Varsayılan olarak `rundll32.exe` parametresiz kullanmak yerine, post-exploitation jobs'ta kullanılan default binary'yi belirtilen bir path ile değiştirir; bu çok gürültülüdür.

### Mythic Forge

Bu, target system üzerinde çalıştırılabilen önceden derlenmiş payloads ve tools deposu olan Mythic Forge'dan **COFF/BOF** files load etmeye izin verir. Yüklenebilen tüm commands ile, bunları mevcut agent process'inde BOF olarak çalıştırarak yaygın actions gerçekleştirmek mümkün olur (genellikle ayrı bir process başlatmaktan daha iyi OPSEC ile).

Kuruluma başlamak için:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` kullanarak Mythic Forge’daki COFF/BOF modüllerini gösterin; böylece bunları seçip execution için agent’ın memory’sine yükleyebilirsiniz. Varsayılan olarak, Apollo’ya aşağıdaki 2 collection eklenir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir module yüklendikten sonra, listede `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir command olarak görünür.

BOF’ler için, Forge’un Apollo’ya sadece düz bir argument string iletmediğini unutmayın. BOF parameters’larını Mythic’in typed-array formatına map eder ve ardından bunları Apollo’nun `execute_coff` flow’una forward eder. Eğer Forge ile yüklenen bir BOF garip davranıyorsa, yalnızca yazdığınız command line yerine beklenen BOF argument types / entrypoint’i kontrol edin.

### PowerShell & scripting execution

- `powershell_import`: Yeni bir PowerShell script’i (.ps1) agent cache’ine daha sonra execution için import eder
- `powershell`: Agent bağlamında bir PowerShell command’ı çalıştırır, advanced scripting ve automation’a izin verir
- `powerpick`: Bir PowerShell loader assembly’sini sacrificial process’e enjekte eder ve bir PowerShell command’ı çalıştırır (powershell logging olmadan).
- `psinject`: Belirtilen bir process içinde PowerShell çalıştırır; böylece script’lerin başka bir process bağlamında hedefli execution’unu sağlar
- `shell`: Agent bağlamında bir shell command’ı çalıştırır; cmd.exe içinde command çalıştırmaya benzer

### Lateral Movement

- `jump_psexec`: PsExec technique’ini kullanarak önce Apollo agent executable’ını (apollo.exe) kopyalayıp çalıştırarak yeni bir host’a laterally move eder
- `jump_wmi`: WMI technique’ini kullanarak önce Apollo agent executable’ını (apollo.exe) kopyalayıp çalıştırarak yeni bir host’a laterally move eder
- `link` ve `unlink`: Callback’ler arasında P2P links oluşturur ve kaldırır (örneğin SMB/TCP üzerinden)
- `wmiexecute`: İsteğe bağlı impersonation credentials ile, local veya belirtilen remote system üzerinde WMI kullanarak bir command çalıştırır
- `net_dclist`: Belirtilen domain için domain controllers listesini alır, lateral movement için potansiyel targets belirlemede kullanışlıdır
- `net_localgroup`: Belirtilen computer üzerindeki local groups’u listeler; computer belirtilmezse localhost varsayılan olur
- `net_localgroup_member`: Local veya remote computer üzerindeki belirtilen bir group için local group membership’i alır; belirli gruplardaki users’ın enumeration’ını sağlar
- `net_shares`: Belirtilen computer üzerindeki remote shares ve bunların accessibility durumunu listeler, lateral movement için potansiyel targets belirlemede kullanışlıdır
- `socks`: Target network üzerinde SOCKS 5 uyumlu bir proxy etkinleştirir; compromised host üzerinden traffic tunneling’e izin verir. proxychains gibi tools ile uyumludur.
- `rpfwd`: Target host üzerinde belirtilen portu dinlemeye başlar ve traffic’i Mythic üzerinden remote bir IP ve port’a forward eder; target network üzerindeki services’e remote access sağlar
- `listpipes`: Local system üzerindeki tüm named pipes’ları listeler; IPC mechanisms ile etkileşerek lateral movement veya privilege escalation için kullanışlı olabilir

`jump_wmi` veya `wmiexecute` altında kullanılan lower-level WMI execution primitives için [WmiExec](lateral-movement/wmiexec.md) kontrol edin. Daha geniş pivoting patterns için [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) kontrol edin.

### Miscellaneous Commands
- `help`: Agent içindeki belirli command’lar veya tüm available commands hakkında ayrıntılı bilgi gösterir
- `clear`: Task’leri 'cleared' olarak işaretler; böylece agents tarafından alınamazlar. Tüm task’leri temizlemek için `all`, belirli bir task’i temizlemek için `task Num` belirtebilirsiniz


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon, **Linux ve macOS** executable’larına derlenen bir Golang agent’ıdır.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon build'leri Linux ve macOS için `x86_64` ve `arm64` üzerinde hedeflenir.
- Supported output formats arasında native executables ile birlikte `dylib` ve `so` gibi shared-library tarzı çıktılar bulunur.
- Poseidon `http`, `websocket`, `tcp`, ve `dynamichttp` destekler; current builders ayrıca `egress_order` ve failover thresholds gibi multi-egress ayarlarını da sunar.
- Build-time options olarak `proxy_bypass` ve `garble`, daha temiz network behavior veya ekstra Go binary obfuscation gerektiğinde kontrol etmeye değerdir.
- `pty`, Linux/macOS operasyonları için en kullanışlı newer-quality-of-life komutlardan biridir çünkü interaktif bir PTY açar ve eski `sleep 0` + SOCKS workaround’una başvurmadan daha tam bir terminal interaction için Mythic-side bir port açabilir.
- Poseidon'un current docs'u özellikle macOS-heavy tradecraft için ilgi çekicidir: `jxa` JavaScript for Automation'ı in-memory çalıştırır, `screencapture` logged-in desktop'u alır, `clipboard_monitor` pasteboard değişikliklerini stream eder, `execute_library` local bir dylib yükleyip içinden bir function çağırır, ve `libinject` remote bir process'i disk üzerindeki bir dylib yüklemeye zorlar.
- Uzun süren jobs için, Poseidon'un post-exploitation work'ü cooperative olan ve hard-kill edilemeyen goroutines/threads içinde çalıştırdığını unutmayın. Docs ayrıca şu anda built-in agent obfuscation olmadığını açıkça belirtir; bu yüzden build/profile-level tradecraft, yoğun şekilde obfuscate edilmiş commercial implants’e kıyasla daha önemlidir.

Mythic-backed operations, JAMF abuse veya MDM-as-C2 ideas etrafındaki macOS-specific tradecraft için [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) kısmına bakın.

Linux veya macOS üzerinde kullanıldığında bazı ilginç komutlar vardır:

### Common actions

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Geçerli çalışma dizinini değiştirir
- `chmod`: Bir dosyanın izinlerini değiştirir
- `config`: Geçerli config ve host bilgilerini görüntüler
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyalar
- `curl`: İsteğe bağlı headers ve method ile tek bir web request çalıştırır
- `upload`: Hedefe bir dosya yükler
- `download`: Hedef sistemden yerel makineye bir dosya indirir
- Ve çok daha fazlası

### Search Sensitive Information

- `triagedirectory`: Bir host üzerindeki bir directory içinde sensitive dosyalar veya credentials gibi ilginç dosyalar bulur.
- `getenv`: Geçerli tüm environment variables'ları alır.

### macOS-specific tradecraft

- `jxa`: `OSAScript` üzerinden in-memory olarak JavaScript for Automation çalıştırır; bu, ayrı script dosyaları bırakmadan native macOS post-exploitation için kullanışlıdır.
- `clipboard_monitor`: pasteboard'u yoklar ve değişiklikleri Mythic'e geri bildirir; bu, copy/paste'e dayanan credential/token theft workflows için kullanışlıdır.
- `screencapture`: macOS üzerinde kullanıcının desktop'unu yakalar.
- `execute_library`: Diskten bir dylib yükler ve belirli bir exported function çağırır.
- `libinject`: Başka bir macOS process'ine disk üzerindeki bir dylib'i yüklemeye zorlayan bir shellcode stub'ı enjekte eder.
- `persist_launchd`: Agent üzerinden doğrudan LaunchAgent / LaunchDaemon persistence oluşturur.

### Move laterally

- `ssh`: Belirlenen credentials'ları kullanarak host'a SSH ile bağlanır ve ssh başlatmadan bir PTY açar.
- `sshauth`: Belirtilen host(s)'lara belirlenen credentials'ları kullanarak SSH ile bağlanır. Bunu ayrıca SSH üzerinden remote host'larda belirli bir command çalıştırmak veya dosyaları SCP ile taşımak için de kullanabilirsiniz.
- `link_tcp`: Başka bir agent'a TCP üzerinden bağlanır, böylece agent'lar arasında doğrudan communication sağlanır.
- `link_webshell`: webshell P2P profile kullanarak bir agent'a bağlanır ve agent'ın web interface'ine remote access sağlar.
- `rpfwd`: Reverse Port Forward başlatır veya durdurur; hedef network üzerindeki services'e remote access sağlar.
- `socks`: Hedef network üzerinde bir SOCKS5 proxy başlatır veya durdurur; compromised host üzerinden traffic tunneling için kullanılır. proxychains gibi tools ile uyumludur.
- `portscan`: host(s) üzerindeki açık portları tarar; lateral movement veya daha fazla attack için potansiyel targets belirlemede kullanışlıdır.

### Process execution

- `shell`: `/bin/sh` üzerinden tek bir shell command çalıştırır, böylece hedef sistemde commands doğrudan yürütülebilir.
- `run`: Args ile birlikte diskten bir command çalıştırır, böylece hedef sistemde binaries veya scripts yürütülebilir.
- `pty`: Interaktif bir PTY açar, böylece hedef sistemde shell ile doğrudan interaction sağlar.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
