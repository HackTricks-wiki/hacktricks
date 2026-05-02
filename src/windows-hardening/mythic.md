# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic nedir?

Mythic, red teaming için tasarlanmış, açık kaynaklı, modüler, iş birliğine dayalı bir komuta ve kontrol (C2) framework'üdür. Operatörlerin Windows, Linux ve macOS dahil olmak üzere farklı işletim sistemlerinde ajanları (payload'lar) yönetmesine ve dağıtmasına olanak tanır. Mythic, çoklu operatör görev atama, dosya işleme, SOCKS/rpfwd yönetimi ve payload oluşturma için bir browser UI sağlar.

Monolitik framework'lerin aksine, Mythic repository'sinin kendisi **payload type** veya C2 profile içermez. Agents, wrappers ve C2 profiles genellikle harici bileşenler olarak kurulur ve Mythic core'dan bağımsız olarak güncellenebilir.

### Kurulum

Mythic'i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin. Mythic dizininden yaygın bir bootstrap şu şekildedir:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic zaten çalışıyorsa, normalde `./mythic-cli install github ...` ile yeni bir agent veya profile ekleyebilir ve ardından ya Mythic’i yeniden başlatabilir ya da yeni bileşeni doğrudan başlatabilirsiniz.

### Agents

Mythic birden fazla agent destekler; bunlar **ele geçirilmiş sistemlerde görevleri gerçekleştiren payloadlardır**. Her agent belirli ihtiyaçlara göre özelleştirilebilir ve farklı işletim sistemlerinde çalışabilir.

Varsayılan olarak Mythic’te kurulu herhangi bir agent yoktur. Açık kaynak topluluk agentları [**https://github.com/MythicAgents**](https://github.com/MythicAgents) adresinde bulunur ve [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html), desteklenen işletim sistemlerini, payload formatlarını, wrappers ve C2 profile’larını hızlıca kontrol etmek için kullanışlıdır.

Bu org’dan bir agent kurmak için şu komutu çalıştırabilirsiniz:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` biçimi, root olmayan bir ortamdan kurulum yaparken faydalıdır. Mythic zaten çalışıyor olsa bile önceki komutla yeni agent'lar ekleyebilirsiniz.

### C2 Profiles

Mythic içindeki C2 profiles, **agent'lerin Mythic server ile nasıl iletişim kurduğunu** tanımlar. İletişim protokolünü, şifreleme yöntemlerini ve diğer ayarları belirtirler. C2 profiles oluşturabilir ve yönetebilirsiniz Mythic web arayüzü üzerinden.

Varsayılan olarak Mythic profiles olmadan kurulur, ancak repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) üzerinden bazı profiles indirmek mümkündür:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: compatible shellcode'u ScareCrow loader ile sarar ve EXE/DLL/CPL gibi loader-backed çıktılar üretir.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps training offerings içinde kullanılmak üzere tasarlanmış, 4.0 .NET Framework kullanan C# ile yazılmış bir Windows agent'dır.

Şununla kurun:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo şu anda `WinExe`, `Shellcode`, `Service` ve `Source` payloads üretebilir.
- Yaygın kullanılan Apollo profiles şunlardır: `http`, `httpx`, `smb`, `tcp` ve `websocket`.
- `httpx`, domain rotation, proxy desteği, custom message placement ve older static `http` profile yerine message transforms gerektiğinde genelde daha esnek seçenektir.
- Apollo, `service_wrapper` ve `scarecrow_wrapper` gibi wrapper payloads destekler.
- `register_file` ve `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` ve `powerpick` için staging primitives olarak kullanılır. Mevcut Apollo builds içinde bu staged artifacts, client-side’da DPAPI-protected AES256 blobs olarak cache’lenir.
- `ls` ve `ps` sonuçları, Mythic'in browser scripts ve file/process browser ile özellikle iyi entegre olur; bu da collaborative operations sırasında operator triage işlemini belirgin şekilde hızlandırır.

Bu agent, Cobalt Strike's Beacon ile çok benzer kılan ama bazı ekstraları da olan birçok komuta sahiptir. Bunlar arasında şunlar bulunur:

### Common actions

- `cat`: Bir dosyanın içeriğini yazdır
- `cd`: Mevcut çalışma dizinini değiştir
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyala
- `ls`: Mevcut dizindeki veya belirtilen path'teki dosyaları ve dizinleri listele
- `ifconfig`: Network adapter ve interface bilgilerini al
- `netstat`: TCP ve UDP bağlantı bilgilerini al
- `pwd`: Mevcut çalışma dizinini yazdır
- `ps`: Hedef sistemde çalışan process'leri listele (ek bilgi ile)
- `jobs`: Uzun süreli tasking ile ilişkili tüm çalışan job'ları listele
- `download`: Hedef sistemden local makineye bir dosya indir
- `upload`: Local makineden hedef sisteme bir dosya yükle
- `reg_query`: Hedef sistemde registry key ve value'ları sorgula
- `reg_write_value`: Belirtilen bir registry key'e yeni bir value yaz
- `sleep`: Agent'ın sleep interval'ini değiştir; bu, Mythic server ile ne sıklıkla check-in yapacağını belirler
- Ve daha fazlası; mevcut komutların tam listesini görmek için `help` kullanın.

### Privilege escalation

- `getprivs`: Mevcut thread token üzerinde mümkün olduğunca çok privilege etkinleştir
- `getsystem`: winlogon'a bir handle aç ve token'ı duplicate et; böylece privilege'leri etkili biçimde SYSTEM seviyesine yükselt
- `make_token`: Yeni bir logon session oluştur ve bunu agent'a uygula; başka bir kullanıcıyı impersonation etmeye izin verir
- `steal_token`: Başka bir process'ten primary token çal; böylece agent, o process'in kullanıcısını impersonation edebilir
- `pth`: Pass-the-Hash attack; plaintext password gerekmeden NTLM hash kullanarak kullanıcı gibi authenticate etmeye izin verir
- `mimikatz`: Memory veya SAM database'den credentials, hash'ler ve diğer hassas bilgileri çıkarmak için Mimikatz komutlarını çalıştır
- `rev2self`: Agent'ın token'ını primary token'ına geri döndür; böylece privilege'leri etkili biçimde orijinal seviyeye indirir
- `ppid`: Yeni bir parent process ID belirterek post-exploitation jobs için parent process'i değiştir; bu, job execution context üzerinde daha iyi kontrol sağlar
- `printspoofer`: PrintSpoofer komutlarını çalıştırarak print spooler security measures'ını bypass et; bu, privilege escalation veya code execution sağlar
- `dcsync`: Bir kullanıcının Kerberos key'lerini local makineye sync et; bu, offline password cracking veya further attacks için izin verir
- `ticket_cache_add`: Mevcut logon session'a veya belirtilen bir session'a Kerberos ticket ekle; bu, ticket reuse veya impersonation sağlar

### Process execution

- `assembly_inject`: Uzak bir process'e .NET assembly loader inject etmeye izin verir
- `blockdlls`: Microsoft tarafından imzalanmamış DLL'lerin post-exploitation jobs içinde yüklenmesini engelle
- `execute_assembly`: Agent bağlamında bir .NET assembly çalıştırır
- `execute_coff`: Bellekte bir COFF file çalıştırır; bu, compiled code'un in-memory execution'ına izin verir
- `execute_pe`: Unmanaged bir executable (PE) çalıştırır
- `get_injection_techniques`: Kullanılabilir injection techniques'i ve şu anda seçili olanı göster
- `inline_assembly`: Disposable bir AppDomain içinde bir .NET assembly çalıştırır; bu, agent'ın ana process'ini etkilemeden geçici code execution sağlar
- `register_assembly`: Daha sonra çalıştırmak üzere bir .NET assembly kaydet
- `register_file`: Daha sonra `execute_*` veya PowerShell tasking için agent cache'e bir dosya kaydet
- `run`: Executable'ı bulmak için sistemin PATH'ini kullanarak hedef sistemde bir binary çalıştırır
- `set_injection_technique`: Post-exploitation jobs tarafından kullanılan injection primitive'ini değiştir
- `shinject`: Bir remote process'e shellcode inject eder; bu, arbitrary code'un in-memory execution'ına izin verir
- `inject`: Bir remote process'e agent shellcode inject eder; bu, agent'ın code'unun in-memory execution'ına izin verir
- `spawn`: Belirtilen executable içinde yeni bir agent session başlatır; bu, yeni bir process'te shellcode execution sağlar
- `spawnto_x64` ve `spawnto_x86`: Post-exploitation jobs içinde kullanılan varsayılan binary'yi, params olmadan `rundll32.exe` kullanmak yerine belirtilen bir path'e değiştir; bu oldukça gürültülüdür.

### Mythic Forge

Bu, hedef sistemde çalıştırılabilen önceden derlenmiş payloads ve tools deposu olan Mythic Forge'dan **COFF/BOF** dosyalarını `load` etmeye izin verir. Yüklenebilen tüm komutlarla, bunları mevcut agent process'i içinde BOF'ler olarak çalıştırarak yaygın actions gerçekleştirmek mümkün olur (genellikle ayrı bir process başlatmaktan daha iyi OPSEC ile).

Şunları yüklemeye başlayın:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` kullanarak Mythic Forge içindeki COFF/BOF modüllerini gösterin; böylece bunları seçip agent’ın belleğine yükleyerek çalıştırabilirsiniz. Varsayılan olarak, Apollo içinde aşağıdaki 2 collection eklenir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir module yüklendikten sonra, listede `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir command olarak görünecektir.

### PowerShell & scripting execution

- `powershell_import`: Daha sonra çalıştırmak üzere agent cache’ine yeni bir PowerShell scripti (.ps1) import eder
- `powershell`: Agent bağlamında bir PowerShell komutu çalıştırır; gelişmiş scripting ve automation sağlar
- `powerpick`: Bir PowerShell loader assembly’sini feda edilen bir process içine inject eder ve bir PowerShell komutu çalıştırır (powershell logging olmadan).
- `psinject`: Belirtilen bir process içinde PowerShell çalıştırır; başka bir process bağlamında scriptlerin hedefli olarak çalıştırılmasını sağlar
- `shell`: cmd.exe içinde çalıştırmaya benzer şekilde, agent bağlamında bir shell komutu çalıştırır

### Lateral Movement

- `jump_psexec`: PsExec tekniğini kullanarak, önce Apollo agent executable’ını (apollo.exe) kopyalayıp çalıştırarak yeni bir hosta laterally move eder.
- `jump_wmi`: WMI tekniğini kullanarak, önce Apollo agent executable’ını (apollo.exe) kopyalayıp çalıştırarak yeni bir hosta laterally move eder.
- `link` and `unlink`: Callback’ler arasında P2P bağlantıları oluşturur ve sonlandırır (örneğin SMB/TCP üzerinden).
- `wmiexecute`: WMI kullanarak local veya belirtilen remote sistem üzerinde bir komut çalıştırır; impersonation için isteğe bağlı credentials desteği vardır.
- `net_dclist`: Belirtilen domain için domain controller listesini alır; lateral movement için potansiyel hedefleri belirlemede faydalıdır.
- `net_localgroup`: Belirtilen bilgisayardaki local group’ları listeler; bir bilgisayar belirtilmezse varsayılan olarak localhost kullanılır.
- `net_localgroup_member`: Local veya remote bilgisayarda belirtilen bir group için local group membership bilgisini alır; belirli gruplardaki kullanıcıları enumerate etmeyi sağlar.
- `net_shares`: Belirtilen bilgisayardaki remote share’leri ve erişilebilirliklerini listeler; lateral movement için potansiyel hedefleri belirlemede faydalıdır.
- `socks`: Hedef ağ üzerinde SOCKS 5 uyumlu bir proxy etkinleştirir; compromised host üzerinden trafiğin tunneling yapılmasını sağlar. proxychains gibi araçlarla uyumludur.
- `rpfwd`: Hedef host üzerinde belirtilen bir portta dinlemeye başlar ve trafiği Mythic üzerinden remote bir IP ve porta forward eder; hedef ağdaki servislere remote access sağlar.
- `listpipes`: Local sistemdeki tüm named pipe’ları listeler; IPC mekanizmalarıyla etkileşerek lateral movement veya privilege escalation için yararlı olabilir.

`jump_wmi` veya `wmiexecute` altında kullanılan daha düşük seviyeli WMI execution primitives için [WmiExec](lateral-movement/wmiexec.md) kısmına bakın. Daha geniş pivoting kalıpları için [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) kısmına bakın.

### Miscellaneous Commands
- `help`: Agent içindeki belirli komutlar veya mevcut tüm komutlar hakkında ayrıntılı bilgi gösterir.
- `clear`: Görevleri 'cleared' olarak işaretler; böylece agent’lar tarafından alınamazlar. Tüm görevleri temizlemek için `all`, belirli bir görevi temizlemek için `task Num` belirtebilirsiniz.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon, **Linux ve macOS** executable’larına derlenen bir Golang agent’tır.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notları

- Mevcut Poseidon build’leri Linux ve macOS hedefler, hem `x86_64` hem de `arm64` için.
- Desteklenen çıktı formatları, native executable’lar ile birlikte `dylib` ve `so` gibi shared-library tarzı çıktıları içerir.
- Poseidon `http`, `websocket`, `tcp` ve `dynamichttp` destekler; mevcut builder’lar `egress_order` ve failover thresholds gibi multi-egress ayarlarını sunar.
- `proxy_bypass` ve `garble` gibi build-time seçenekleri, daha temiz network davranışı veya ek Go binary obfuscation gerektiğinde kontrol etmeye değerdir.

Mythic-backed operasyonlar, JAMF abuse veya MDM-as-C2 fikirleri etrafındaki macOS-spesifik tradecraft için [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) bölümüne bakın.

Linux veya macOS üzerinde kullanıldığında bazı ilginç komutları vardır:

### Common actions

- `cat`: Bir dosyanın içeriğini yazdırır
- `cd`: Mevcut çalışma dizinini değiştirir
- `chmod`: Bir dosyanın permissions’ını değiştirir
- `config`: Mevcut config ve host bilgilerini görüntüler
- `cp`: Bir dosyayı bir konumdan başka bir konuma kopyalar
- `curl`: İsteğe bağlı headers ve method ile tek bir web request çalıştırır
- `upload`: Hedefe bir dosya yükler
- `download`: Hedef sistemden yerel makineye bir dosya indirir
- Ve daha fazlası

### Search Sensitive Information

- `triagedirectory`: Bir host üzerindeki bir dizin içinde sensitive files veya credentials gibi ilginç dosyaları bulur.
- `getenv`: Mevcut tüm environment variables’ları alır.

### Move laterally

- `ssh`: Belirlenen credentials kullanarak host’a SSH ile bağlanır ve ssh başlatmadan bir PTY açar.
- `sshauth`: Belirlenen credentials kullanarak belirtilen host’lara SSH ile bağlanır. Bunu ayrıca remote host’larda belirli bir command çalıştırmak veya dosyaları SCP ile aktarmak için de kullanabilirsiniz.
- `link_tcp`: TCP üzerinden başka bir agent’a bağlanır ve agent’lar arasında doğrudan communication sağlar.
- `link_webshell`: webshell P2P profile kullanarak bir agent’a bağlanır ve agent’ın web interface’ine remote access sağlar.
- `rpfwd`: Bir Reverse Port Forward başlatır veya durdurur; target network üzerindeki services’e remote access sağlar.
- `socks`: Target network üzerinde bir SOCKS5 proxy başlatır veya durdurur; compromised host üzerinden traffic tunneling sağlar. proxychains gibi tools ile uyumludur.
- `portscan`: Open ports için host’ları tarar; lateral movement veya daha fazla attack için potansiyel targets belirlemede faydalıdır.

### Process execution

- `shell`: `/bin/sh` üzerinden tek bir shell command çalıştırır ve target system üzerinde commands’in doğrudan çalıştırılmasını sağlar.
- `run`: Arguments ile diskten bir command çalıştırır ve target system üzerinde binaries veya scripts’in çalıştırılmasını sağlar.
- `pty`: Etkileşimli bir PTY açar ve target system üzerindeki shell ile doğrudan interaction sağlar.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
