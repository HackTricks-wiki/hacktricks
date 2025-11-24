# BloodHound & Zana Nyingine za Active Directory Enumeration

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> TAARIFA: Ukurasa huu unakusanya baadhi ya zana muhimu zaidi za **enumerate** na **visualise** mahusiano ya Active Directory. Kwa ukusanyaji kupitia njia ya kimyakimya ya **Active Directory Web Services (ADWS)** angalia rejea hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni **AD viewer & editor** ya hali ya juu ambayo inaruhusu:

* Kuvinjari mti wa directory kwa kutumia GUI
* Kuhariri attributes za object & security descriptors
* Uundaji wa snapshot / kulinganisha kwa uchambuzi wa offline

### Matumizi ya haraka

1. Anzisha zana na uunganishe na `dc01.corp.local` kwa kutumia credentials yoyote ya domain.
2. Tengeneza snapshot ya offline kupitia `File ➜ Create Snapshot`.
3. Linganisha snapshots mbili kwa `File ➜ Compare` kutambua mabadiliko ya ruhusa.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) inachota seti kubwa ya artefakti kutoka kwenye domain (ACLs, GPOs, trusts, CA templates …) na inatoa **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (uonyeshaji wa grafu)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) inatumia nadharia ya grafu + Neo4j kufichua uhusiano wa ruhusa uliyofichika ndani ya on-prem AD & Azure AD.

### Usanidi (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Wakusanyaji

* `SharpHound.exe` / `Invoke-BloodHound` – toleo la asili au la PowerShell
* `AzureHound` – uorodheshaji wa Azure AD
* **SoaPy + BOFHound** – ukusanyaji wa ADWS (angalia kiungo hapo juu)

#### Modi za kawaida za SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Collectors huunda JSON ambayo inaingizwa kupitia BloodHound GUI.

---

## Kuweka kipaumbele Kerberoasting kwa kutumia BloodHound

Muktadha wa graph ni muhimu ili kuepuka roasting yenye kelele na isiyo ya mpangilio. Mtiririko wa kazi mwepesi:

1. **Kusanya kila kitu mara moja** kwa kutumia collector inayolingana na ADWS (e.g. RustHound-CE) ili uweze kufanya kazi offline na kujaribu njia bila kugusa DC tena:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Ingia ZIP, weka compromised principal kama owned**, kisha endesha built-in queries kama *Kerberoastable Users* na *Shortest Paths to Domain Admins*. Hii mara moja inaonyesha akaunti zenye SPN zikiwa na uanachama wa vikundi wenye manufaa (Exchange, IT, tier0 service accounts, etc.).
3. **Panga kipaumbele kwa blast radius** – zingatia SPNs zinazosimamia miundombinu ya pamoja au zina haki za admin, na angalia `pwdLastSet`, `lastLogon`, na aina za encryption zilizoruhusiwa kabla ya kutumia mizunguko ya kuvunja.
4. **Omba tiketi unazojali tu**. Zana kama NetExec zinaweza kulenga `sAMAccountName`s zilizochaguliwa ili kila ombi la LDAP ROAST liwe na msingi wazi:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, kisha mara moja uliza tena BloodHound ili kupanga post-exploitation kwa idhinisho mpya.

Njia hii inahifadhi uwiano wa ishara na kelele kuwa juu, inapunguza kiasi kinachoweza kugunduliwa (hakuna maombi ya wingi ya SPN), na inahakikisha kwamba kila cracked ticket inatafsiriwa kuwa hatua zenye maana za kupandisha idhini.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) huorodhesha **Group Policy Objects** na inaangazia mipangilio isiyo sahihi.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) hufanya **ukaguzi wa afya** wa Active Directory na hutengeneza ripoti ya HTML yenye ukadiriaji wa hatari.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Marejeleo

- [HackTheBox Mirage: Kuunganisha NFS Leaks, Matumizi mabaya ya Dynamic DNS, NATS Credential Theft, JetStream Secrets, na Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
