# Windows Kredensiaalbeskerming

## Kredensiaalbeskerming

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Die [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protokol, wat met Windows XP bekendgestel is, is ontwerp vir autentisering via die HTTP-protokol en is **standaard geaktiveer op Windows XP tot Windows 8.0 en Windows Server 2003 tot Windows Server 2012**. Hierdie standaardinstelling lei tot **planktekst wagwoordopberging in LSASS** (Local Security Authority Subsystem Service). 'n Aanvaller kan Mimikatz gebruik om **hierdie kredensiale** te **onttrek** deur die volgende uit te voer:
```bash
sekurlsa::wdigest
```
Om **hierdie funksie aan of af te skakel**, moet die _**UseLogonCredential**_ en _**Negotiate**_ registersleutels binne _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" gestel word. As hierdie sleutels **afwesig of op "0" gestel is**, is WDigest **gedeaktiveer**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Beskerming

Begin met **Windows 8.1**, het Microsoft die sekuriteit van LSA verbeter om **ongeautoriseerde geheuelees of kode-inspuitings deur onbetroubare prosesse** te blokkeer. Hierdie verbetering hinder die tipiese funksionering van opdragte soos `mimikatz.exe sekurlsa:logonpasswords`. Om **hierdie verbeterde beskerming te aktiveer**, moet die _**RunAsPPL**_ waarde in _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ aangepas word na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Dit is moontlik om hierdie beskerming te omseil met behulp van die Mimikatz bestuurder mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, 'n kenmerk wat eksklusief is vir **Windows 10 (Enterprise en Education edisies)**, verbeter die sekuriteit van masjien kredensiale deur gebruik te maak van **Virtual Secure Mode (VSM)** en **Virtualization Based Security (VBS)**. Dit benut CPU virtualisering uitbreidings om sleutelprosesse binne 'n beskermde geheue ruimte te isoleer, weg van die hoofbedryfstelsel se bereik. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM kan verkry nie, wat effektief kredensiale teen aanvalle soos **pass-the-hash** beskerm. Die **Local Security Authority (LSA)** werk binne hierdie veilige omgewing as 'n trustlet, terwyl die **LSASS** proses in die hoof OS bloot as 'n kommunikeerder met die VSM se LSA optree.

Standaard is **Credential Guard** nie aktief nie en vereis handmatige aktivering binne 'n organisasie. Dit is krities vir die verbetering van sekuriteit teen gereedskap soos **Mimikatz**, wat belemmer word in hul vermoë om kredensiale te onttrek. egter, kwesbaarhede kan steeds benut word deur die toevoeging van pasgemaakte **Security Support Providers (SSP)** om kredensiale in duidelike teks tydens aanmeldpogings te vang.

Om die aktiveringsstatus van **Credential Guard** te verifieer, kan die registriesleutel _**LsaCfgFlags**_ onder _**HKLM\System\CurrentControlSet\Control\LSA**_ nagegaan word. 'n Waarde van "**1**" dui aktivering met **UEFI slot** aan, "**2**" sonder slot, en "**0**" dui aan dat dit nie geaktiveer is nie. Hierdie registrasie kontrole, terwyl 'n sterk aanduiding, is nie die enigste stap om Credential Guard te aktiveer nie. Gedetailleerde leiding en 'n PowerShell-skrip om hierdie kenmerk te aktiveer is aanlyn beskikbaar.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip en instruksies oor die aktivering van **Credential Guard** in Windows 10 en sy outomatiese aktivering in kompatible stelsels van **Windows 11 Enterprise en Education (weergawe 22H2)**, besoek [Microsoft se dokumentasie](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Verder besonderhede oor die implementering van pasgemaakte SSPs vir kredensievangs word verskaf in [hierdie gids](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 en Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke bekendgestel, insluitend die _**Restricted Admin mode vir RDP**_. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat verband hou met [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) aanvalle te verminder.

Tradisioneel, wanneer jy met 'n afstandrekenaar via RDP verbind, word jou kredensiale op die teikenmasjien gestoor. Dit stel 'n beduidende sekuriteitsrisiko voor, veral wanneer jy rekeninge met verhoogde voorregte gebruik. Met die bekendstelling van _**Restricted Admin mode**_ word hierdie risiko egter aansienlik verminder.

Wanneer jy 'n RDP-verbinding begin met die opdrag **mstsc.exe /RestrictedAdmin**, word die outentisering na die afstandrekenaar uitgevoer sonder om jou kredensiale daarop te stoor. Hierdie benadering verseker dat, in die geval van 'n malware-infeksie of as 'n kwaadwillige gebruiker toegang tot die afstandbediener verkry, jou kredensiale nie gecompromitteer word nie, aangesien dit nie op die bediener gestoor word nie.

Dit is belangrik om te noem dat in **Restricted Admin mode**, pogings om netwerkbronne vanaf die RDP-sessie te benader nie jou persoonlike kredensiale sal gebruik nie; eerder word die **masjien se identiteit** gebruik.

Hierdie kenmerk merk 'n beduidende stap vorentoe in die beveiliging van afstanddesktopverbindinge en die beskerming van sensitiewe inligting teen blootstelling in die geval van 'n sekuriteitsbreuk.

![](../../images/RAM.png)

Vir meer gedetailleerde inligting besoek [hierdie hulpbron](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Gekapte Kredensiale

Windows beveilig **domein kredensiale** deur die **Local Security Authority (LSA)**, wat aanmeldprosesse met sekuriteitsprotokolle soos **Kerberos** en **NTLM** ondersteun. 'n Sleutelkenmerk van Windows is sy vermoë om die **laaste tien domein aanmeldings** te kas om te verseker dat gebruikers steeds toegang tot hul rekenaars kan verkry, selfs as die **domeinbeheerder aflyn** is—'n voordeel vir skootrekenaargebruikers wat dikwels van hul maatskappy se netwerk af is.

Die aantal gekapte aanmeldings is aanpasbaar via 'n spesifieke **registersleutel of groepbeleid**. Om hierdie instelling te besigtig of te verander, word die volgende opdrag gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gekapte geloofsbriewe word streng beheer, met slegs die **SYSTEM** rekening wat die nodige regte het om dit te sien. Administrators wat toegang tot hierdie inligting benodig, moet dit met SYSTEM gebruikersregte doen. Die geloofsbriewe word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gekapte geloofsbriewe te onttrek met die opdrag `lsadump::cache`.

Vir verdere besonderhede bied die oorspronklike [bron](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.

## Gekapte Gebruikers

Lidmaatskap in die **Gekapte Gebruikersgroep** stel verskeie sekuriteitsverbeterings vir gebruikers in, wat hoër vlakke van beskerming teen diefstal en misbruik van geloofsbriewe verseker:

- **Geloofsbriefdelegasie (CredSSP)**: Selfs al is die Groepsbeleid instelling vir **Toelaat om standaard geloofsbriewe te delegeren** geaktiveer, sal die teksgeloofsbriewe van Gekapte Gebruikers nie gekap word nie.
- **Windows Digest**: Begin vanaf **Windows 8.1 en Windows Server 2012 R2**, sal die stelsel nie teksgeloofsbriewe van Gekapte Gebruikers cache nie, ongeag die status van Windows Digest.
- **NTLM**: Die stelsel sal nie teksgeloofsbriewe van Gekapte Gebruikers of NT eenrigting funksies (NTOWF) cache nie.
- **Kerberos**: Vir Gekapte Gebruikers sal Kerberos-verifikasie nie **DES** of **RC4 sleutels** genereer nie, en dit sal ook nie teksgeloofsbriewe of langtermynsleutels buite die aanvanklike Ticket-Granting Ticket (TGT) verkryging cache nie.
- **Offline Aanmelding**: Gekapte Gebruikers sal nie 'n gekapte verifikator hê wat by aanmelding of ontgrendeling geskep word nie, wat beteken dat offline aanmelding nie vir hierdie rekeninge ondersteun word nie.

Hierdie beskermings word geaktiveer die oomblik wanneer 'n gebruiker, wat 'n lid van die **Gekapte Gebruikersgroep** is, by die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls in plek is om te beskerm teen verskeie metodes van geloofsbriefkompromie.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [dokumentasie](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabel van** [**die docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
