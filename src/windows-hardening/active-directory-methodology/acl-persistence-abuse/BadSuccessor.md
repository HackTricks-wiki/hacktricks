# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Gedelegeerde Bestuurde Diens Rekeninge (**dMSAs**) is 'n splinternuwe AD hoofstuk tipe wat met **Windows Server 2025** bekendgestel is. Hulle is ontwerp om verouderde diensrekeninge te vervang deur 'n een-klik “migrasie” wat outomaties die ou rekening se Diens Hoofstuk Namen (SPNs), groep lidmaatskappe, delegasie instellings, en selfs kriptografiese sleutels na die nuwe dMSA kopieer, wat toepassings 'n naatlose oorgang bied en die risiko van Kerberoasting elimineer.

Akamai navorsers het gevind dat 'n enkele attribuut — **`msDS‑ManagedAccountPrecededByLink`** — die KDC vertel watter verouderde rekening 'n dMSA “opvolg”. As 'n aanvaller daardie attribuut kan skryf (en **`msDS‑DelegatedMSAState` → 2** kan omskakel), sal die KDC gelukkig 'n PAC bou wat **elke SID van die gekose slagoffer erf**, wat effektief die dMSA in staat stel om enige gebruiker na te volg, insluitend Domein Administrators.

## Wat is 'n dMSA presies?

* Gebou op top van **gMSA** tegnologie maar gestoor as die nuwe AD klas **`msDS‑DelegatedManagedServiceAccount`**.
* Ondersteun 'n **opt-in migrasie**: die aanroep van `Start‑ADServiceAccountMigration` koppel die dMSA aan die verouderde rekening, gee die verouderde rekening skryfrechten op `msDS‑GroupMSAMembership`, en draai `msDS‑DelegatedMSAState` = 1 om.
* Na `Complete‑ADServiceAccountMigration`, word die vervangde rekening gedeaktiveer en die dMSA word ten volle funksioneel; enige gasheer wat voorheen die verouderde rekening gebruik het, word outomaties gemagtig om die dMSA se wagwoord te trek.
* Tydens verifikasie, embed die KDC 'n **KERB‑SUPERSEDED‑BY‑USER** aanduiding sodat Windows 11/24H2 kliënte deursigtig weer probeer met die dMSA.

## Vereistes om aan te val
1. **Ten minste een Windows Server 2025 DC** sodat die dMSA LDAP klas en KDC logika bestaan.
2. **Enige objek-skepping of attribuut-skryfrechte op 'n OU** (enige OU) – bv. `Create msDS‑DelegatedManagedServiceAccount` of eenvoudig **Create All Child Objects**. Akamai het gevind dat 91% van werklike huurders sulke “benigne” OU toestemmings aan nie-administrateurs toeken.
3. Vermoë om gereedskap (PowerShell/Rubeus) van enige domein-verbonden gasheer te loop om Kerberos kaartjies aan te vra.
*Geen beheer oor die slagoffer gebruiker is nodig nie; die aanval raak nooit die teikenrekening direk nie.*

## Stap-vir-stap: BadSuccessor*privilege escalasie

1. **Vind of skep 'n dMSA wat jy beheer**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Omdat jy die objek binne 'n OU geskep het waartoe jy kan skryf, besit jy outomaties al sy attribuut.

2. **Simuleer 'n “voltooide migrasie” in twee LDAP skrywe**:
- Stel `msDS‑ManagedAccountPrecededByLink = DN` van enige slagoffer in (bv. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Stel `msDS‑DelegatedMSAState = 2` (migrasie-voltooi).

Gereedskap soos **Set‑ADComputer, ldapmodify**, of selfs **ADSI Edit** werk; geen domein-administrateur regte is nodig nie.

3. **Vra 'n TGT vir die dMSA aan** — Rubeus ondersteun die `/dmsa` vlag:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Die teruggekeer PAC bevat nou die SID 500 (Administrator) plus Domein Administrators/Enterprise Administrators groepe.

## Versamel al die gebruikers se wagwoorde

Tydens wettige migrasies moet die KDC die nuwe dMSA toelaat om **kaartjies wat aan die ou rekening voor die oorgang uitgereik is, te ontsleutel**. Om te verhoed dat lewende sessies gebroke word, plaas dit beide huidige sleutels en vorige sleutels binne 'n nuwe ASN.1 blob genaamd **`KERB‑DMSA‑KEY‑PACKAGE`**.

Omdat ons valse migrasie beweer dat die dMSA die slagoffer opvolg, kopieer die KDC plegtig die slagoffer se RC4‑HMAC sleutel in die **vorige-sleutels** lys – selfs al het die dMSA nooit 'n “vorige” wagwoord gehad nie. Daardie RC4 sleutel is nie gesout nie, so dit is effektief die slagoffer se NT hash, wat die aanvaller **offline krak of “pass-the-hash”** vermoë bied.

Daarom laat massakoppeling van duisende gebruikers 'n aanvaller toe om hashes “op skaal” te dump, wat **BadSuccessor in beide 'n privilege-escalasie en kredensieël-kompromie primitief** omskep.

## Gereedskap

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Verwysings

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
