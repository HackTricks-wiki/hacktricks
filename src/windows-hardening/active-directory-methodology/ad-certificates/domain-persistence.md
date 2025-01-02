# AD CS Domein Volharding

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die domein volharding tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Kyk daarna vir verdere besonderhede.

## Vervalsing van Sertifikate met Gesteelde CA Sertifikate - DPERSIST1

Hoe kan jy sê dat 'n sertifikaat 'n CA sertifikaat is?

Dit kan bepaal word dat 'n sertifikaat 'n CA sertifikaat is as verskeie voorwaardes nagekom word:

- Die sertifikaat word op die CA bediener gestoor, met sy privaat sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM as die bedryfstelsel dit ondersteun.
- Beide die Uitgewer en Onderwerp velde van die sertifikaat stem ooreen met die onderskeibare naam van die CA.
- 'n "CA Weergawe" uitbreiding is eksklusief teenwoordig in die CA sertifikate.
- Die sertifikaat ontbreek Extended Key Usage (EKU) velde.

Om die privaat sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc` hulpmiddel op die CA bediener die ondersteunde metode via die ingeboude GUI. Nietemin, hierdie sertifikaat verskil nie van ander wat binne die stelsel gestoor is nie; dus kan metodes soos die [THEFT2 tegniek](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) toegepas word vir onttrekking.

Die sertifikaat en privaat sleutel kan ook verkry word met Certipy met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Na die verkryging van die CA-sertifikaat en sy private sleutel in `.pfx` formaat, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Die gebruiker wat teiken vir sertifikaat vervalsing moet aktief wees en in staat wees om in te log in Active Directory vir die proses om te slaag. Vervalsing van 'n sertifikaat vir spesiale rekeninge soos krbtgt is ondoeltreffend.

Hierdie vervalste sertifikaat sal **geldigheid** hê tot die einddatum wat gespesifiseer is en so **lank as die wortel CA-sertifikaat geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, so gekombineer met **S4U2Self**, kan 'n aanvaller **volharding op enige domeinmasjien handhaaf** solank as wat die CA-sertifikaat geldig is.\
Boonop kan die **sertifikate wat met hierdie metode gegenereer word** **nie herroep** word nie, aangesien die CA nie daarvan bewus is nie.

## Vertroue op Rogue CA Sertifikate - DPERSIST2

Die `NTAuthCertificates` objek is gedefinieer om een of meer **CA-sertifikate** binne sy `cacertificate` attribuut te bevat, wat Active Directory (AD) gebruik. Die verifikasieproses deur die **domeinbeheerder** behels die nagaan van die `NTAuthCertificates` objek vir 'n inskrywing wat ooreenstem met die **CA gespesifiseer** in die Uitgever veld van die autentiserende **sertifikaat**. Autentisering gaan voort as 'n ooreenkoms gevind word.

'n Self-ondertekende CA-sertifikaat kan by die `NTAuthCertificates` objek gevoeg word deur 'n aanvaller, op voorwaarde dat hulle beheer oor hierdie AD objek het. Gewoonlik word slegs lede van die **Enterprise Admin** groep, saam met **Domain Admins** of **Administrators** in die **woudwortel se domein**, toestemming gegee om hierdie objek te wysig. Hulle kan die `NTAuthCertificates` objek redigeer met `certutil.exe` met die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

Hierdie vermoë is veral relevant wanneer dit saam met 'n voorheen uiteengesette metode wat ForgeCert betrek, gebruik word om sertifikate dinamies te genereer.

## Kwaadwillige Misconfigurasie - DPERSIST3

Geleenthede vir **volharding** deur **veiligheidsbeskrywer wysigings van AD CS** komponente is volop. Wysigings wat in die "[Domein Escalation](domain-escalation.md)" afdeling beskryf word, kan kwaadwillig geïmplementeer word deur 'n aanvaller met verhoogde toegang. Dit sluit die toevoeging van "beheerregte" (bv. WriteOwner/WriteDACL/etc.) aan sensitiewe komponente soos:

- Die **CA bediener se AD rekenaar** objek
- Die **CA bediener se RPC/DCOM bediener**
- Enige **afstammeling AD objek of houer** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld, die Sertifikaat Templates houer, Sertifiseringsowerhede houer, die NTAuthCertificates objek, ens.)
- **AD groepe wat regte gedelegeer het om AD CS te beheer** per standaard of deur die organisasie (soos die ingeboude Cert Publishers groep en enige van sy lede)

'n Voorbeeld van kwaadwillige implementering sou 'n aanvaller behels, wat **verhoogde toestemmings** in die domein het, wat die **`WriteOwner`** toestemming aan die standaard **`User`** sertifikaat sjabloon voeg, met die aanvaller as die hoof vir die reg. Om dit te benut, sou die aanvaller eers die eienaarskap van die **`User`** sjabloon na hulself verander. Daarna sou die **`mspki-certificate-name-flag`** op die sjabloon op **1** gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die versoek te verskaf. Vervolgens kan die aanvaller **inskryf** met behulp van die **sjabloon**, 'n **domein administrateur** naam as 'n alternatiewe naam kies, en die verkryde sertifikaat gebruik vir autentisering as die DA.

{{#include ../../../banners/hacktricks-training.md}}
