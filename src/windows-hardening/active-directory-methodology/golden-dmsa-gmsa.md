# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows Managed Service Accounts su domenски entiteti namenjeni pokretanju servisa bez potrebe da administrator upravlja dugotrajnom lozinkom:

1. **gMSA** (group Managed Service Account) mogu koristiti računari autorizovani putem `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) uveden je u **Windows Server 2025**. On vezuje normalnu autentikaciju za identitete autorizovanih računara i može zameniti legacy service account kroz migracioni workflow.

Ne mešajte **Golden dMSA** sa **BadSuccessor**. Golden dMSA zahteva kompromitovanje KDS root-key materijala i izvodi ključeve managed account-a; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) umesto toga zloupotrebljava kontrolu nad dMSA objektom i njegovim atributima migracije.

DC ne čuva nezavisno generisanu clear-text lozinku za svaki gMSA. On izvodi lozinku naloga iz **KDS root key-a**, vremenski indeksiranog Group Key Distribution Protocol (GKDI) ključa i SID-a naloga. Root-key objekti su `msKds-ProvRootKey` objekti ispod `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; osetljiva vrednost je `msKds-RootKeyData`. `msDS-ManagedPasswordId` **nije GUID**: to je binarni identifikator ključa koji sadrži GUID KDS root key-a, GKDI `L0`/`L1`/`L2` indekse i metapodatke domena/šume. DC primenjuje KDF sa labelom `GMSA PASSWORD` i binarnim SID-om kao kontekstom, a zatim izlaže `MSDS-MANAGEDPASSWORD_BLOB` samo principalima autorizovanim za preuzimanje gMSA lozinke.<sup>[[2]](#references)</sup>

dMSA se operativno obično razlikuje: njegova tajna treba da ostane na DC-u, a KDC izdaje credentials autorizovanom računaru. Međutim, dMSA ponovo koriste osnovnu KDS/GKDI derivaciju lozinke. Golden dMSA direktno rekonstruiše tu tajnu i time zaobilazi predviđeni machine-bound flow i Credential Guard na service host-u.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Nakon ekstrakcije KDS root key-a, attacker može izvesti lozinke za naloge povezane sa tim ključem bez čitanja `msDS-ManagedPassword`. Time se zaobilazi ACL za preuzimanje lozinke po nalogu i napad opstaje tokom uobičajenih rotacija managed lozinki dok je kompromitovani root key i dalje u upotrebi. Kod gMSA, čitljivi `msDS-ManagedPasswordId` obično obezbeđuje tačan identifikator ključa. Kod ACL-om ograničenih dMSA, Golden dMSA smanjuje nedostajući identifikator na samo **1.024 kandidata**.<sup>[[1]](#references)[[2]](#references)</sup>

### Preduslovi

* Relevantni KDS root-key objekat, koji se obično dobija sa Enterprise Admin / forest-root Domain Admin pravima, kao `SYSTEM` na DC-u ili iz izložene DC baze podataka ili backup-a.<sup>[[1]](#references)[[2]](#references)</sup>
* SID ciljnog naloga, DNS domen, naziv šume i `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Za direktan gMSA proračun, njegov base64-encoded `msDS-ManagedPasswordId`; za Golden dMSA ovo se umesto toga može pogoditi.<sup>[[1]](#references)[[2]](#references)</sup>
* x64 Windows host sa .NET Framework 4.7.2 za [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Faza 1 - Ekstrakcija KDS root key-a

`GoldenDMSA` i [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) izvoze polja root-key objekta kao base64 blob. Bez argumenta domena, alati upituju forest root i zahtevaju odgovarajući privilegovani directory access. Sa argumentom domena/šume, `SYSTEM` na DC-u može upitati lokalnu repliku Configuration naming-context-a tog DC-a.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Zabeležite i GUID root-key ključa i base64 blob root-key ključa. Izvoz registra `SECURITY`/`SYSTEM` hive sam po sebi nije KDS root key: merodavni materijal nalazi se u AD Configuration particiji.<sup>[[1]](#references)[[2]](#references)</sup>

### Faza 2 - Enumeracija gMSA / dMSA objekata

Za gMSA objekte pribavite `sAMAccountName`, `objectSid` i binarni `msDS-ManagedPasswordId`. Ovo poslednje je obično čitljivo čak i kada caller nema dozvolu za preuzimanje atributa `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Podrazumevani ACL za dMSA može sprečiti LDAP enumeration sa niskim privilegijama. `GoldenDMSA info` može upitati LDAP ili enumerisati kandidate RID-ova i razrešiti SID-ove preko `LsaLookupSids` kroz `\PIPE\lsarpc`, a zatim razlikovati dMSA-ove od računa računara i gMSA-ova.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Faza 3 - Rekonstruiši ili pogodi `msDS-ManagedPasswordId`

Identifikator ključa uključuje `L0Index`, `L1Index` i `L2Index`, a ne vremensku oznaku kreiranja naloga praćenu nasumičnim bitovima. Semperis je otkrio da putanja generisanja lozinke ne koristi kandidat `L0Index`, dok su `L1Index` i `L2Index` ograničeni na vrednosti `0..31`. Shodno tome, napadač koji zna GUID root-key-a, domen, forest i SID može da konstruiše svih `32 * 32 = 1,024` kandidatskih identifikatora.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Izračunavanja se obavljaju offline, ali identifikovanje aktivnog kandidata obično zahteva pokušaje autentikacije. To može proizvesti nalet neuspelih Kerberos pre-authentication ili NTLM validation pokušaja pre nego što se pronađe validan ključ. Za AES Kerberos ključeve, salt managed naloga koji alat koristi jeste `UPPERCASE.DNS.DOMAIN` + `host` + account UPN pisan malim slovima, bez završnog `$` (na primer, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Faza 4 - Izračunavanje i korišćenje password-a

Ako je tačan identifier poznat, izračunajte 256-byte password buffer i konvertujte ga u NTLM/AES materijal. Base64 vrednost koju ovi alati prikazuju jeste enkodovani password buffer, **a ne sam LDAP `MSDS-MANAGEDPASSWORD_BLOB`**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM rezultat može da se koristi tamo gde je NTLM prihvaćen; AES ključ može da se koristi za overpass-the-hash / TGT zahteve tamo gde je managed nalog ograničen samo na AES. Ovo daje privilegije, SPN-ove, konfiguraciju delegiranja i pristup resursima kompromitovanog managed service naloga, bez dodavanja mašine napadača u `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Zloupotreba Configuration particije između domena

Objekti KDS root ključeva nalaze se u forest Configuration naming context-u, koji se replicira na DC-ove u child domenima. Shodno tome, `SYSTEM` na DC-u child domena može da pročita KDS materijal root-a šume iz lokalne replike child DC-a, iako child Domain Admins ne mogu direktno da pročitaju objekat sa DC-a root domena šume. Ako napadač može da pročita i `msDS-ManagedPasswordId` parent-domain gMSA naloga, GoldenGMSA može da izračuna lozinku tog parent naloga; SID filtering ne sprečava ovaj kriptografski napad.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Detekcija, ograničavanje i oporavak

* Konfigurišite SACL na kontejneru **Master Root Keys**, koji se nasleđuje na objekte `msKds-ProvRootKey`, za uspešna čitanja atributa `msKds-RootKeyData`. Kada je omogućeno Directory Service Access auditing, online extraction proizvodi Security događaj **4662**; istražite subjekte koji nisu očekivani DC-ovi ili Tier-0 operatori. Takođe auditujte izmene ovih SACL-ova i ACL-ova objekata root-key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Child-to-parent attack čita KDS objekat iz lokalne replike kompromitovanog child DC-a, tako da forest-root domain možda neće registrovati to čitanje. U parent domain-u auditujte uspešna čitanja atributa `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) na objektima `msDS-GroupManagedServiceAccount` i istražite čitanja od strane principal-a iz drugog domain-a.<sup>[[5]](#references)</sup>
* Korelišite pristup KDS objektima sa neuobičajenim logon-ima managed account-a i naletima Kerberos/NTLM grešaka za service account-e sa sufiksom `$`. Offline computation nakon prethodne krađe baze podataka ili backup-a nije vidljiv aktivnom DC-u.<sup>[[1]](#references)[[3]](#references)</sup>
* Uobičajena rotacija password-a nije dovoljna nakon izlaganja root-key-a. Microsoft-ova aktuelna procedura oporavka kreira novi KDS root key, restartuje KDS na svim relevantnim DC-ovima i premešta pogođene account-e na taj key. Ako su obim ili vreme izlaganja nepoznati, a čekanje na bezbednu rotaciju nije prihvatljivo, zamenite svaki gMSA koji je koristio kompromitovani key; ako je obim poznat, Microsoft dokumentuje authoritative-restore workflow za prinudnu bezbednu rotaciju. Potvrdite novi key GUID u `msDS-ManagedPasswordId` pre brisanja starog key-a.<sup>[[4]](#references)</sup>
* Tretirajte pristup DC bazi podataka i backup-u, replikaciju Configuration-partition-a i administraciju KDS root-key-a kao Tier-0. Smanjenje vrednosti `ManagedPasswordIntervalInDays` ograničava neke recovery prozore, ali ne opoziva već kompromitovani root key.<sup>[[4]](#references)</sup>

## Alati

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, generisanje identifikatora, validacija 1.024 kandidata, password computation i NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration i online, offline i cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) i [`Impacket`](https://github.com/fortra/impacket) - koristite ili validirajte izvedene NTLM/AES key-eve u ovlašćenom testiranju.



## References

- [1] [Golden dMSA - zaobilaženje autentikacije za delegirane Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory napadi](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repozitorijum](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Kako se oporaviti od Golden gMSA napada](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter kao bezbednosna granica između domain-a? Deo 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
