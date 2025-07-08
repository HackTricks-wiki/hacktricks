# Zloupotreba Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Delegirani upravljani servisni nalozi (**dMSAs**) su potpuno novi tip AD principa uveden sa **Windows Server 2025**. Dizajnirani su da zamene nasleđene servisne naloge omogućavajući "migraciju" jednim klikom koja automatski kopira Service Principal Names (SPNs), članstva u grupama, postavke delegacije, pa čak i kriptografske ključeve starog naloga u novi dMSA, omogućavajući aplikacijama neometan prelaz i eliminišući rizik od Kerberoasting-a.

Istraživači Akamai-a su otkrili da jedan atribut — **`msDS‑ManagedAccountPrecededByLink`** — govori KDC-u koji nasleđeni nalog dMSA "nasleđuje". Ako napadač može da upiše taj atribut (i prebaciti **`msDS‑DelegatedMSAState` → 2**), KDC će rado izgraditi PAC koji **nasleđuje svaki SID od odabranog žrtvenog naloga**, efikasno omogućavajući dMSA da se pretvara u bilo kog korisnika, uključujući Domain Admins.

## Šta je tačno dMSA?

* Izgrađen na osnovu **gMSA** tehnologije, ali smešten kao nova AD klasa **`msDS‑DelegatedManagedServiceAccount`**.
* Podržava **migraciju na zahtev**: pozivanje `Start‑ADServiceAccountMigration` povezuje dMSA sa nasleđenim nalogom, dodeljuje nasleđenom nalogu pravo pisanja na `msDS‑GroupMSAMembership`, i prebacuje `msDS‑DelegatedMSAState` = 1.
* Nakon `Complete‑ADServiceAccountMigration`, zamenjeni nalog se onemogućava i dMSA postaje potpuno funkcionalan; svaki host koji je prethodno koristio nasleđeni nalog automatski je ovlašćen da povuče lozinku dMSA.
* Tokom autentifikacije, KDC ugrađuje **KERB‑SUPERSEDED‑BY‑USER** naznaku tako da Windows 11/24H2 klijenti transparentno ponovo pokušavaju sa dMSA.

## Zahtevi za napad
1. **Najmanje jedan Windows Server 2025 DC** kako bi dMSA LDAP klasa i KDC logika postojale.
2. **Bilo koja prava za kreiranje objekata ili pisanje atributa na OU** (bilo koji OU) – npr. `Create msDS‑DelegatedManagedServiceAccount` ili jednostavno **Create All Child Objects**. Akamai je otkrio da 91% stvarnih korisnika dodeljuje takva "benigna" OU prava ne-administratorima.
3. Sposobnost pokretanja alata (PowerShell/Rubeus) sa bilo kog hosta povezanog sa domenom za zahtev Kerberos karata.
*Nema kontrole nad korisnikom žrtvom; napad nikada ne dodiruje ciljni nalog direktno.*

## Korak po korak: BadSuccessor*eskalacija privilegija

1. **Pronađite ili kreirajte dMSA koji kontrolišete**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Pošto ste kreirali objekat unutar OU na koji možete pisati, automatski posedujete sve njegove atribute.

2. **Simulirajte "završenu migraciju" u dva LDAP pisanja**:
- Postavite `msDS‑ManagedAccountPrecededByLink = DN` bilo koje žrtve (npr. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Postavite `msDS‑DelegatedMSAState = 2` (migracija završena).

Alati kao što su **Set‑ADComputer, ldapmodify**, ili čak **ADSI Edit** rade; nisu potrebna prava domen administratora.

3. **Zahtevajte TGT za dMSA** — Rubeus podržava `/dmsa` zastavicu:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Vraćeni PAC sada sadrži SID 500 (Administrator) plus grupe Domain Admins/Enterprise Admins.

## Prikupite lozinke svih korisnika

Tokom legitimnih migracija, KDC mora dozvoliti novom dMSA da dekriptuje **karte izdate starom nalogu pre prelaza**. Da bi izbegao prekid aktivnih sesija, stavlja i trenutne ključeve i prethodne ključeve unutar novog ASN.1 blob-a nazvanog **`KERB‑DMSA‑KEY‑PACKAGE`**.

Pošto naša lažna migracija tvrdi da dMSA nasleđuje žrtvu, KDC savesno kopira RC4‑HMAC ključ žrtve u **prethodne ključeve** – čak i ako dMSA nikada nije imao "prethodnu" lozinku. Taj RC4 ključ nije zasoljen, tako da je efikasno NT hash žrtve, dajući napadaču **offline cracking ili "pass-the-hash"** sposobnost.

Stoga, masovno povezivanje hiljada korisnika omogućava napadaču da izdumpuje hash-ove "na velikoj skali", pretvarajući **BadSuccessor u primitiv za eskalaciju privilegija i kompromitaciju kredencijala**.

## Alati

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Reference

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
