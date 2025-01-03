# DPAPI - Kutolewa kwa Nywila

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni Nini

Data Protection API (DPAPI) inatumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa **symmetric encryption ya funguo za kibinafsi zisizo za kawaida**, ikitumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Njia hii inarahisisha usimbaji kwa waendelezaji kwa kuwapa uwezo wa kusimbisha data kwa kutumia funguo zilizotokana na siri za kuingia za mtumiaji au, kwa usimbaji wa mfumo, siri za uthibitishaji wa kikoa cha mfumo, hivyo kuondoa hitaji kwa waendelezaji kusimamia ulinzi wa funguo za usimbaji wenyewe.

### Data Iliyolindwa na DPAPI

Miongoni mwa data za kibinafsi zilizolindwa na DPAPI ni:

- Nywila za Internet Explorer na Google Chrome na data ya kukamilisha kiotomatiki
- Nywila za barua pepe na akaunti za FTP za ndani kwa programu kama Outlook na Windows Mail
- Nywila za folda zilizoshirikiwa, rasilimali, mitandao isiyo na waya, na Windows Vault, ikiwa ni pamoja na funguo za usimbaji
- Nywila za muunganisho wa desktop ya mbali, .NET Passport, na funguo za kibinafsi kwa madhumuni mbalimbali ya usimbaji na uthibitishaji
- Nywila za mtandao zinazodhibitiwa na Credential Manager na data za kibinafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger, na zaidi

## Orodha ya Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Faili za Akreditivu

Faili **za akreditivu zilizolindwa** zinaweza kupatikana katika:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Pata taarifa za akidi kwa kutumia mimikatz `dpapi::cred`, katika jibu unaweza kupata taarifa za kuvutia kama vile data iliyosimbwa na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa kufungua:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Funguo za DPAPI zinazotumika kwa ajili ya kuficha funguo za RSA za mtumiaji zimehifadhiwa chini ya `%APPDATA%\Microsoft\Protect\{SID}` directory, ambapo {SID} ni [**Kitambulisho cha Usalama**](https://en.wikipedia.org/wiki/Security_Identifier) **cha mtumiaji huyo**. **Funguo ya DPAPI imehifadhiwa katika faili ile ile kama funguo kuu inayolinda funguo za faragha za watumiaji**. Kwa kawaida ni bytes 64 za data za nasibu. (Kumbuka kwamba directory hii inalindwa hivyo huwezi kuorodhesha kwa kutumia `dir` kutoka cmd, lakini unaweza kuorodhesha kutoka PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hii ndiyo inavyoonekana kwa funguo kuu za mtumiaji:

![](<../../images/image (1121).png>)

Kawaida **kila funguo kuu ni funguo ya simetriki iliyosimbwa ambayo inaweza kufungua maudhui mengine**. Hivyo, **kutoa** **funguo kuu iliyosimbwa** ni ya kuvutia ili **kufungua** baadaye **maudhui mengine** yaliyosimbwa nayo.

### Toa funguo kuu & fungua

Angalia chapisho [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) kwa mfano wa jinsi ya kutoa funguo kuu na kuifungua.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) ni bandiko la C# la baadhi ya kazi za DPAPI kutoka kwa [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) mradi.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni chombo kinachotumia otomatiki kutoa watumiaji wote na kompyuta kutoka kwenye directory ya LDAP na kutoa funguo za nakala za kudhibiti eneo kupitia RPC. Skripti itatatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata DPAPI blobs za watumiaji wote na kufungua kila kitu kwa funguo za nakala za eneo.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta zilizotolewa kutoka LDAP unaweza kupata kila mtandao wa chini hata kama hukujua!

"Kwa sababu haki za Msimamizi wa Eneo hazitoshi. Wavunje wote."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kutoa siri zilizolindwa na DPAPI kiotomatiki.

## Marejeleo

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
