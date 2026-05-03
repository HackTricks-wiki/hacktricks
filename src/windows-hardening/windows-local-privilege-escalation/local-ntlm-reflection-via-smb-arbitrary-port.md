# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Mabuild ya hivi karibuni ya Windows yalileta **usaidizi wa SMB client kwa alternative TCP ports**. Kipengele hicho kinaweza kutumiwa vibaya kugeuza **local NTLM authentication** kuwa **SYSTEM local privilege escalation** wakati attacker anaweza:

1. Kufungua muunganisho wa SMB kwenda kwa listener inayodhibitiwa na attacker kwenye **non-445 port**
2. Kuweka muunganisho huo wa TCP ukiendelea
3. Kulazimisha **privileged local client** kufikia **sawa hiyo SMB share path**
4. Kurudisha kwa relay **local NTLM authentication** inayotokana na hilo hadi kwenye huduma halisi ya SMB ya mashine

Hiki ndicho primitive nyuma ya **CVE-2026-24294**, iliyopata patch katika **March 2026**.

## Kwa nini inafanya kazi

Trick ya zamani ya CMTI / serialized-SPN reflection imeelezewa hapa:

{{#ref}}
../ntlm/README.md
{{#endref}}

Tofauti hii mpya haihitaji marshalled hostname. Badala yake, inatumia vibaya tabia mbili za SMB client:

- **Alternative port support** kwenye **Windows 11 24H2** na **Windows Server 2025**, inayopatikana kwa watumiaji kupitia `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, ambapo authenticated sessions nyingi zinaweza kutumia muunganisho ule ule wa TCP

Hiyo inamaanisha kuwa mtumiaji mwenye hakimiliki za chini anaweza kwanza kuunda muunganisho wa TCP kutoka SMB client kwenda kwa attacker SMB server kwenye high port, kisha kulazimisha huduma yenye hakimiliki kufikia **sawa hiyo UNC path**. Kama Windows itaamua kutumia tena muunganisho uliopo wa TCP, privileged NTLM exchange hutumwa kupitia transport inayodhibitiwa na attacker na inaweza kufanyiwa relay kwenda kwa local SMB server.

## Masharti ya awali

- Target inaunga mkono SMB alternative ports:
- **Windows 11 24H2** au baadaye
- **Windows Server 2025** au baadaye
- Attacker anaweza kuendesha local au remote SMB server kwenye high port aliyochagua
- Attacker anaweza kulazimisha huduma yenye hakimiliki kufikia UNC path
- Privileged authentication lazima iwe **NTLM local authentication**
- Target lazima iwe relayable:
- Synacktiv waliripoti kuwa ilifanya kazi kwa default kwenye **Windows Server 2025**
- Chain yao haikufanya kazi kwenye **Windows 11 24H2** kwa sababu outbound SMB signing inalazimishwa hapo kwa default

## Userland and internals

Kutoka kwenye command line, kipengele kinaonekana rahisi:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, mteja hutumia `WNetAddConnection4W` pamoja na data ya `lpUseOptions` ambayo haijadokumentiwi. Chaguo husika ni `TraP` (transport parameters), ambalo hatimaye hufika kwa kernel SMB client kupitia FSCTL na kuchakatwa na `mrxsmb`.

Maelezo muhimu ya vitendo:

- **UNC syntax bado haina field ya port**
- **`net use` ni per-logon-session**
- Bypass bado inafanya kazi kwa sababu **TCP connection na SMB session ni vitu tofauti**
- Kutumia tena **same share path** ni lazima ikiwa exploit inategemea SMB client kutumia tena TCP connection iliyoundwa awali

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Seva inaweza kupokea jozi yoyote ya credential unayodhibiti, kwa mfano `user:user`. Lengo la hatua hii bado si privilege escalation, bali ni kufanya Windows SMB client ifungue na iendelee kushikilia reusable TCP connection kwenda kwa listener wako.

### 2. Coerce huduma yenye privilege hadi kwenye UNC path ile ile

Tumia coercion primitive kama **PetitPotam** dhidi ya **path ile ile** `\\192.168.56.3\share`. Ikiwa client iliyolazimishwa ina privilege na jina la target ni local (`localhost` au local IP/host), Windows hufanya **NTLM local authentication**.

Kwa kuwa TCP connection inatumiwa tena, NTLM exchange hiyo yenye privilege husafiri kwenda kwa attacker SMB service badala ya kwenda moja kwa moja kwa real local SMB server.

### 3. Relay uthibitishaji wenye privilege kurudi kwenye local SMB

Attacker-controlled SMB service huforward NTLM exchange yenye privilege kwenda `ntlmrelayx.py`, ambayo hui-relay kwenda kwa real SMB listener ya machine na kupata session kama `NT AUTHORITY\SYSTEM`.

Tooling ya kawaida kutoka public writeup:

- `smbserver.py` kwenye port ya custom ili kupokea privileged auth kupitia reused TCP connection
- `ntlmrelayx.py` ili kufanya relay ya NTLM iliyokamatwa kwenda local SMB
- `PetitPotam.exe` au coercion primitive nyingine ili kulazimisha privileged authentication

## Maelezo kwa operator

- Hii ni **local privilege escalation** technique, si generic remote relay trick
- Attacker-controlled SMB service lazima ishughulikie privileged authentication kwenye **same TCP connection** iliyotumika awali kwa mount ya share
- Ikiwa access iliyolazimishwa itagusa **different share path**, Windows inaweza kuanzisha connection tofauti na chain kuvunjika
- SMB signing requirements zinaweza kuzuia relay hata wakati hatua ya arbitrary-port inafanya kazi
- Ikiwa una Kerberos material tu au huwezi kulazimisha local NTLM, variant hii mahsusi haitoshi

## Detection na hardening

- Patch **CVE-2026-24294** kutoka **March 2026 Patch Tuesday**
- Fuatilia `net use` au `New-SmbMapping` zinazotumia **non-default SMB ports**
- Tuma alert kwa outbound SMB isiyo ya kawaida kutoka workstations au servers kwenda **high TCP ports**
- Kagua coercion opportunities kama **EFSRPC / PetitPotam-style** triggers
- Tekeleza SMB signing pale inapowezekana; Synacktiv hasa inasema hili liliizuia relay yao kwenye Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
