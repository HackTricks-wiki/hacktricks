# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Windows builds za hivi karibuni zilianzisha **SMB client support for alternative TCP ports**. Kipengele hicho kinaweza kutumiwa kubadilisha **local NTLM authentication** kuwa **SYSTEM local privilege escalation** wakati mshambuliaji anaweza:<sup>[[1]](#references)</sup>

1. Kufungua muunganisho wa SMB kwa listener anayedhibitiwa na mshambuliaji kwenye **non-445 port**
2. Kudumisha muunganisho huo wa TCP ukiwa hai
3. Kumlazimisha **privileged local client** kufikia **SMB share path** hiyo hiyo
4. Kurelaya **local NTLM authentication** inayotokana na hapo kurudi kwenye SMB service halisi ya mashine

Hii ndiyo primitive iliyo nyuma ya **CVE-2026-24294**, iliyopigwa patch mnamo **March 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Kwa nini inafanya kazi

Mbinu ya zamani ya CMTI / serialized-SPN reflection imeelezwa hapa:

{{#ref}}
../ntlm/README.md
{{#endref}}

Variant hii mpya **haihitaji marshalled hostname**. Badala yake, inatumia vibaya tabia mbili za SMB client:<sup>[[1]](#references)</sup>

- **Alternative port support** kwenye **Windows 11 24H2** na **Windows Server 2025**, inayopatikana kwa watumiaji kupitia `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, ambapo authenticated sessions nyingi zinaweza kutumia TCP connection hiyo hiyo

Hii inamaanisha kuwa user mwenye privileges ndogo anaweza kwanza kuunda TCP connection kutoka kwa SMB client kwenda kwenye attacker SMB server kwenye high port, kisha kumlazimisha service yenye privileges kufikia **exact same UNC path**. Ikiwa Windows itaamua kutumia tena TCP connection iliyopo, privileged NTLM exchange itatumwa kupitia transport inayodhibitiwa na mshambuliaji na inaweza kurelaya kwenye local SMB server.<sup>[[1]](#references)</sup>

## Masharti ya awali

- Target inasaidia SMB alternative ports:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** au toleo la baadaye
- Mshambuliaji anaweza kuendesha local au remote SMB server kwenye high port iliyochaguliwa
- Mshambuliaji anaweza kumlazimisha service yenye privileges kufikia UNC path
- Privileged authentication lazima iwe **NTLM local authentication**
- Target lazima iwe relayable:<sup>[[1]](#references)</sup>
- Synacktiv iliripoti kuwa ilifanya kazi kwa default kwenye **Windows Server 2025**
- Chain yao haikufanya kazi kwenye **Windows 11 24H2** kwa sababu outbound SMB signing inalazimishwa kwa default hapo

## Userland and internals

Kutoka kwenye command line, kipengele hiki kinaonekana kuwa rahisi:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Kiprogramu, client hutumia `WNetAddConnection4W` pamoja na data ya `lpUseOptions` ambayo haijawekewa nyaraka. Chaguo husika ni `TraP` (transport parameters), ambayo hatimaye hufika kwa SMB client ya kernel kupitia FSCTL na kuchanganuliwa na `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Mambo muhimu ya kuzingatia kiutendaji:<sup>[[1]](#references)</sup>

- **UNC syntax bado haina port field**
- **`net use` ni ya kila logon session**
- Bypass bado inafanya kazi kwa sababu **TCP connection na SMB session ni objects tofauti**
- Kutumia tena **same share path** ni lazima ikiwa exploit inategemea SMB client kutumia tena TCP connection iliyoundwa awali

## Mtiririko wa Exploitation

### 1. Unda SMB transport inayodhibitiwa na attacker

Endesha SMB server kwenye port ya juu na uifanye Windows iunganishe nayo:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Server inaweza kukubali jozi yoyote ya credentials unazodhibiti, kwa mfano `user:user`. Lengo la hatua hii bado si privilege escalation, bali kuifanya Windows SMB client ifungue na ihifadhi TCP connection inayoweza kutumiwa tena kuelekea kwa listener wako.<sup>[[1]](#references)</sup>

### 2. Lazimisha service yenye privileges kutumia UNC path hiyo hiyo

Tumia coercion primitive kama **PetitPotam** dhidi ya path hiyo hiyo ya `\\192.168.56.3\share`. Ikiwa client inayolazimishwa ina privileges na target name ni ya ndani (`localhost` au local IP/host), Windows hufanya **NTLM local authentication**.

Kwa sababu TCP connection inatumiwa tena, exchange hiyo ya privileged NTLM hupitia attacker SMB service badala ya kwenda moja kwa moja kwenye real local SMB server.<sup>[[1]](#references)</sup>

### 3. Relay privileged authentication kurudi kwenye local SMB

Attacker-controlled SMB service hutuma privileged NTLM exchange kwa `ntlmrelayx.py`, ambayo hui-relay kwenye SMB listener halisi ya mashine na kupata session kama `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Typical tooling kutoka kwenye public writeup:<sup>[[1]](#references)</sup>

- `smbserver.py` kwenye custom port ili kupokea privileged auth kupitia reused TCP connection
- `ntlmrelayx.py` ili ku-relay NTLM iliyonaswa kwenda kwenye local SMB
- `PetitPotam.exe` au coercion primitive nyingine ili kulazimisha privileged authentication

## Maelezo kwa operator

- Hii ni technique ya **local privilege escalation**, si generic remote relay trick<sup>[[1]](#references)</sup>
- Attacker-controlled SMB service lazima ishughulikie privileged authentication kwenye **TCP connection hiyo hiyo** iliyotumiwa awali kwa share mount<sup>[[1]](#references)</sup>
- Ikiwa coerced access itafikia **share path tofauti**, Windows inaweza kuanzisha connection tofauti na chain itakatika<sup>[[1]](#references)</sup>
- Mahitaji ya SMB signing yanaweza kuzuia relay hata wakati hatua ya arbitrary-port inafanya kazi<sup>[[1]](#references)</sup>
- Ikiwa una Kerberos material pekee au huwezi kulazimisha local NTLM, variant hii kamili haitoshi<sup>[[1]](#references)</sup>

## Detection na hardening

- Sakinisha patch ya **CVE-2026-24294** kutoka **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Fuatilia `net use` au `New-SmbMapping` zinazotumia **non-default SMB ports**<sup>[[1]](#references)</sup>
- Weka alert kwa outbound SMB isiyo ya kawaida kutoka workstations au servers kwenda kwenye **high TCP ports**<sup>[[1]](#references)</sup>
- Kagua coercion opportunities kama triggers za **EFSRPC / PetitPotam-style**<sup>[[1]](#references)</sup>
- Tekeleza SMB signing inapowezekana; Synacktiv inabainisha kwamba hii ilizuia relay yao kwenye Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
