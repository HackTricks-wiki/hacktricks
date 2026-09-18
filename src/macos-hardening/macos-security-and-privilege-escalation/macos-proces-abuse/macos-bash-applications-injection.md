# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Kada se Bash pokrene neinteraktivno radi izvršavanja skripte ili `-c` komande, proširuje vrednost promenljive `BASH_ENV` i učitava dobijenu datoteku pre izvršavanja zahtevane komande. Bash ne koristi `PATH` za pronalaženje ove datoteke. Proces koji pokrene neinteraktivni Bash sa environment varijablama pod kontrolom napadača zato može da se natera da prvo izvrši čitljiv shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook se pokreće samo kada cilj zaista pokrene Bash; `/bin/sh` na drugoj platformi ili program koji izvršava komandu bez shell-a neće ga nužno poštovati. Bash u privilegovanom režimu ignoriše `BASH_ENV`. Kada se efektivni i stvarni ID-ovi korisnika/grupe razlikuju, Bash takođe preskače startup fajlove i resetuje efektivne ID-ove osim ako nije prosleđen `-p`; sa `-p`, privilegovani režim ostaje omogućen, a `BASH_ENV` se i dalje ignoriše.<sup>[[1]](#references)[[2]](#references)</sup>

Na macOS-u, `launchd` jobs mogu definisati nasleđene promenljive okruženja ili promenljive specifične za job, zato proverite plist fajlove i launch kontekste koji prosleđuju privilegovane skripte. Nemojte se oslanjati samo na SIP za sanitizaciju interpreter promenljivih: koristite minimalno okruženje (`env -i`), eksplicitno uklonite `BASH_ENV`, pozovite željeni interpreter apsolutnom putanjom i izbegavajte startup fajlove sa dozvolom upisa.

## zsh `ZDOTDIR`

zsh čita `$ZDOTDIR/.zshenv` za svaki uobičajeni shell, uključujući neinteraktivne shell-ove; ako `ZDOTDIR` nije postavljen, koristi `HOME`. Preusmeravanje `ZDOTDIR` na direktorijum sa dozvolom upisa zato izvršava njegov `.zshenv` pre `zsh -c` komande ili skripte.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` poništava opciju `RCS` i preskače ovu korisničku startup datoteku. Globalna `/etc/zshenv` se i dalje učitava, pa mora ostati pouzdana i minimalna.

## fish `XDG_CONFIG_HOME`

fish čita `$XDG_CONFIG_HOME/fish/conf.d/*.fish` i `$XDG_CONFIG_HOME/fish/config.fish` pri pokretanju svake shell instance, ne samo interaktivnih ili login shell-ova. Takođe izvršava `fish/vendor_conf.d/*.fish` ispod unosa u `XDG_DATA_DIRS`. Napadač koji kontroliše jednu od ovih promenljivih i čitljiv direktorijum stoga može izvršiti kod pre fish skripte ili `-c` komande.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Koristite `fish --no-config` za pouzdan poziv i obrišite nepouzdane XDG promenljive putanja.

## bash `PS4` + xtrace (`SHELLOPTS`)

Kada Bash radi sa opcijom **xtrace**, pre svake praćene komande proširuje `PS4` i ispisuje ga. `PS4` se proširuje kao svaki prompt, tako da se **command substitution** unutar njega izvršava. I vrednost promenljive `PS4` **i način na koji je xtrace omogućen** mogu u potpunosti poticati iz okruženja: izvozom `SHELLOPTS=xtrace` uključuje se xtrace za uobičajeni `bash script.sh` (nije potrebna oznaka `-x`). Time se svaka Bash skripta koju žrtva pokrene pretvara u izvršavanje koda.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` sam po sebi ne radi ništa dok se ne omogući xtrace (putem `SHELLOPTS=xtrace`, `set -x` ili `bash -x`). Bash ignoriše `SHELLOPTS` u **privileged mode** (različiti stvarni/efektivni ID-jevi bez rukovanja pomoću `-p`), pa važe iste setuid napomene kao i za `BASH_ENV`.

## POSIX `ENV`

POSIX-style shells (`/bin/sh`, `dash`, `ksh`) čitaju promenljivu `ENV`, proširuju je i učitavaju rezultujući fajl kada pokrenu **interactive** shell. To je POSIX pandan promenljivoj `BASH_ENV` (koja se aktivira za *non-interactive* Bash), pa kontrola nad `ENV` izvršava kod svaki put kada žrtva pokrene interaktivni `sh`/`dash`.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash datoteke za pokretanje](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh datoteke za pokretanje/isključivanje](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish konfiguracione datoteke](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash promenljive — `PS4` i ugrađena komanda Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
