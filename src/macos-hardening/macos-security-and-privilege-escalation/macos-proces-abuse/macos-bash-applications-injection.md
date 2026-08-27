# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Kada se Bash pokrene u neinteraktivnom režimu radi izvršavanja skripte ili komande `-c`, proširuje vrednost promenljive `BASH_ENV` i učitava rezultujuću datoteku pre izvršavanja zahtevane komande. Bash ne koristi `PATH` za pronalaženje ove datoteke. Proces koji pokreće neinteraktivni Bash sa attacker-controlled environment variables zato može biti nateran da najpre izvrši čitljiv shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook se izvršava samo kada cilj zaista pokrene Bash; `/bin/sh` na drugoj platformi ili program koji izvršava komandu bez shell-a neće ga nužno poštovati. Bash u privileged mode-u ignoriše `BASH_ENV`. Kada se efektivni i stvarni ID-ovi korisnika/grupe razlikuju, Bash takođe preskače startup fajlove i resetuje efektivne ID-ove osim ako nije prosleđen `-p`; sa `-p`, privileged mode ostaje omogućen, a `BASH_ENV` se i dalje ignoriše.<sup>[[1]](#references)[[2]](#references)</sup>

Na macOS-u, `launchd` poslovi mogu definisati nasleđene ili environment promenljive po poslu, zato proverite plist fajlove i launch kontekste koji prosleđuju privileged skripte. Nemojte se oslanjati samo na SIP za sanitizaciju promenljivih interpretera: koristite minimalno okruženje (`env -i`), eksplicitno uklonite `BASH_ENV`, pozovite željeni interpreter pomoću apsolutne putanje i izbegavajte startup fajlove u koje je moguće upisivati.

## zsh `ZDOTDIR`

zsh čita `$ZDOTDIR/.zshenv` za svaki normalni shell, uključujući neinteraktivne shell-ove; ako `ZDOTDIR` nije postavljen, koristi `HOME`. Preusmeravanje `ZDOTDIR` na direktorijum u koji je moguće upisivati zato izvršava njegov `.zshenv` pre `zsh -c` komande ili skripte.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` poništava opciju `RCS` i preskače ovu korisničku startup datoteku. Globalna `/etc/zshenv` se i dalje učitava, pa mora ostati pouzdana i minimalna.

## fish `XDG_CONFIG_HOME`

fish čita `$XDG_CONFIG_HOME/fish/conf.d/*.fish` i `$XDG_CONFIG_HOME/fish/config.fish` pri pokretanju svakog shell-a, ne samo interactive ili login shell-ova. Takođe izvršava `fish/vendor_conf.d/*.fish` ispod stavki u `XDG_DATA_DIRS`. Napadač koji kontroliše jednu od ovih promenljivih i čitljiv direktorijum stoga može izvršiti code pre fish script-a ili `-c` komande.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Koristite `fish --no-config` za pouzdano pokretanje i očistite nepouzdane XDG putanje u promenljivama.

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
