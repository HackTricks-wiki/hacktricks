# Pokretanje shell-a, aliasi i istorija

{{#include ../../banners/hacktricks-training.md}}

Shell komanda može da se ponaša drugačije od izvršne datoteke istog naziva ako alias, funkcija, startup datoteka ili promenljiva okruženja utiče na njen rad. Proverite ovo pre nego što se pouzdate u izlaz komande ili pretpostavite da skripta koristi isti PATH kao interaktivna sesija.

## Pregled trenutnog shell-a

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` otkrivaju da li se ime razrešava kao alias, funkcija, ugrađena komanda ili datoteka. `command -v` i `which` možda ne daju iste rezultate za aliase i funkcije. Istorija shell-a može otkriti komande ili pristupne podatke, ali može biti nepotpuna, onemogućena ili čuvana u memoriji dok se sesija ne završi.

## Pregled datoteka za pokretanje i istoriju

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Datoteka za pokretanje koju korisnik može da menja može da izvršava komande pri sledećem pokretanju shell-a. Sistemska datoteka za pokretanje ili datoteka za pokretanje privilegovanog korisnika osetljivija je ako nalog sa nižim privilegijama može da je menja. Neinteraktivni Bash može da čita i datoteku navedenu u `BASH_ENV`; stranica o [promenljivama okruženja](linux-environment-variables.md#bash_env--env) objašnjava to ponašanje i druge interpreter hook-ove. Pre nego što neki mehanizam za održavanje pristupa proglasite mogućim, proverite koje datoteke konkretna shell konfiguracija čita u login, interaktivnim i neinteraktivnim sesijama.

Proverite i datoteke koje učitava globalna datoteka za pokretanje. Na primer, doslovni `source /opt/app/venv/bin/activate` u `/etc/bash.bashrc` izvršava aktivacionu datoteku kao shell kod kada shell zaista čita tu datoteku za pokretanje. Pregledajte aktivacionu datoteku, dozvole simboličke veze i nadređenih direktorijuma, kao i ACL-ove; korisnik sa nižim privilegijama može da utiče na privilegovani shell samo ako taj shell ili privilegovani zadatak kasnije učita tu datoteku. Ako pristup za pisanje zavisi od `sudoedit`, najpre proverite tačno sudoers pravilo i instalirani vendor-patched sudo paket; samo broj verzije upstream-a ne potvrđuje [izloženost ubrizgavanju argumenata sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Proverite istoriju, dotfiles i rezervne kopije u potrazi za tajnama, kao što je opisano u odeljku [korisnici i sesije](../user-information/user-and-session-triage.md). Ako privilegovana skripta razrešava komande po imenu, kombinujte ovaj pregled sa [uputstvima za PATH hijacking](linux-environment-variables.md#path).

## Preusmeravanje pokretanja Zsh-a i kompajlirane datoteke

Uz podrazumevane postavke `RCS`, zsh čita `$ZDOTDIR/.zshenv` pre uobičajenih poziva, uključujući `zsh -c` i skripte; ako `ZDOTDIR` nije postavljen, koristi se `$HOME`. Ako alat za pokretanje komandi prihvata mapu okruženja, proverite да ли prosleđuje neku od ovih promenljivih privilegovanom zsh procesu. Tada `.zshenv` u direktorijumu u koji je preusmeren može da se izvrši **pre** tela komande koje alat proverava ili dozvoljava. Za to je potrebno da privilegovani proces nasledi preusmereni direktorijum; `zsh -f` preskače korisničke datoteke za pokretanje, ali ne i globalni `zshenv` (često `/etc/zshenv`, ali putanje zavise od distribucije). Stranica o zsh injection-u na [macOS-u](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) sadrži minimalni primer sa `ZDOTDIR`-om.<sup>[[1]](#references)[[2]](#references)</sup>

Novija, ispravna datoteka `.zshenv.zwc` ili `.zshrc.zwc` izvršava se umesto odgovarajuće tekstualne datoteke za pokretanje. Ako možete da pišete u direktorijum za pokretanje, kompajliranjem izmenjene datoteke, a zatim vraćanjem bezazleno izgledajuće tekstualne datoteke, izvršivi kod može ostati u kompajliranoj kopiji. Ovo je prikrivanje, a ne šifrovanje. Test u nastavku, koji se može bezbedno odbaciti, pokazuje zašto nije dovoljno pregledati samo tekstualnu datoteku; on ne utiče na stvarni kućni direktorijum.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Za stvarnu metu, utvrdite efektivne vrednosti `ZDOTDIR`/`HOME`, pregledajte i tekstualne i `.zwc` datoteke i proverite vremenske oznake, vlasništvo i da li su nadređeni direktorijumi upisivi. `.zwc` datoteka mora odgovarati izvornoj datoteci i biti novija da bi imala prednost.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh datoteke za pokretanje i gašenje](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Bezbednosno obaveštenje o ubacivanju u okruženje pri pokretanju ljuske](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Ugrađene komande Zsh ljuske: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [`.zshrc.zwc` koji ste zaboravili da proverite](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
