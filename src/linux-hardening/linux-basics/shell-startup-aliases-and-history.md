# Pokretanje shell-a, aliasi i istorija

{{#include ../../banners/hacktricks-training.md}}

Shell komanda može da se ponaša drugačije od izvršne datoteke istog imena ako alias, funkcija, startup datoteka ili promenljiva okruženja utiče na njeno izvršavanje. Proverite ih pre nego što se oslonite na izlaz komande ili pretpostavite da skripta koristi isti PATH kao interaktivna sesija.

## Provera trenutnog shell-a

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` and `command -V` otkrivaju da li se ime razrešava kao alias, funkcija, builtin ili datoteka. `command -v` i `which` možda ne daju isti rezultat za alias-e i funkcije. Istorija shell-a može otkriti komande ili akreditive, ali može biti nepotpuna, onemogućena ili zadržana u memoriji dok se sesija ne završi.

Izmenjeni `.bashrc` može definisati `sudo` alias koji oponaša upit za lozinku, beleži odgovor i prosleđuje ga pravoj komandi. To može prikriti presretanje akreditiva bez izmene izvršne datoteke `sudo` ili `PATH`.<sup>[[5]](#references)</sup> Shell mora da pročita izmenjenu startup datoteku i proširi alias.<sup>[[7]](#references)</sup> Bash po podrazumevanim podešavanjima ne proširuje alias-e u neinteraktivnom režimu, osim ako je omogućeno `expand_aliases`.<sup>[[6]](#references)</sup>

## Pregled startup datoteka i datoteka istorije

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Korisnički upisiva startup datoteka može da izvršava komande pri sledećem pokretanju shell-a. Sistemska startup datoteka ili startup datoteka privilegovanog korisnika osetljivija je ako nalog sa nižim privilegijama može da je menja. Neinteraktivni Bash može da čita i datoteku navedenu u `BASH_ENV`; stranica o [environment variables](linux-environment-variables.md#bash_env--env) objašnjava to ponašanje i druge interpreter hook-ove. Pre nego što tvrdite da postoji putanja za persistence, proverite koje datoteke konkretni shell čita za login, interaktivne i neinteraktivne sesije.

Pregledajte i datoteke koje učitava globalna startup datoteka. Na primer, doslovni `source /opt/app/venv/bin/activate` u datoteci `/etc/bash.bashrc` izvršava aktivacionu datoteku kao shell kod kada shell zaista pročita tu startup datoteku. Pregledajte aktivacionu datoteku, dozvole za symlink i nadređene direktorijume, kao i ACL-ove; korisnik sa nižim privilegijama može da utiče na privilegovani shell samo ako taj shell ili privilegovani zadatak kasnije učita tu datoteku. Ako pristup za pisanje zavisi od `sudoedit`, prvo proverite tačno sudoers pravilo i instalirani sudo paket sa zakrpama dobavljača; sam upstream broj verzije ne potvrđuje izloženost na [sudoedit argument-injection](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Proverite history, dotfiles i rezervne kopije da biste pronašli tajne, kao što je opisano u odeljku [users and sessions](../user-information/user-and-session-triage.md). Ako privilegovana skripta pronalazi komande po imenu, dopunite ovaj pregled smernicama za [PATH hijacking](linux-environment-variables.md#path).

## Preusmeravanje Zsh startup datoteka i kompajlirane datoteke

Uz podrazumevana podešavanja `RCS`, zsh čita `$ZDOTDIR/.zshenv` pre uobičajenih pokretanja, uključujući `zsh -c` i skripte; ako `ZDOTDIR` nije postavljen, koristi `$HOME`. Kada command runner prihvata mapu okruženja, proverite da li prosleđuje bilo koju od tih promenljivih privilegovanom zsh procesu. Tada upisiva `.zshenv` može da se izvrši **pre** tela komande koju runner proverava ili stavlja na allowlistu. To zahteva da privilegovani proces nasledi preusmereni direktorijum; `zsh -f` preskače korisničke startup datoteke, ali ne i globalni `zshenv` (često `/etc/zshenv`, ali putanje zavise od distribucije). Stranica o [zsh injection na macOS-u](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) sadrži jednostavan primer upotrebe `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Novija, ispravna datoteka `.zshenv.zwc` ili `.zshrc.zwc` izvršava se umesto odgovarajuće plaintext startup datoteke. Ako možete da pišete u startup direktorijum, kompajliranje izmenjene datoteke, a zatim vraćanje bezazlene plaintext verzije, može da ostavi izvršiv kod u kompajliranoj kopiji. Ovo je prikrivanje, a ne šifrovanje. Test ispod koristi privremene datoteke i pokazuje zašto nije dovoljno pregledati samo tekstualnu datoteku; ne dira stvarni home direktorijum.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Za stvarnu metu, utvrdite efektivne vrednosti `ZDOTDIR`/`HOME`, pregledajte i tekstualne i `.zwc` datoteke i proverite vremenske oznake, vlasništvo i direktorijume iznad njih u kojima može da se vrši upis. Datoteka `.zwc` mora da odgovara izvornoj datoteci i da bude novija da bi imala prednost.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh datoteke za pokretanje i gašenje](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Bezbednosno upozorenje o ubacivanju u okruženje pri pokretanju shell-a](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Ugrađene komande Zsh-a: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [.zshrc.zwc koju ste zaboravili da proverite](https://dfir.ch/posts/compiled_zsh/)
- [5] [Kampanja špijunaže uz pomoć AI-ja cilja vladinu Linux infrastrukturu](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash priručnik: Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash priručnik: Datoteke za pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
