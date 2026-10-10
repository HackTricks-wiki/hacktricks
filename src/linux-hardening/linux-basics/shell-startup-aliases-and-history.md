# Pokretanje shell-a, alias-i i istorija

{{#include ../../banners/hacktricks-training.md}}

Shell komanda može da se ponaša drugačije od izvršne datoteke istog imena ako alias, funkcija, startup datoteka ili promenljiva okruženja utiče na njeno izvršavanje. Proverite ih pre nego što poverujete izlazu komande ili pretpostavite da skripta koristi isti PATH kao interaktivna sesija.

## Pregled trenutnog shell-a

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` otkrivaju da li se ime razrešava kao alias, funkcija, builtin ili datoteka. `command -v` i `which` možda neće prikazati iste informacije za aliase i funkcije. Istorija shell-a može otkriti komande ili akreditive, ali može biti nepotpuna, onemogućena ili čuvana u memoriji do završetka sesije.

## Pregledaj datoteke za pokretanje i istoriju

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Datoteka za pokretanje u koju korisnik može da upisuje može da izvrši komande pri budućem pokretanju shell-a. Sistemska datoteka za pokretanje ili datoteka za pokretanje privilegovanog korisnika osetljivija je ako nalog sa nižim privilegijama može da je izmeni. Neinteraktivni Bash može da čita i datoteku navedenu u `BASH_ENV`; stranica o [environment variables](linux-environment-variables.md#bash_env--env) objašnjava to ponašanje i druge interpreter hook-ove. Pre nego što tvrdite da postoji putanja za persistence, proverite koje datoteke konkretni shell zaista čita za login, interaktivne i neinteraktivne sesije.

Proverite i datoteke koje učitava globalna datoteka za pokretanje. Na primer, doslovni `source /opt/app/venv/bin/activate` u `/etc/bash.bashrc` izvršava activation datoteku kao shell kod kada shell zaista pročita tu datoteku za pokretanje. Proverite activation datoteku, dozvole za symlink i nadređene direktorijume, kao i ACL-ove; korisnik sa nižim privilegijama može da utiče na privilegovani shell samo ako taj shell ili privilegovani zadatak kasnije učita tu datoteku. Ako pristup za upis zavisi od `sudoedit`, prvo proverite tačno sudoers pravilo i instalirani sudo paket sa zakrpama dobavljača; samo uzvodni broj verzije ne potvrđuje izloženost [sudoedit argument-injection](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Proverite history, dotfiles i rezervne kopije da biste pronašli tajne, kao što je opisano u odeljku [users and sessions](../user-information/user-and-session-triage.md). Ako privilegovana skripta razrešava komande po imenu, povežite ovaj pregled sa [smernicama za PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
