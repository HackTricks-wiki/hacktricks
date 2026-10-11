# Pokretanje shell-a, aliasi i istorija

{{#include ../../banners/hacktricks-training.md}}

Shell komanda može da se ponaša drugačije od izvršne datoteke istog imena ako alias, funkcija, startup datoteka ili promenljiva okruženja utiče na njeno pokretanje. Proverite ovo pre nego što prihvatite izlaz komande kao pouzdan ili pretpostavite da skripta koristi isti PATH kao interaktivna sesija.

## Pregled trenutnog shell-a

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` otkrivaju da li se ime razrešava kao alias, funkcija, ugrađena komanda ili datoteka. `command -v` i `which` možda neće dati isti rezultat za aliase i funkcije. Istorija shell-a može otkriti komande ili akreditive, ali može biti nepotpuna, onemogućena ili sačuvana u memoriji dok se sesija ne završi.

## Pregled datoteka za pokretanje i istoriju

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Datoteka za pokretanje koju korisnik može da menja može da izvrši komande pri budućem pokretanju shell-a. Sistemska datoteka za pokretanje ili datoteka za pokretanje privilegovanog korisnika osetljivija je ako nalog sa nižim privilegijama može da je menja. Neinteraktivni Bash može da čita i datoteku navedenu u `BASH_ENV`; stranica o [promenljivama okruženja](linux-environment-variables.md#bash_env--env) objašnjava ovo ponašanje i druge interpreter hooks. Pre nego što navedete putanju za perzistenciju, proverite koje datoteke konkretni shell zaista čita u sesijama za prijavu, interaktivnim i neinteraktivnim sesijama.

Pregledajte i datoteke koje učitava globalna datoteka za pokretanje. Na primer, doslovna naredba `source /opt/app/venv/bin/activate` u `/etc/bash.bashrc` izvršava aktivacionu datoteku kao shell kod kada shell zaista čita tu datoteku za pokretanje. Pregledajte aktivacionu datoteku, dozvole za simboličku vezu i nadređene direktorijume, kao i ACL-ove; korisnik sa nižim privilegijama može da utiče na privilegovani shell samo ako taj shell ili privilegovani zadatak kasnije učita tu datoteku. Ako pristup za pisanje zavisi od `sudoedit`, prvo proverite tačno sudoers pravilo i instalirani sudo paket sa zakrpama dobavljača; sama uzvodna oznaka verzije ne dokazuje [izloženost sudoedit argument-injection napadu](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Proverite istoriju, dotfiles i rezervne kopije da biste pronašli tajne, kao što je opisano u [korisnicima i sesijama](../user-information/user-and-session-triage.md). Ako privilegovana skripta pronalazi komande po imenu, kombinujte ovaj pregled sa [uputstvima za PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
