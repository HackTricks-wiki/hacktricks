# Pokretanje shell-a, aliasi i istorija

{{#include ../../banners/hacktricks-training.md}}

Shell komanda može da se ponaša drugačije od izvršne datoteke istog imena ako alias, funkcija, startup datoteka ili promenljiva okruženja utiče na njeno pokretanje. Proverite ih pre nego što se oslonite na izlaz komande ili pretpostavite da skripta koristi isti PATH kao interaktivna sesija.

## Pregled trenutnog shell-a

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` otkrivaju da li se ime razrešava kao alias, funkcija, ugrađena komanda ili datoteka. `command -v` i `which` možda neće dati iste rezultate za aliase i funkcije. Istorija shell-a može otkriti komande ili akreditive, ali može biti nepotpuna, onemogućena ili sačuvana u memoriji dok se sesija ne završi.

## Pregledajte datoteke za pokretanje i istoriju

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Datoteka za pokretanje koju korisnik može da menja može da izvrši komande pri budućem pokretanju shell-a. Sistemska datoteka za pokretanje ili datoteka za pokretanje privilegovanog korisnika osetljivija je ako nalog sa nižim privilegijama može da je menja. Neinteraktivni Bash takođe može da pročita datoteku navedenu u `BASH_ENV`; stranica o [promenljivama okruženja](linux-environment-variables.md#bash_env--env) objašnjava to ponašanje i druge interpreter hook-ove. Pre nego što tvrdite da postoji putanja za uspostavljanje postojanosti, proverite koje datoteke stvarna shell instanca čita za sesije prijavljivanja, interaktivne i neinteraktivne sesije.

Takođe pregledajte datoteke koje učitava globalna datoteka za pokretanje. Na primer, doslovni `source /opt/app/venv/bin/activate` u `/etc/bash.bashrc` izvršava aktivacionu datoteku kao shell kod kada shell zaista pročita tu datoteku za pokretanje. Pregledajte aktivacionu datoteku, dozvole simboličke veze i nadređenih direktorijuma, kao i ACL-ove; korisnik sa nižim privilegijama može da utiče na privilegovani shell samo ako taj shell ili privilegovani zadatak kasnije učita tu datoteku. Ako pristup za upis zavisi od `sudoedit`, prvo proverite tačno sudoers pravilo i instalirani sudo paket sa zakrpama dobavljača; sama oznaka upstream verzije ne potvrđuje [izloženost sudoedit ubrizgavanju argumenata](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Proverite istoriju komandi, dotfiles i rezervne kopije u potrazi za tajnama, kao što je opisano u odeljku [korisnici i sesije](../user-information/user-and-session-triage.md). Ako privilegovana skripta razrešava komande po imenu, dopunite ovaj pregled smernicama za [otimanje PATH-a](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
