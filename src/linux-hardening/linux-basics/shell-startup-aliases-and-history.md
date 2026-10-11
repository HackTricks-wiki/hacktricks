# Shell-opstart, aliasse en geskiedenis

{{#include ../../banners/hacktricks-training.md}}

’n Shell-opdrag kan anders optree as die uitvoerbare lêer met dieselfde naam indien ’n alias, funksie, opstartlêer of omgewingsveranderlike die manier waarop dit loop, verander. Gaan hierdie na voordat jy ’n opdrag se uitvoer vertrou of aanvaar dat ’n script dieselfde PATH as ’n interaktiewe sessie gebruik.

## Inspekteer die huidige shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` en `command -V` wys of ’n naam na ’n alias, funksie, ingeboude opdrag of lêer verwys. `command -v` en `which` gee dalk nie dieselfde resultaat vir aliases en funksies nie. Shell-geskiedenis kan opdragte of geloofsbriewe blootlê, maar dit kan onvolledig of afgeskakel wees, of in die geheue gehou word totdat die sessie eindig.

## Gaan opstart- en geskiedenislêers na

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

’n Opstartlêer wat deur ’n gebruiker geskryf kan word, kan opdragte uitvoer wanneer ’n shell later begin. ’n Stelselwye opstartlêer of ’n bevoorregte gebruiker se opstartlêer is sensitiewer as ’n rekening met laer voorregte dit kan wysig. Nie-interaktiewe Bash kan ook die lêer lees waarna `BASH_ENV` verwys; die bladsy oor [omgewingsveranderlikes](linux-environment-variables.md#bash_env--env) verduidelik dié gedrag en ander interpreter-hooks. Verifieer watter lêers die werklike shell vir aanmeld-, interaktiewe en nie-interaktiewe sessies lees voordat jy ’n persistence-pad aanvoer.

Ondersoek ook lêers wat deur ’n globale opstartlêer ingesluit word. Byvoorbeeld, ’n letterlike `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` voer die aktiveringslêer as shell-kode uit wanneer ’n shell daardie opstartlêer werklik lees. Gaan die aktiveringslêer, die toestemmings van die simboliese skakel en ouergidse, en die ACL’s na; ’n skrywer met laer voorregte kan ’n bevoorregte shell slegs beïnvloed as daardie shell of ’n bevoorregte taak die lêer later insluit. As skryftoegang van `sudoedit` afhang, verifieer eers die presiese sudoers-reël en die geïnstalleerde, deur die verskaffer gelapte sudo-pakket; ’n stroomop-weergawe-string alleen bewys nie blootstelling aan [sudoedit-argumentinspuiting](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) nie.

Gaan geskiedenis, dotfiles en rugsteune na vir geheime, soos beskryf in [gebruikers en sessies](../user-information/user-and-session-triage.md). As ’n bevoorregte skrip opdragte volgens naam vind, kombineer hierdie ondersoek met die [leiding oor PATH-kaping](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
