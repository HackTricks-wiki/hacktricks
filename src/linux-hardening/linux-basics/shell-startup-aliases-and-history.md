# Kuanzisha Shell, Aliases, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na executable yenye jina hilo hilo ikiwa alias, function, startup file, au environment variable itabadilisha jinsi inavyoendeshwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script hutumia PATH sawa na session ya maingiliano.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` na `command -V` huonyesha kama jina linatatuliwa kuwa alias, function, builtin, au faili. `command -v` na `which` huenda zisionyeshe matokeo sawa kwa alias na function. Historia ya shell inaweza kufichua amri au credentials, lakini inaweza kuwa haijakamilika, imezimwa, au kuhifadhiwa kwenye kumbukumbu hadi kipindi kitakapofungwa.

## Kagua faili za uanzishaji na historia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya uanzishaji inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya uanzishaji ya mfumo mzima au faili ya uanzishaji ya mtumiaji mwenye ruhusa za juu ni nyeti zaidi ikiwa akaunti yenye ruhusa za chini inaweza kuirekebisha. Bash isiyoingiliana pia inaweza kusoma faili iliyotajwa na `BASH_ENV`; ukurasa wa [vigeu vya mazingira](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na hooks nyingine za interpreter. Thibitisha ni faili zipi shell halisi husoma kwa vipindi vya login, vinavyoingiliana na visivyoingiliana kabla ya kudai kuwa njia fulani inaweza kutumika kwa persistence.

Pia kagua faili zinazoingizwa na faili ya uanzishaji ya kimataifa. Kwa mfano, `source /opt/app/venv/bin/activate` iliyoandikwa moja kwa moja katika `/etc/bash.bashrc` huendesha faili ya uanzishaji kama msimbo wa shell wakati shell inaposoma faili hiyo ya uanzishaji. Kagua faili ya uanzishaji, ruhusa za symlink na saraka zake kuu, pamoja na ACLs; mtumiaji mwenye ruhusa za chini anaweza kuathiri shell yenye ruhusa za juu tu ikiwa shell hiyo au kazi yenye ruhusa za juu itaiingiza baadaye. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, thibitisha kwanza kanuni halisi ya sudoers na kifurushi cha sudo kilichosakinishwa chenye viraka vya vendor; nambari ya toleo la upstream pekee haithibitishi [uwezekano wa kuathiriwa na uingizaji wa hoja za sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua history, dotfiles na nakala rudufu ili kutafuta siri kama ilivyoelezwa katika [watumiaji na vipindi](../user-information/user-and-session-triage.md). Ikiwa script yenye ruhusa za juu hutatua amri kwa kutumia majina, unganisha ukaguzi huu na [mwongozo wa utekaji wa PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
