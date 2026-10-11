# Uanzishaji wa Shell, Aliases, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na executable yenye jina hilo hilo ikiwa alias, function, faili ya uanzishaji, au environment variable itabadilisha jinsi inavyoendeshwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script hutumia PATH sawa na session shirikishi.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` na `command -V` huonyesha kama jina linarejelea alias, function, builtin au file. `command -v` na `which` huenda visitoe taarifa sawa kuhusu aliases na functions. Historia ya shell inaweza kufichua commands au credentials, lakini huenda isiwe kamili, imezimwa, au ihifadhiwe kwenye memory hadi session imalizike.

## Kagua faili za startup na historia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya kuanzisha inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya kuanzisha ya mfumo mzima au faili ya kuanzisha ya mtumiaji mwenye mapendeleo ya juu ni nyeti zaidi ikiwa akaunti yenye mapendeleo ya chini inaweza kuibadilisha. Bash isiyo ya mwingiliano pia inaweza kusoma faili iliyoainishwa na `BASH_ENV`; ukurasa wa [environment variables](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na njia nyingine za kuingilia interpreter. Hakikisha ni faili zipi ambazo shell husoma katika vipindi vya kuingia, vya mwingiliano na visivyo vya mwingiliano kabla ya kudai kuwa njia fulani inaweza kutumika kudumisha ufikiaji.

Pia kagua faili zinazopakiwa na faili ya kuanzisha ya jumla. Kwa mfano, `source /opt/app/venv/bin/activate` iliyoandikwa moja kwa moja kwenye `/etc/bash.bashrc` hutekeleza faili ya activation kama msimbo wa shell pale tu shell inaposoma faili hiyo ya kuanzisha. Kagua faili ya activation, ruhusa za symlink na saraka zake kuu, pamoja na ACLs; mtumiaji mwenye mapendeleo ya chini anaweza kuathiri shell yenye mapendeleo ya juu tu ikiwa shell hiyo au kazi yenye mapendeleo ya juu itaipakia baadaye. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, hakikisha kwanza sheria halisi ya sudoers na kifurushi cha sudo kilichowekwa ambacho muuzaji amekibadilisha; nambari ya toleo la upstream pekee haithibitishi [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua history, dotfiles na nakala rudufu ili kutafuta siri kama ilivyoelezwa kwenye [users and sessions](../user-information/user-and-session-triage.md). Ikiwa script yenye mapendeleo ya juu hutafuta amri kwa kutumia jina lake, unganisha ukaguzi huu na [mwongozo wa PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
