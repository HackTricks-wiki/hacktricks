# Uanzishaji wa Shell, Alias, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na executable yenye jina lilelile ikiwa alias, function, faili ya uanzishaji, au environment variable itabadilisha jinsi inavyoendeshwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script inatumia PATH sawa na kipindi shirikishi.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` and `command -V` huonyesha kama jina linarejelea alias, function, builtin, au file. `command -v` na `which` huenda zisionyeshe jambo lilelile kwa aliases na functions. Historia ya shell inaweza kufichua commands au credentials, lakini huenda isiwe kamili, imezimwa, au ikabaki kwenye memory hadi session iishe.

## Kagua faili za uanzishaji na historia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya startup inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya startup ya mfumo mzima au ya mtumiaji mwenye ruhusa za juu ni nyeti zaidi ikiwa akaunti yenye ruhusa za chini inaweza kuibadilisha. Bash isiyo ya interactive pia inaweza kusoma faili iliyotajwa na `BASH_ENV`; ukurasa wa [vigeu vya mazingira](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na hooks nyingine za interpreter. Thibitisha faili ambazo shell halisi husoma katika vipindi vya login, interactive na non-interactive kabla ya kudai kuwa kuna njia ya persistence.

Kagua pia faili zinazojumuishwa na faili ya startup ya jumla. Kwa mfano, amri halisi `source /opt/app/venv/bin/activate` katika `/etc/bash.bashrc` huendesha faili ya activation kama shell code pale tu shell inaposoma faili hiyo ya startup. Kagua faili ya activation, ruhusa za symlink na saraka zake za mzazi, pamoja na ACL; mtumiaji mwenye ruhusa za chini anaweza kuathiri shell yenye ruhusa za juu tu ikiwa shell hiyo au task yenye ruhusa za juu itajumuisha faili hiyo baadaye. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, thibitisha kwanza sheria halisi ya sudoers na kifurushi cha sudo kilichosakinishwa chenye marekebisho ya vendor; mfuatano wa toleo la upstream pekee hauthibitishi [uwezekano wa kuathiriwa na uingizaji wa hoja za sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua historia, dotfiles na nakala za hifadhi ili kutafuta siri, kama ilivyoelezwa katika [watumiaji na vipindi](../user-information/user-and-session-triage.md). Ikiwa script yenye ruhusa za juu hutatua amri kwa majina yake, changanya ukaguzi huu na [mwongozo wa PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
