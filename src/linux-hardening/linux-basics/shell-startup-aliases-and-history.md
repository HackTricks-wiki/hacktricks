# Kuanzisha Shell, Aliases, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na executable yenye jina hilo hilo ikiwa alias, function, faili ya kuanzisha, au variable ya mazingira itabadilisha jinsi inavyotekelezwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script inatumia PATH sawa na session shirikishi.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` na `command -V` huonyesha kama jina linatatuliwa kuwa alias, function, builtin, au faili. `command -v` na `which` huenda zisionyeshe matokeo sawa kwa aliases na functions. Historia ya shell inaweza kufichua amri au vitambulisho, lakini huenda isiwe kamili, iwe imezimwa, au ihifadhiwe kwenye kumbukumbu hadi kipindi kiishe.

## Kagua faili za uanzishaji na historia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya uanzishaji inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya uanzishaji ya mfumo mzima au faili ya uanzishaji ya mtumiaji mwenye marupurupu ni nyeti zaidi ikiwa akaunti yenye marupurupu ya chini inaweza kuibadilisha. Bash isiyoingiliana pia inaweza kusoma faili iliyotajwa na `BASH_ENV`; ukurasa wa [environment variables](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na hooks nyingine za interpreter. Thibitisha faili ambazo shell halisi husoma katika vipindi vya login, interactive, na non-interactive kabla ya kudai kuwa kuna njia ya persistence.

Pia kagua faili zinazopakiwa na faili ya uanzishaji ya kimataifa. Kwa mfano, `source /opt/app/venv/bin/activate` iliyoandikwa moja kwa moja ndani ya `/etc/bash.bashrc` huendesha faili ya activation kama shell code shell inaposoma faili hiyo ya uanzishaji. Kagua faili ya activation, ruhusa za symlink na saraka zake kuu, pamoja na ACLs; mwandishi mwenye marupurupu ya chini anaweza kuathiri shell yenye marupurupu ya juu tu ikiwa shell hiyo au kazi yenye marupurupu ya juu itaipakia baadaye. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, kwanza thibitisha kanuni halisi ya sudoers na kifurushi cha sudo kilichosakinishwa ambacho vendor amekifanyia marekebisho; nambari ya toleo la upstream pekee haithibitishi [uwezekano wa sudoedit argument-injection](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua history, dotfiles, na backups ili kutafuta siri kama ilivyoelezwa katika [users and sessions](../user-information/user-and-session-triage.md). Ikiwa script yenye marupurupu ya juu hutafuta amri kwa majina, unganisha ukaguzi huu na [mwongozo wa PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
