# Kuanzisha Shell, Aliases, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na executable yenye jina hilo hilo ikiwa alias, function, startup file, au environment variable itabadilisha jinsi inavyoendeshwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script inatumia PATH sawa na kipindi cha interactive.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` na `command -V` huonyesha kama jina linatatuliwa kuwa alias, function, builtin au faili. `command -v` na `which` huenda zisionyeshe matokeo sawa kwa alias na function. Historia ya shell inaweza kufichua amri au vitambulisho vya kuingia, lakini huenda isiwe kamili, imezimwa, au ibaki kwenye kumbukumbu hadi kipindi kifungwe.

## Kagua faili za uanzishaji na historia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya uanzishaji inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya uanzishaji ya mfumo mzima au ya mtumiaji mwenye ruhusa za juu ni nyeti zaidi ikiwa akaunti yenye ruhusa za chini inaweza kuibadilisha. Bash isiyoingiliana pia inaweza kusoma faili iliyotajwa na `BASH_ENV`; ukurasa wa [environment variables](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na hooks nyingine za interpreter. Thibitisha faili ambazo shell halisi husoma kwa vipindi vya kuingia, vinavyoingiliana na visivyoingiliana kabla ya kudai kuwa kuna njia ya persistence.

Pia kagua faili zinazopakiwa kwa `source` na faili ya uanzishaji ya mfumo mzima. Kwa mfano, `source /opt/app/venv/bin/activate` iliyoandikwa moja kwa moja ndani ya `/etc/bash.bashrc` huendesha faili ya activation kama shell code pale shell inapoisoma faili hiyo ya uanzishaji. Kagua faili ya activation, ruhusa za symlink na saraka zake za juu, pamoja na ACLs; mtumiaji mwenye ruhusa za chini anaweza kuathiri shell yenye ruhusa za juu tu ikiwa shell hiyo au kazi yenye ruhusa za juu itapakia faili hiyo baadaye kwa `source`. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, thibitisha kwanza kanuni halisi ya sudoers na kifurushi cha sudo kilichosakinishwa chenye marekebisho ya vendor; nambari ya toleo la upstream peke yake haithibitishi [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua history, dotfiles na backups ili kutafuta secrets kama ilivyoelezwa katika [users and sessions](../user-information/user-and-session-triage.md). Ikiwa script yenye ruhusa za juu inatafuta amri kwa jina, unganisha ukaguzi huu na [mwongozo wa PATH hijacking](linux-environment-variables.md#path).

## Uelekezaji upya wa uanzishaji wa Zsh na faili zilizokompiliwa

Kwa mipangilio yake ya chaguomsingi ya `RCS`, zsh husoma `$ZDOTDIR/.zshenv` kabla ya uendeshaji wa kawaida, ikijumuisha `zsh -c` na scripts; ikiwa `ZDOTDIR` haijawekwa, hutumia `$HOME`. Runner ya amri inapokubali ramani ya mazingira, jaribu ikiwa inapitisha mojawapo ya vigezo hivyo kwenye mchakato wa zsh wenye ruhusa za juu. Hivyo, `.zshenv` inayoweza kuandikwa inaweza kuendeshwa **kabla** ya sehemu ya amri ambayo runner hukagua au kuruhusu. Hili linahitaji mchakato wenye ruhusa za juu kurithi saraka iliyoelekezwa upya; `zsh -f` huruka faili za uanzishaji za mtumiaji, lakini si `zshenv` ya mfumo mzima (mara nyingi `/etc/zshenv`, ingawa njia hutofautiana kulingana na distribution). Ukurasa wa [macOS zsh injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) una mfano mfupi wa `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

`.zshenv.zwc` au `.zshrc.zwc` mpya na halali hutekelezwa badala ya faili yake ya uanzishaji ya maandishi yasiyokompiliwa. Ikiwa unaweza kuandika kwenye saraka ya uanzishaji, kukompili faili iliyobadilishwa kisha kurejesha maandishi yanayoonekana kuwa hayana madhara kunaweza kuacha code inayotekelezeka kwenye nakala iliyokompiliwa. Huu ni ufichaji, si usimbaji fiche. Jaribio la muda hapa chini linaonyesha kwa nini kukagua faili ya maandishi pekee hakutoshi; haliathiri saraka halisi ya home.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Kwa target halisi, tambua `ZDOTDIR`/`HOME` inayotumika, kagua faili za maandishi na za `.zwc`, na uhakiki mihuri ya muda, umiliki na kama saraka za mzazi zinaweza kuandikwa. Faili ya `.zwc` lazima ilingane na faili chanzo na iwe mpya zaidi ili itangulie.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Faili za kuanzisha na kuzima Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Ushauri kuhusu kuingiza mazingira ya uanzishaji wa shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Amri zilizojengewa ndani za shell ya Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Faili ya .zshrc.zwc Uliyosahau Kukagua](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
