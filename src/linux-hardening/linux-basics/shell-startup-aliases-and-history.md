# Kuanza kwa Shell, Aliases, na Historia

{{#include ../../banners/hacktricks-training.md}}

Amri ya shell inaweza kufanya kazi tofauti na programu inayoweza kutekelezwa yenye jina hilo hilo ikiwa alias, function, faili ya kuanzisha, au variable ya mazingira inabadilisha jinsi inavyoendeshwa. Kagua vitu hivi kabla ya kuamini matokeo ya amri au kudhani kuwa script inatumia PATH sawa na kipindi shirikishi.

## Kagua shell ya sasa

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` na `command -V` hufichua kama jina linapatana na alias, function, builtin, au file. `command -v` na `which` huenda zisionyeshe taarifa sawa kuhusu aliases na functions. Historia ya shell inaweza kufichua commands au credentials, lakini huenda isiwe kamili, imezimwa, au ihifadhiwe kwenye memory hadi session itoke.

`.bashrc` iliyorekebishwa inaweza kufafanua alias ya `sudo` inayoiga ombi la password, kurekodi jibu, na kulipitisha kwa command halisi. Hii inaweza kuficha kunaswa kwa credentials bila kubadilisha executable ya `sudo` au `PATH`.<sup>[[5]](#references)</sup> Shell lazima isome startup file iliyorekebishwa na kupanua alias.<sup>[[7]](#references)</sup> Kwa chaguomsingi, Bash isiyo ya interactive haipanui aliases isipokuwa `expand_aliases` iwashwe.<sup>[[6]](#references)</sup>

## Kagua startup na history files

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Faili ya uanzishaji inayoweza kuandikwa na mtumiaji inaweza kutekeleza amri shell itakapozinduliwa baadaye. Faili ya uanzishaji ya mfumo mzima au ya mtumiaji mwenye haki za juu ni nyeti zaidi ikiwa akaunti yenye haki za chini inaweza kuibadilisha. Bash isiyoingiliana pia inaweza kusoma faili iliyotajwa na `BASH_ENV`; ukurasa wa [environment variables](linux-environment-variables.md#bash_env--env) unaeleza tabia hiyo na njia nyingine za kuingiza msimbo kwenye interpreters. Thibitisha ni faili zipi shell halisi husoma katika vipindi vya login, interactive na non-interactive kabla ya kudai kuwa kuna njia ya persistence.

Pia kagua faili zinazojumuishwa na faili ya uanzishaji ya kimataifa. Kwa mfano, `source /opt/app/venv/bin/activate` iliyoandikwa moja kwa moja ndani ya `/etc/bash.bashrc` hutekeleza faili ya activation kama msimbo wa shell wakati shell inaposoma faili hiyo ya uanzishaji. Kagua faili ya activation, ruhusa za symlink na saraka zake za mzazi, pamoja na ACLs; mtumiaji mwenye haki za chini anaweza kuathiri shell yenye haki za juu tu ikiwa shell hiyo au kazi yenye haki za juu itajumuisha faili hiyo baadaye. Ikiwa ufikiaji wa kuandika unategemea `sudoedit`, kwanza thibitisha kanuni halisi ya sudoers na kifurushi cha sudo kilichowekwa, kilichorekebishwa na msambazaji; nambari ya toleo la upstream pekee haithibitishi [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kagua history, dotfiles na backups ili kutafuta siri kama ilivyoelezwa kwenye [users and sessions](../user-information/user-and-session-triage.md). Ikiwa script yenye haki za juu hutafuta amri kwa majina, unganisha ukaguzi huu na [mwongozo wa PATH hijacking](linux-environment-variables.md#path).

## Kuelekeza upya uanzishaji wa Zsh na faili zilizokusanywa

Ikiwa mipangilio ya `RCS` ya kawaida inatumika, zsh husoma `$ZDOTDIR/.zshenv` kabla ya uendeshaji wa kawaida, ikiwemo `zsh -c` na scripts; ikiwa `ZDOTDIR` haijawekwa, hutumia `$HOME`. Wakati command runner inapokubali environment map, jaribu kuona kama inapitisha mojawapo ya vigeu hivyo kwenye mchakato wa zsh wenye haki za juu. Hivyo, `.zshenv` inayoweza kuandikwa inaweza kutekelezwa **kabla** ya command body ambayo runner hukagua au kuiweka kwenye allowlist. Hili linahitaji mchakato wenye haki za juu kurithi saraka iliyoelekezwa upya; `zsh -f` huruka faili za uanzishaji za mtumiaji, lakini si `zshenv` ya kimataifa (mara nyingi `/etc/zshenv`, lakini njia hutofautiana kulingana na distribution). Ukurasa wa [macOS zsh injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) una mfano rahisi wa `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Faili mpya zaidi na halali ya `.zshenv.zwc` au `.zshrc.zwc` hutekelezwa badala ya faili yake ya uanzishaji ya maandishi ya kawaida. Ikiwa unaweza kuandika kwenye saraka ya uanzishaji, kukusanya faili iliyobadilishwa kisha kurejesha maandishi yanayoonekana kutokuwa na madhara kunaweza kuacha msimbo unaotekelezeka ndani ya nakala iliyokusanywa. Huu ni ufichaji, si usimbaji fiche. Jaribio la muda mfupi hapa chini linaonyesha kwa nini kukagua faili ya maandishi pekee hakutoshi; haligusi saraka halisi ya home.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Kwa shabaha halisi, tambua thamani za `ZDOTDIR`/`HOME` zinazotumika, kagua faili za maandishi na za `.zwc`, na uhakiki mihuri ya muda, umiliki na kama saraka za mzazi zina ruhusa ya kuandikiwa. Faili ya `.zwc` lazima ilingane na faili chanzo na iwe mpya zaidi ili ipewe kipaumbele.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Faili za Zsh za kuwasha na kuzima](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Ushauri kuhusu kuingiza mazingira wakati wa kuwasha Shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Amri zilizojengewa ndani za Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Faili ya .zshrc.zwc Uliyosahau Kukagua](https://dfir.ch/posts/compiled_zsh/)
- [5] [Kampeni ya Ujasusi Inayotumia AI Yalenga Miundombinu ya Linux ya Serikali](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Mwongozo wa Bash: Majina mbadala](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Mwongozo wa Bash: Faili za kuwasha za Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
