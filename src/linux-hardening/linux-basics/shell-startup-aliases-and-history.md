# Shell-opstart, aliasse en geskiedenis

{{#include ../../banners/hacktricks-training.md}}

’n shell-opdrag kan anders optree as die uitvoerbare lêer met dieselfde naam as ’n alias, funksie, opstartlêer of omgewingsveranderlike verander hoe dit loop. Gaan hierdie na voordat jy die uitvoer van ’n opdrag vertrou of aanvaar dat ’n script dieselfde PATH as ’n interaktiewe sessie gebruik.

## Inspekteer die huidige shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` en `command -V` wys of ’n naam na ’n alias, funksie, ingeboude opdrag of lêer verwys. `command -v` en `which` vertel dalk nie dieselfde storie oor aliases en funksies nie. Shell-geskiedenis kan opdragte of geloofsbriewe blootlê, maar dit kan onvolledig of afgeskakel wees, of in die geheue bly totdat die sessie eindig.

## Hersien opstart- en geskiedenislêers

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

'n Opstartlêer waarop 'n gebruiker kan skryf, kan opdragte uitvoer wanneer 'n dop later begin. 'n Stelselwye opstartlêer of 'n bevoorregte gebruiker se opstartlêer is meer sensitief as 'n laerbevoorregte rekening dit kan wysig. Nie-interaktiewe Bash kan ook die lêer lees wat deur `BASH_ENV` benoem word; die bladsy oor [omgewingsveranderlikes](linux-environment-variables.md#bash_env--env) verduidelik dié gedrag en ander interpreter-haakplekke. Verifieer watter lêers die werklike dop vir aanmeldings-, interaktiewe en nie-interaktiewe sessies lees voordat jy beweer dat daar 'n volhardingsroete is.

Ondersoek ook lêers wat deur 'n globale opstartlêer ingesluit word. Byvoorbeeld, `source /opt/app/venv/bin/activate` as letterlike teks in `/etc/bash.bashrc` voer die aktiveringslêer as dopkode uit wanneer 'n dop daardie opstartlêer werklik lees. Gaan die aktiveringslêer, die toestemmings van die simboliese skakel en ouergids, en ACL's na; 'n laerbevoorregte gebruiker met skryftoegang kan 'n bevoorregte dop beïnvloed slegs as daardie dop of 'n bevoorregte taak dit later insluit. As skryftoegang van `sudoedit` afhang, verifieer eers die presiese sudoers-reël en die geïnstalleerde, deur die verspreider gelapte sudo-pakket; 'n stroomop-weergawe-string alleen bevestig nie [blootstelling aan sudoedit-argumentinspuiting](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) nie.

Soek na geheime in geskiedenis, dotfiles en rugsteunlêers soos beskryf in [gebruikers en sessies](../user-information/user-and-session-triage.md). As 'n bevoorregte skrip opdragte volgens naam oplos, kombineer hierdie ondersoek met die [riglyne oor PATH-kaping](linux-environment-variables.md#path).

## Zsh-opstartomleiding en saamgestelde lêers

Met die verstekinstellings vir `RCS` lees zsh `$ZDOTDIR/.zshenv` voor normale aanroepe, insluitend `zsh -c` en skripte; as `ZDOTDIR` nie gestel is nie, gebruik dit `$HOME`. Wanneer 'n opdraguitvoerder 'n omgewingskaart aanvaar, toets of dit een van dié veranderlikes na 'n bevoorregte zsh-proses deurgee. 'n `.zshenv` waarop geskryf kan word, kan dan **uitgevoer word voordat** die opdragliggaam wat die uitvoerder nagaan of op 'n toelaatlys plaas. Dit vereis dat die bevoorregte proses die herlei gids erf; `zsh -f` slaan gebruikeropstartlêers oor, maar nie die globale `zshenv` nie (dikwels `/etc/zshenv`, maar die paaie verskil tussen verspreidings). Die [macOS-bladsy oor zsh-inspuiting](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) bevat 'n minimale `ZDOTDIR`-voorbeeld.<sup>[[1]](#references)[[2]](#references)</sup>

'n Nuwer, geldige `.zshenv.zwc` of `.zshrc.zwc` word in plaas van die gewone teksweergawe van die opstartlêer uitgevoer. As jy in die opstartgids kan skryf, kan jy 'n gewysigde lêer saamstel en daarna die gewone teksweergawe met onskuldig lykende inhoud herstel; uitvoerbare kode kan dan in die saamgestelde kopie agterbly. Dit is verhulling, nie enkripsie nie. Die weggooibare toets hieronder wys waarom dit nie genoeg is om net die tekslêer te ondersoek nie; dit raak nie 'n werklike tuisgids nie.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Vir ’n werklike teiken, bepaal die effektiewe `ZDOTDIR`/`HOME`, inspekteer beide die teks- en `.zwc`-lêers, en kontroleer tydstempels, eienaarskap en skryfbare ouergidse. ’n `.zwc`-lêer moet met die bronlêer ooreenstem en nuwer wees om voorrang te geniet.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh-opstart- en afsluitlêers](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Sekuriteitsadvies oor omgewingsinspuiting tydens dop-opstart](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh-dop se ingeboude opdragte: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Die .zshrc.zwc wat jy vergeet het om na te gaan](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
