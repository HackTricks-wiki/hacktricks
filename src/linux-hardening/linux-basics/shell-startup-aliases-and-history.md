# Shell-opstart, aliasse en geskiedenis

{{#include ../../banners/hacktricks-training.md}}

'n Shell-opdrag kan anders optree as die uitvoerbare lêer met dieselfde naam as 'n alias, funksie, opstartlêer of omgewingsveranderlike verander hoe dit loop. Gaan dit na voordat jy 'n opdrag se uitvoer vertrou of aanneem dat 'n script dieselfde PATH as 'n interaktiewe sessie gebruik.

## Inspekteer die huidige shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` en `command -V` wys of ’n naam na ’n alias, funksie, ingeboude opdrag of lêer verwys. `command -v` en `which` gee dalk nie dieselfde resultaat vir aliases en funksies nie. Shell-geskiedenis kan opdragte of aanmeldbesonderhede blootlê, maar dit kan onvolledig of afgeskakel wees, of in die geheue gehou word totdat die sessie eindig.

’n Gewysigde `.bashrc` kan ’n `sudo`-alias definieer wat ’n wagwoordaanwysing naboots, die antwoord aanteken en dit aan die werklike opdrag deurgee. Dit kan die onderskepping van aanmeldbesonderhede verberg sonder om die `sudo`-uitvoerbare lêer of `PATH` te verander.<sup>[[5]](#references)</sup> Die shell moet die gewysigde opstartlêer lees en die alias uitbrei.<sup>[[7]](#references)</sup> By verstek brei nie-interaktiewe Bash nie aliases uit nie, tensy `expand_aliases` geaktiveer is.<sup>[[6]](#references)</sup>

## Hersien opstart- en geskiedenisêers

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

'n Gebruiker-skryfbare opstartlêer kan opdragte uitvoer wanneer 'n shell later begin. 'n Stelselwye opstartlêer of 'n bevoorregte gebruiker se opstartlêer is meer sensitief as 'n rekening met laer voorregte dit kan wysig. Nie-interaktiewe Bash kan ook die lêer lees wat deur `BASH_ENV` benoem word; die bladsy oor [omgewingsveranderlikes](linux-environment-variables.md#bash_env--env) verduidelik dié gedrag en ander interpreter-hooks. Verifieer watter lêers die werklike shell vir aanmeld-, interaktiewe en nie-interaktiewe sessies lees voordat jy 'n persistensieroete beweer.

Ondersoek ook lêers wat deur 'n globale opstartlêer ingesluit word. Byvoorbeeld, 'n letterlike `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` voer die aktiveringslêer as shell-kode uit wanneer 'n shell daardie opstartlêer werklik lees. Hersien die aktiveringslêer, die toestemmings vir simboliese skakels en ouergidse, en ACL's; 'n skrywer met laer voorregte kan 'n bevoorregte shell slegs beïnvloed as daardie shell of 'n bevoorregte taak dit later insluit. As skryftoegang van `sudoedit` afhang, verifieer eers die presiese sudoers-reël en die geïnstalleerde, deur die verspreider aangepaste sudo-pakket; 'n stroomop-weergawe-string alleen bewys nie blootstelling aan [sudoedit-argumentinspuiting](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) nie.

Soek na geheime in geskiedenis, dotfiles en rugsteun soos beskryf in [gebruikers en sessies](../user-information/user-and-session-triage.md). As 'n bevoorregte skrip opdragte volgens naam oplos, kombineer hierdie hersiening met die [leiding oor PATH-kaping](linux-environment-variables.md#path).

## Zsh-opstartherleiding en gecompileerde lêers

Met die verstek `RCS`-instellings lees zsh `$ZDOTDIR/.zshenv` voor normale aanroepe, insluitend `zsh -c` en skripte; as `ZDOTDIR` nie ingestel is nie, gebruik dit `$HOME`. Wanneer 'n opdraguitvoerder 'n omgewingskaart aanvaar, toets of dit een van dié veranderlikes na 'n bevoorregte zsh-proses deurgee. 'n Skryfbare `.zshenv` kan dan loop **voordat** die opdragliggaam wat die uitvoerder nagaan of toelaat, uitgevoer word. Dit vereis dat die bevoorregte proses die herlei gids erf; `zsh -f` slaan gebruiker-opstartlêers oor, maar nie die globale `zshenv` nie (dikwels `/etc/zshenv`, maar die paaie verskil tussen verspreidings). Die [macOS-zsh-inspuitingsbladsy](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) bevat 'n minimale `ZDOTDIR`-voorbeeld.<sup>[[1]](#references)[[2]](#references)</sup>

'n Nuwer, geldige `.zshenv.zwc` of `.zshrc.zwc` word in plaas van die ooreenstemmende gewone-teks-opstartlêer uitgevoer. As jy die opstartgids kan skryf, kan jy 'n gewysigde lêer compileer en dan skynbaar onskadelike gewone teks terugplaas, terwyl uitvoerbare kode in die gecompileerde kopie agterbly. Dit is verduistering, nie enkripsie nie. Die weggooibare toets hieronder wys waarom dit nie genoeg is om net die tekslêer te inspekteer nie; dit raak nie 'n werklike tuisgids nie.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Vir ’n werklike teiken, bepaal die effektiewe `ZDOTDIR`/`HOME`, ondersoek beide die teks- en `.zwc`-lêers, en kontroleer tydstempels, eienaarskap en skryfbare ouergidse. ’n `.zwc`-lêer moet met die bronlêer ooreenstem en nuwer wees om voorkeur te geniet.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh-opstart- en afsluitlêers](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Advies oor inspuiting in die dop se opstartomgewing](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh-dop se ingeboude opdragte: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Die .zshrc.zwc wat jy vergeet het om na te gaan](https://dfir.ch/posts/compiled_zsh/)
- [5] [KI-aangedrewe spioenasieveldtog teiken Linux-infrastruktuur van die regering](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash-handleiding: Aliasse](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash-handleiding: Bash-opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
