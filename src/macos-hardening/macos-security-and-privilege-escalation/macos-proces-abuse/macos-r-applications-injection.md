# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Pri pokretanju, R učitava site i user profile fajlove koji sadrže R kod. `R_PROFILE` bira site profile, a `R_PROFILE_USER` bira user profile, što omogućava da nasleđeno okruženje preusmeri bilo koje od ta dva traženja na fajl dostupan napadaču.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` preskače korisnički profil, `--no-site-file` preskače site profil, a `--vanilla` uključuje obe zaštite. R prvo obrađuje environment fajlove izabrane pomoću `R_ENVIRON` i `R_ENVIRON_USER`, ali ti fajlovi samo postavljaju promenljive; promenljive profila predstavljaju direktan primitive za izvršavanje proizvoljnog koda.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` i putanje biblioteka

R tokom pokretanja učitava pakete razdvojene zarezima iz promenljive `R_DEFAULT_PACKAGES`. `Rscript` daje prednost promenljivoj `R_SCRIPT_DEFAULT_PACKAGES`. Kombinovanje bilo koje od ovih promenljivih sa `R_LIBS`, `R_LIBS_USER` ili `R_LIBS_SITE` može omogućiti da R pronađe i učita instalirani paket pod kontrolom napadača; njegova `.onLoad` ili `.onAttach` hook funkcija izvršava se automatski.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Ovo zahteva strukturalno validan instalirani R paket, a ne samo zaseban `.R` fajl. `--vanilla` ne uklanja direktno nasleđene promenljive, tako da pouzdani wrapper mora da poništi ili zameni promenljive podrazumevanih paketa i putanja biblioteka, kao i da onemogući profile fajlove.

## References

- [1] [Inicijalizacija pri pokretanju R sesije](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Instalacija i administracija R-a: dodatni paketi](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
