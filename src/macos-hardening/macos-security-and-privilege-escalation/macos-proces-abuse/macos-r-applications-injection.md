# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

By opstart lees R bronkode uit werf- en gebruikersprofiellêers. `R_PROFILE` kies die werfprofiel en `R_PROFILE_USER` kies die gebruikersprofiel, wat dit moontlik maak dat ’n geërfde omgewing enige van die opsoeke na ’n lêer wat deur ’n aanvaller gelees kan word, herlei.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` slaan die gebruikerprofiel oor, `--no-site-file` slaan die werfprofiel oor, en `--vanilla` sluit albei beskermings in. R verwerk eers omgewingslêers wat deur `R_ENVIRON` en `R_ENVIRON_USER` gekies word, maar daardie lêers stel slegs veranderlikes; die profielveranderlikes is die direkte arbitrary-code primitive.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` en library paths

R heg die komma-geskeide packages in `R_DEFAULT_PACKAGES` tydens opstart aan. `Rscript` gee voorkeur aan `R_SCRIPT_DEFAULT_PACKAGES`. Deur enige van hierdie veranderlikes met `R_LIBS`, `R_LIBS_USER` of `R_LIBS_SITE` te kombineer, kan R 'n aanvaller-beheerde geïnstalleerde package vind en laai; sy `.onLoad`- of `.onAttach`-hook word outomaties uitgevoer.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Dit vereis ’n struktureel geldige geïnstalleerde R package, nie bloot ’n los `.R`-lêer nie. `--vanilla` verwyder nie direkte geërfde veranderlikes nie, dus moet ’n trusted wrapper die verstek-package- en library-path-veranderlikes ook unset of vervang, benewens die deaktivering van profile-lêers.

## References

- [1] [Initialisering by die begin van ’n R-sessie](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R-installasie en administrasie: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
