# Injection d'applications R sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Au démarrage, R charge les fichiers de profil du site et de l'utilisateur contenant du code R. `R_PROFILE` sélectionne le profil du site et `R_PROFILE_USER` sélectionne le profil de l'utilisateur, ce qui permet à un environnement hérité de rediriger l'une ou l'autre recherche vers un fichier lisible par l'attaquant.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` ignore le profil utilisateur, `--no-site-file` ignore le profil du site, et `--vanilla` inclut ces deux protections. R traite d'abord les fichiers d'environnement sélectionnés par `R_ENVIRON` et `R_ENVIRON_USER`, mais ces fichiers ne font que définir des variables ; les variables de profil constituent la primitive d'exécution de code arbitraire.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` et chemins des libraries

R attache les packages séparés par des virgules dans `R_DEFAULT_PACKAGES` lors du démarrage. `Rscript` donne la priorité à `R_SCRIPT_DEFAULT_PACKAGES`. La combinaison de l'une ou l'autre variable avec `R_LIBS`, `R_LIBS_USER` ou `R_LIBS_SITE` peut permettre à R de trouver et de charger un package installé contrôlé par l'attaquant ; son hook `.onLoad` ou `.onAttach` s'exécute automatiquement.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Cela nécessite un package R installé et structurellement valide, et pas simplement un fichier `.R` isolé. `--vanilla` n'efface pas les variables héritées directement ; un wrapper de confiance doit donc également désactiver ou remplacer les variables relatives au package par défaut et au chemin des libraries, tout en désactivant les fichiers de profil.

## References

- [1] [Initialisation au démarrage d'une session R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Installation et administration de R : packages complémentaires](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
