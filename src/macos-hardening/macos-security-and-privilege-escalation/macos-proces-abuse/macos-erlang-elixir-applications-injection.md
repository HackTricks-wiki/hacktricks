# Injection dans les applications Erlang et Elixir sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` et `ERL_ZFLAGS`

Le lanceur `erl` ajoute `ERL_AFLAGS` au début de sa ligne de commande, et `ERL_FLAGS` / `ERL_ZFLAGS` à la fin. Comme `-eval` évalue une expression Erlang lors de l'initialisation de la VM, ces variables peuvent permettre une exécution de code sans fichier avant le traitement prévu.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix et de nombreuses releases Elixir démarrent finalement la VM Erlang et peuvent hériter de ces flags. Confirmez le wrapper exact de la release : il peut reconstruire ou nettoyer les arguments de la VM, tandis que certains outils prennent explicitement en charge `ERL_AFLAGS`, `ERL_ZFLAGS` ou `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Contrairement à la plupart des techniques basées sur des fichiers, le payload `-eval` ne nécessite aucun fichier contrôlé par l’attaquant. Un wrapper de confiance doit effacer les trois variables de flags Erlang (ainsi que `ELIXIR_ERL_OPTIONS` pour Elixir) avant de démarrer le runtime ; n’essayez pas d’autoriser individuellement certains flags de la VM, sauf si le parser et l’ordre de traitement sont parfaitement compris.

## References

- [1] [`erl` command et variables d’environnement](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Releases Elixir et options d’environnement de la VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
