# Criptografía

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en la criptografía práctica para pruebas de seguridad y CTFs: reconocer patrones comunes, seleccionar herramientas adecuadas y aplicar ataques conocidos.

Para consultar técnicas que ocultan datos dentro de archivos, visita la sección **Stego**.

## Cómo usar esta sección

Comienza identificando la primitiva y sus parámetros. Después, determina qué controla u observa el atacante, como un oracle, un valor leak o la reutilización de un nonce, antes de seleccionar un ataque.

### Flujo de trabajo de CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Criptografía simétrica

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs y KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Criptografía de clave pública

{{#ref}}
public-key/README.md
{{#endref}}

### TLS y certificados

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Criptografía en malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Miscelánea

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuración rápida

Crea un entorno aislado de Python e instala los paquetes de uso habitual. La documentación de PyCryptodome recomienda instalar `pycryptodome` con `pip`; SageMath proporciona instrucciones de instalación independientes para cada plataforma compatible.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath suele ser útil para realizar cálculos algebraicos, de lattice, RSA y de curvas elípticas.<sup>[[2]](#references)</sup>

## References

- [1] [Documentación de PyCryptodome - Instalación](https://www.pycryptodome.org/src/installation)
- [2] [Documentación de SageMath - Guía de instalación](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
