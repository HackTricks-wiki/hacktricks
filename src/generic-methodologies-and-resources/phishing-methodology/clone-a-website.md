# Clonar un sitio web

{{#include ../../banners/hacktricks-training.md}}

Para una evaluación de phishing, a veces puede ser útil **clonar/volcar completamente un sitio web**.

Ten en cuenta que también puedes añadir algunos payloads al sitio web clonado, como un hook de BeEF, para "controlar" la pestaña del usuario.

Hay diferentes herramientas que puedes utilizar para este propósito:

## wget

El siguiente comando utiliza los modos de Wget de mirror, requisitos de página, conversión de enlaces y ajuste de extensiones, y después sirve los archivos descargados desde el directorio actual con el módulo `http.server` de Python en el puerto 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

El repositorio de goclone describe la utilidad como una herramienta que descarga un sitio web en un directorio local mientras conserva su estructura de enlaces relativos, y documenta la invocación `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit de herramientas de ingeniería social

El repositorio de Social-Engineer Toolkit (SET) identifica SET como un framework open-source de pentesting para evaluaciones autorizadas de ingeniería social.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Manual de GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Documentación de Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Repositorio de goclone](https://github.com/imthaghost/goclone)
- [4] [Repositorio de Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
