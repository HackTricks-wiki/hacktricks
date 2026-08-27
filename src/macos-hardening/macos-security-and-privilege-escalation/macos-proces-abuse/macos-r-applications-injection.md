# Inyección de aplicaciones R en macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Al iniciarse, R carga los archivos de perfil del sitio y del usuario, que contienen código R. `R_PROFILE` selecciona el perfil del sitio y `R_PROFILE_USER` selecciona el perfil del usuario, lo que permite que un entorno heredado redirija cualquiera de estas búsquedas a un archivo legible por el atacante.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` omite el perfil del usuario, `--no-site-file` omite el perfil del sitio y `--vanilla` incluye ambas protecciones. R procesa primero los archivos de entorno seleccionados por `R_ENVIRON` y `R_ENVIRON_USER`, pero esos archivos solo establecen variables; las variables del perfil son la primitive directa para ejecutar código arbitrario.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` y rutas de las libraries

R adjunta los paquetes separados por comas en `R_DEFAULT_PACKAGES` durante el inicio. `Rscript` da prioridad a `R_SCRIPT_DEFAULT_PACKAGES`. Combinar cualquiera de estas variables con `R_LIBS`, `R_LIBS_USER` o `R_LIBS_SITE` puede hacer que R encuentre y cargue un paquete instalado controlado por el atacante; su hook `.onLoad` o `.onAttach` se ejecuta automáticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Esto requiere un paquete R instalado estructuralmente válido, no simplemente un archivo `.R` suelto. `--vanilla` no elimina las variables heredadas directamente, por lo que un wrapper de confianza también debe desestablecer o reemplazar las variables del paquete predeterminado y de la ruta de bibliotecas, además de deshabilitar los archivos de perfil.

## References

- [1] [Inicialización al inicio de una sesión de R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Instalación y administración de R: paquetes adicionales](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
