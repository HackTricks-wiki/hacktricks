<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


Para una evaluación de phishing, a veces puede ser útil **clonar completamente un sitio web**.

Ten en cuenta que también puedes agregar algunos payloads al sitio clonado, como un gancho BeEF para "controlar" la pestaña del usuario.

Existen diferentes herramientas que puedes utilizar para este propósito:

## wget
```text
wget -mk -nH
```
## goclone

### Descripción

`goclone` es una herramienta que te permite clonar un sitio web completo, incluyendo todas las páginas, imágenes y archivos asociados. Esta herramienta es útil para realizar ataques de phishing, ya que te permite crear una réplica exacta de un sitio web legítimo para engañar a los usuarios y robar sus credenciales.

### Uso

Para clonar un sitio web con `goclone`, simplemente ejecuta el siguiente comando:

```bash
goclone http://sitio-web-a-clonar.com
```

Esto creará una copia local del sitio web especificado en el directorio actual. Una vez que se complete el proceso de clonación, puedes modificar la réplica según tus necesidades para llevar a cabo un ataque de phishing efectivo.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit de Herramientas de Ingeniería Social
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
