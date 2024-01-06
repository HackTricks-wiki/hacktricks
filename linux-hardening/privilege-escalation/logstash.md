<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Información Básica

Logstash se utiliza para recopilar, transformar y emitir registros. Esto se realiza mediante el uso de **pipelines**, que contienen módulos de entrada, filtro y salida. El servicio se vuelve interesante cuando se ha comprometido una máquina que está ejecutando Logstash como servicio.

## Pipelines

El archivo de configuración del pipeline **/etc/logstash/pipelines.yml** especifica las ubicaciones de los pipelines activos:
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Aquí puedes encontrar las rutas a los archivos **.conf**, que contienen las **pipelines** configuradas. Si se utiliza el **módulo de salida Elasticsearch**, es probable que las **pipelines** **contengan** **credenciales** válidas para una instancia de Elasticsearch. Estas credenciales suelen tener más privilegios, ya que Logstash tiene que escribir datos en Elasticsearch. Si se utilizan comodines, Logstash intenta ejecutar todas las **pipelines** ubicadas en esa carpeta que coincidan con el comodín.

## Privesc con pipelines escribibles

Antes de intentar elevar tus propios privilegios, debes verificar qué usuario está ejecutando el servicio de logstash, ya que este será el usuario que controlarás posteriormente. Por defecto, el servicio de logstash se ejecuta con los privilegios del usuario **logstash**.

Comprueba si tienes **uno** de los derechos requeridos:

* Tienes **permisos de escritura** en un archivo **.conf** de una **pipeline** **o**
* **/etc/logstash/pipelines.yml** contiene un comodín y tienes permiso para escribir en la carpeta especificada

Además, se debe cumplir **uno** de los siguientes requisitos:

* Eres capaz de reiniciar el servicio de logstash **o**
* **/etc/logstash/logstash.yml** contiene la entrada **config.reload.automatic: true**

Si se especifica un comodín, intenta crear un archivo que coincida con ese comodín. El siguiente contenido puede ser escrito en el archivo para ejecutar comandos:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
El **intervalo** especifica el tiempo en segundos. En este ejemplo, el comando **whoami** se ejecuta cada 120 segundos. La salida del comando se guarda en **/tmp/output.log**.

Si **/etc/logstash/logstash.yml** contiene la entrada **config.reload.automatic: true** solo tienes que esperar hasta que se ejecute el comando, ya que Logstash reconocerá automáticamente nuevos archivos de configuración de pipeline o cualquier cambio en las configuraciones de pipeline existentes. De lo contrario, inicia de nuevo el servicio de logstash.

Si no se utiliza un comodín, puedes aplicar esos cambios a una configuración de pipeline existente. **¡Asegúrate de no romper nada!**

# Referencias

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
