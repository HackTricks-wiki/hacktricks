<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


## Logstash

Logstash se utiliza para **recopilar, transformar y enviar registros** a través de un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **entrada**, **filtro** y **salida**. Un aspecto interesante surge cuando Logstash opera en una máquina comprometida.

### Configuración del Pipeline

Los pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que enumera las ubicaciones de las configuraciones del pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen configuraciones de canalización. Al emplear un **módulo de salida de Elasticsearch**, es común que las **canalizaciones** incluyan **credenciales de Elasticsearch**, las cuales suelen poseer amplios privilegios debido a la necesidad de Logstash de escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten a Logstash ejecutar todas las canalizaciones coincidentes en el directorio designado.

### Escalada de privilegios a través de Canalizaciones Escribibles

Para intentar la escalada de privilegios, primero identifique el usuario bajo el cual se está ejecutando el servicio de Logstash, típicamente el usuario **logstash**. Asegúrese de cumplir con **uno** de estos criterios:

- Poseer **acceso de escritura** a un archivo **.conf** de canalización **o**
- El archivo **/etc/logstash/pipelines.yml** utiliza un comodín y puede escribir en la carpeta de destino

Además, se debe cumplir con **una** de estas condiciones:

- Capacidad para reiniciar el servicio de Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene **config.reload.automatic: true** configurado

Dado un comodín en la configuración, crear un archivo que coincida con este comodín permite la ejecución de comandos. Por ejemplo:
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
Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo dado, el comando **whoami** se ejecuta cada 120 segundos, con su salida dirigida a **/tmp/output.log**.

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente nuevas o modificadas configuraciones de canalización sin necesidad de reiniciar. Si no hay comodines, aún se pueden realizar modificaciones en las configuraciones existentes, pero se recomienda precaución para evitar interrupciones.


# Referencias

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
