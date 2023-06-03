# Información Básica

Logstash se utiliza para recopilar, transformar y emitir registros. Esto se logra mediante el uso de **pipelines**, que contienen módulos de entrada, filtro y salida. El servicio se vuelve interesante cuando se ha comprometido una máquina que está ejecutando Logstash como servicio.

## Pipelines

El archivo de configuración de la canalización **/etc/logstash/pipelines.yml** especifica las ubicaciones de las canalizaciones activas:
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
Aquí puedes encontrar las rutas a los archivos **.conf**, que contienen las tuberías configuradas. Si se utiliza el módulo de salida de **Elasticsearch**, es probable que las tuberías contengan credenciales válidas para una instancia de Elasticsearch. Esas credenciales suelen tener más privilegios, ya que Logstash tiene que escribir datos en Elasticsearch. Si se utilizan comodines, Logstash intenta ejecutar todas las tuberías ubicadas en esa carpeta que coincidan con el comodín.

## Privesc con tuberías escribibles

Antes de intentar elevar tus propios privilegios, debes comprobar qué usuario está ejecutando el servicio de logstash, ya que este será el usuario que poseerás después. Por defecto, el servicio de logstash se ejecuta con los privilegios del usuario **logstash**.

Comprueba si tienes **uno** de los permisos necesarios:

* Tienes permisos de escritura en un archivo **.conf** de una tubería **o**
* **/etc/logstash/pipelines.yml** contiene un comodín y se te permite escribir en la carpeta especificada

Además, se debe cumplir **uno** de los siguientes requisitos:

* Puedes reiniciar el servicio de logstash **o**
* **/etc/logstash/logstash.yml** contiene la entrada **config.reload.automatic: true**

Si se especifica un comodín, intenta crear un archivo que coincida con ese comodín. El siguiente contenido se puede escribir en el archivo para ejecutar comandos:
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
El parámetro **interval** especifica el tiempo en segundos. En este ejemplo, el comando **whoami** se ejecuta cada 120 segundos. La salida del comando se guarda en **/tmp/output.log**.

Si **/etc/logstash/logstash.yml** contiene la entrada **config.reload.automatic: true**, solo tienes que esperar a que se ejecute el comando, ya que Logstash reconocerá automáticamente los nuevos archivos de configuración de canalización o cualquier cambio en las configuraciones de canalización existentes. De lo contrario, debes reiniciar el servicio de Logstash.

Si no se utiliza un comodín, puedes aplicar esos cambios a una configuración de canalización existente. ¡Asegúrate de no romper nada!

# Referencias

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
