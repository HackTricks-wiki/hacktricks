# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Consulta la publicación original para [toda la información sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Como **resumen**: si puedes escribir en la propiedad **msDS-KeyCredentialLink** de un usuario/computadora, puedes recuperar el **hash NT de ese objeto**.

En la publicación, se describe un método para configurar **credenciales de autenticación de clave pública-privada** para adquirir un **Ticket de Servicio** único que incluye el hash NTLM del objetivo. Este proceso implica el NTLM_SUPPLEMENTAL_CREDENTIAL cifrado dentro del Certificado de Atributo de Privilegio (PAC), que puede ser descifrado.

### Requirements

Para aplicar esta técnica, deben cumplirse ciertas condiciones:

- Se necesita un mínimo de un Controlador de Dominio de Windows Server 2016.
- El Controlador de Dominio debe tener un certificado digital de autenticación de servidor instalado.
- Active Directory debe estar en el Nivel Funcional de Windows Server 2016.
- Se requiere una cuenta con derechos delegados para modificar el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuse

El abuso de Key Trust para objetos de computadora abarca pasos más allá de obtener un Ticket Granting Ticket (TGT) y el hash NTLM. Las opciones incluyen:

1. Crear un **ticket de plata RC4** para actuar como usuarios privilegiados en el host previsto.
2. Usar el TGT con **S4U2Self** para la suplantación de **usuarios privilegiados**, lo que requiere alteraciones en el Ticket de Servicio para agregar una clase de servicio al nombre del servicio.

Una ventaja significativa del abuso de Key Trust es su limitación a la clave privada generada por el atacante, evitando la delegación a cuentas potencialmente vulnerables y no requiriendo la creación de una cuenta de computadora, lo que podría ser difícil de eliminar.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Se basa en DSInternals proporcionando una interfaz C# para este ataque. Whisker y su contraparte en Python, **pyWhisker**, permiten la manipulación del atributo `msDS-KeyCredentialLink` para obtener control sobre las cuentas de Active Directory. Estas herramientas soportan varias operaciones como agregar, listar, eliminar y limpiar credenciales clave del objeto objetivo.

Las funciones de **Whisker** incluyen:

- **Add**: Genera un par de claves y agrega una credencial clave.
- **List**: Muestra todas las entradas de credenciales clave.
- **Remove**: Elimina una credencial clave especificada.
- **Clear**: Borra todas las credenciales clave, potencialmente interrumpiendo el uso legítimo de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Extiende la funcionalidad de Whisker a **sistemas basados en UNIX**, aprovechando Impacket y PyDSInternals para capacidades de explotación completas, incluyendo listar, agregar y eliminar KeyCredentials, así como importarlos y exportarlos en formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray tiene como objetivo **explotar los permisos GenericWrite/GenericAll que amplios grupos de usuarios pueden tener sobre objetos de dominio** para aplicar ShadowCredentials de manera amplia. Implica iniciar sesión en el dominio, verificar el nivel funcional del dominio, enumerar objetos de dominio e intentar agregar KeyCredentials para la adquisición de TGT y la revelación de hash NT. Las opciones de limpieza y las tácticas de explotación recursiva mejoran su utilidad.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
