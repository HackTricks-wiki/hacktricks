# Algoritmos Criptográficos/Compresión

## Algoritmos Criptográficos/Compresión

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identificación de Algoritmos

Si terminas en un código **usando desplazamientos a la derecha e izquierda, xors y varias operaciones aritméticas** es muy probable que sea la implementación de un **algoritmo criptográfico**. Aquí se mostrarán algunas formas de **identificar el algoritmo que se utiliza sin necesidad de revertir cada paso**.

### Funciones de API

**CryptDeriveKey**

Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** revisando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Revisa aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime y descomprime un buffer de datos dado.

**CryptAcquireContext**

La función **CryptAcquireContext** se utiliza para adquirir un identificador a un contenedor de claves específico dentro de un proveedor de servicios criptográficos (CSP) particular. **Este identificador devuelto se utiliza en llamadas a funciones de CryptoAPI** que usan el CSP seleccionado.

**CryptCreateHash**

Inicia el hash de un flujo de datos. Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** revisando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (376).png>)

\
Revisa aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de Código

A veces es muy fácil identificar un algoritmo gracias al hecho de que necesita usar un valor especial y único.

![](<../../.gitbook/assets/image (370).png>)

Si buscas la primera constante en Google esto es lo que obtienes:

![](<../../.gitbook/assets/image (371).png>)

Por lo tanto, puedes asumir que la función descompilada es un **calculador de sha256**.
Puedes buscar cualquiera de las otras constantes y obtendrás (probablemente) el mismo resultado.

### Información de Datos

Si el código no tiene ninguna constante significativa, puede estar **cargando información de la sección .data**.\
Puedes acceder a esos datos, **agrupar el primer dword** y buscarlo en Google como hemos hecho en la sección anterior:

![](<../../.gitbook/assets/image (372).png>)

En este caso, si buscas **0xA56363C6** puedes encontrar que está relacionado con las **tablas del algoritmo AES**.

## RC4 **(Criptografía Simétrica)**

### Características

Está compuesto por 3 partes principales:

* **Etapa de Inicialización/**: Crea una **tabla de valores de 0x00 a 0xFF** (256 bytes en total, 0x100). Esta tabla se llama comúnmente **Caja de Sustitución** (o SBox).
* **Etapa de Revuelto**: Recorrerá **la tabla** creada anteriormente (bucle de 0x100 iteraciones, de nuevo) modificando cada valor con bytes **semi-aleatorios**. Para crear estos bytes semi-aleatorios, se utiliza la **clave RC4**. Las **claves RC4** pueden tener **entre 1 y 256 bytes de longitud**, sin embargo, se recomienda que sea superior a 5 bytes. Comúnmente, las claves RC4 tienen 16 bytes de longitud.
* **Etapa XOR**: Finalmente, el texto plano o cifrado se **XOR con los valores creados antes**. La función para encriptar y desencriptar es la misma. Para esto, se realizará un **bucle a través de los 256 bytes creados** tantas veces como sea necesario. Esto suele reconocerse en un código descompilado con un **%256 (mod 256)**.

{% hint style="info" %}
**Para identificar un RC4 en un código desensamblado/descompilado puedes buscar 2 bucles de tamaño 0x100 (con el uso de una clave) y luego un XOR de los datos de entrada con los 256 valores creados antes en los 2 bucles probablemente usando un %256 (mod 256)**
{% endhint %}

### **Etapa de Inicialización/Caja de Sustitución:** (Nota el número 256 usado como contador y cómo se escribe un 0 en cada lugar de los 256 caracteres)

![](<../../.gitbook/assets/image (377).png>)

### **Etapa de Revuelto:**

![](<../../.gitbook/assets/image (378).png>)

### **Etapa XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Criptografía Simétrica)**

### **Características**

* Uso de **cajas de sustitución y tablas de búsqueda**
* Es posible **distinguir AES gracias al uso de valores específicos de tablas de búsqueda** (constantes). _Nota que la **constante** puede estar **almacenada** en el binario **o creada**_ _**dinámicamente**._
* La **clave de cifrado** debe ser **divisible** por **16** (usualmente 32B) y comúnmente se utiliza un **IV** de 16B.

### Constantes de SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Criptografía Simétrica)**

### Características

* Es raro encontrar algún malware que lo utilice, pero hay ejemplos (Ursnif)
* Es simple determinar si un algoritmo es Serpent o no basado en su longitud (función extremadamente larga)

### Identificación

En la siguiente imagen observa cómo se utiliza la constante **0x9E3779B9** (nota que esta constante también es utilizada por otros algoritmos criptográficos como **TEA** -Tiny Encryption Algorithm).\
También observa el **tamaño del bucle** (**132**) y el **número de operaciones XOR** en las instrucciones de **desensamblado** y en el ejemplo de **código**:

![](<../../.gitbook/assets/image (381).png>)

Como se mencionó antes, este código puede visualizarse dentro de cualquier descompilador como una **función muy larga** ya que **no hay saltos** dentro de ella. El código descompilado puede parecerse al siguiente:

![](<../../.gitbook/assets/image (382).png>)

Por lo tanto, es posible identificar este algoritmo revisando el **número mágico** y los **XOR iniciales**, viendo una **función muy larga** y **comparando** algunas **instrucciones** de la función larga **con una implementación** (como el desplazamiento a la izquierda por 7 y el giro a la izquierda por 22).

## RSA **(Criptografía Asimétrica)**

### Características

* Más complejo que los algoritmos simétricos
* ¡No hay constantes! (las implementaciones personalizadas son difíciles de determinar)
* KANAL (un analizador criptográfico) falla en mostrar pistas sobre RSA ya que se basa en constantes.

### Identificación por comparaciones

![](<../../.gitbook/assets/image (383).png>)

* En la línea 11 (izquierda) hay un `+7) >> 3` que es lo mismo que en la línea 35 (derecha): `+7) / 8`
* La línea 12 (izquierda) está comprobando si `modulus_len < 0x040` y en la línea 36 (derecha) está comprobando si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

* 3 funciones: Inicializar, Actualizar, Finalizar
* Funciones de inicialización similares

### Identificar

**Inicializar**

Puedes identificar ambos revisando las constantes. Nota que sha\_init tiene 1 constante que MD5 no tiene:

![](<../../.gitbook/assets/image (385).png>)

**Transformación MD5**

Nota el uso de más constantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Más pequeño y eficiente ya que su función es encontrar cambios accidentales en los datos
* Usa tablas de búsqueda (así que puedes identificar constantes)

### Identificar

Revisa **constantes de tablas de búsqueda**:

![](<../../.gitbook/assets/image (387).png>)

Un algoritmo hash CRC se ve así:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compresión)

### Características

* No hay constantes reconocibles
* Puedes intentar escribir el algoritmo en python y buscar cosas similares en línea

### Identificar

El gráfico es bastante grande:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Revisa **3 comparaciones para reconocerlo**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
