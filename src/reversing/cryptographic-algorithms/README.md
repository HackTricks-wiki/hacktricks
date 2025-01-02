# Algoritmos Criptográficos/De Compresión

## Algoritmos Criptográficos/De Compresión

{{#include ../../banners/hacktricks-training.md}}

## Identificación de Algoritmos

Si terminas en un código **usando desplazamientos a la derecha e izquierda, xors y varias operaciones aritméticas** es muy posible que sea la implementación de un **algoritmo criptográfico**. Aquí se mostrarán algunas formas de **identificar el algoritmo que se está utilizando sin necesidad de revertir cada paso**.

### Funciones de API

**CryptDeriveKey**

Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** verificando el valor del segundo parámetro:

![](<../../images/image (375) (1) (1) (1) (1).png>)

Consulta aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime y descomprime un búfer de datos dado.

**CryptAcquireContext**

De [la documentación](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La función **CryptAcquireContext** se utiliza para adquirir un identificador a un contenedor de claves particular dentro de un proveedor de servicios criptográficos (CSP) particular. **Este identificador devuelto se utiliza en llamadas a funciones de CryptoAPI** que utilizan el CSP seleccionado.

**CryptCreateHash**

Inicia el hashing de un flujo de datos. Si se utiliza esta función, puedes encontrar qué **algoritmo se está utilizando** verificando el valor del segundo parámetro:

![](<../../images/image (376).png>)

\
Consulta aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de código

A veces es realmente fácil identificar un algoritmo gracias al hecho de que necesita usar un valor especial y único.

![](<../../images/image (370).png>)

Si buscas la primera constante en Google, esto es lo que obtienes:

![](<../../images/image (371).png>)

Por lo tanto, puedes asumir que la función decompilada es un **calculador de sha256.**\
Puedes buscar cualquiera de las otras constantes y probablemente obtendrás el mismo resultado.

### información de datos

Si el código no tiene ninguna constante significativa, puede estar **cargando información de la sección .data**.\
Puedes acceder a esos datos, **agrupar el primer dword** y buscarlo en Google como hemos hecho en la sección anterior:

![](<../../images/image (372).png>)

En este caso, si buscas **0xA56363C6** puedes encontrar que está relacionado con las **tablas del algoritmo AES**.

## RC4 **(Criptografía Simétrica)**

### Características

Está compuesto por 3 partes principales:

- **Etapa de inicialización/**: Crea una **tabla de valores de 0x00 a 0xFF** (256 bytes en total, 0x100). Esta tabla se llama comúnmente **Caja de Sustitución** (o SBox).
- **Etapa de mezcla**: **Recorrerá la tabla** creada anteriormente (bucle de 0x100 iteraciones, nuevamente) modificando cada valor con bytes **semi-aleatorios**. Para crear estos bytes semi-aleatorios, se utiliza la **clave RC4**. Las **claves RC4** pueden tener **entre 1 y 256 bytes de longitud**, sin embargo, generalmente se recomienda que sea superior a 5 bytes. Comúnmente, las claves RC4 tienen 16 bytes de longitud.
- **Etapa XOR**: Finalmente, el texto plano o el texto cifrado se **XORea con los valores creados anteriormente**. La función para cifrar y descifrar es la misma. Para esto, se realizará un **bucle a través de los 256 bytes creados** tantas veces como sea necesario. Esto generalmente se reconoce en un código decompilado con un **%256 (mod 256)**.

> [!NOTE]
> **Para identificar un RC4 en un código desensamblado/decompilado, puedes buscar 2 bucles de tamaño 0x100 (con el uso de una clave) y luego un XOR de los datos de entrada con los 256 valores creados anteriormente en los 2 bucles, probablemente usando un %256 (mod 256)**

### **Etapa de Inicialización/Caja de Sustitución:** (Nota el número 256 usado como contador y cómo se escribe un 0 en cada lugar de los 256 caracteres)

![](<../../images/image (377).png>)

### **Etapa de Mezcla:**

![](<../../images/image (378).png>)

### **Etapa XOR:**

![](<../../images/image (379).png>)

## **AES (Criptografía Simétrica)**

### **Características**

- Uso de **cajas de sustitución y tablas de búsqueda**
- Es posible **distinguir AES gracias al uso de valores específicos de tablas de búsqueda** (constantes). _Nota que la **constante** puede ser **almacenada** en el binario **o creada** _**dinámicamente**._
- La **clave de cifrado** debe ser **divisible** por **16** (generalmente 32B) y generalmente se utiliza un **IV** de 16B.

### Constantes SBox

![](<../../images/image (380).png>)

## Serpent **(Criptografía Simétrica)**

### Características

- Es raro encontrar malware que lo use, pero hay ejemplos (Ursnif)
- Simple de determinar si un algoritmo es Serpent o no basado en su longitud (función extremadamente larga)

### Identificación

En la siguiente imagen, nota cómo se utiliza la constante **0x9E3779B9** (nota que esta constante también es utilizada por otros algoritmos criptográficos como **TEA** -Tiny Encryption Algorithm).\
También nota el **tamaño del bucle** (**132**) y el **número de operaciones XOR** en las instrucciones de **desensamblado** y en el **ejemplo de código**:

![](<../../images/image (381).png>)

Como se mencionó anteriormente, este código puede visualizarse dentro de cualquier decompilador como una **función muy larga** ya que **no hay saltos** dentro de ella. El código decompilado puede verse como el siguiente:

![](<../../images/image (382).png>)

Por lo tanto, es posible identificar este algoritmo verificando el **número mágico** y los **XORs iniciales**, viendo una **función muy larga** y **comparando** algunas **instrucciones** de la función larga **con una implementación** (como el desplazamiento a la izquierda por 7 y la rotación a la izquierda por 22).

## RSA **(Criptografía Asimétrica)**

### Características

- Más complejo que los algoritmos simétricos
- ¡No hay constantes! (las implementaciones personalizadas son difíciles de determinar)
- KANAL (un analizador criptográfico) no logra mostrar pistas sobre RSA ya que se basa en constantes.

### Identificación por comparaciones

![](<../../images/image (383).png>)

- En la línea 11 (izquierda) hay un `+7) >> 3` que es el mismo que en la línea 35 (derecha): `+7) / 8`
- La línea 12 (izquierda) está verificando si `modulus_len < 0x040` y en la línea 36 (derecha) está verificando si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

- 3 funciones: Init, Update, Final
- Funciones de inicialización similares

### Identificar

**Init**

Puedes identificar ambos verificando las constantes. Nota que sha_init tiene 1 constante que MD5 no tiene:

![](<../../images/image (385).png>)

**Transformación MD5**

Nota el uso de más constantes

![](<../../images/image (253) (1) (1) (1).png>)

## CRC (hash)

- Más pequeño y eficiente ya que su función es encontrar cambios accidentales en los datos
- Utiliza tablas de búsqueda (por lo que puedes identificar constantes)

### Identificar

Verifica **constantes de tablas de búsqueda**:

![](<../../images/image (387).png>)

Un algoritmo de hash CRC se ve como:

![](<../../images/image (386).png>)

## APLib (Compresión)

### Características

- Constantes no reconocibles
- Puedes intentar escribir el algoritmo en python y buscar cosas similares en línea

### Identificar

El gráfico es bastante grande:

![](<../../images/image (207) (2) (1).png>)

Verifica **3 comparaciones para reconocerlo**:

![](<../../images/image (384).png>)

{{#include ../../banners/hacktricks-training.md}}
