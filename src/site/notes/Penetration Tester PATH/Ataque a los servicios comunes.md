---
{"dg-publish":true,"permalink":"/penetration-tester-path/ataque-a-los-servicios-comunes/","dgPassFrontmatter":true}
---


### Interacción con los servicios comunes

Las vulnerabilidades suelen ser descubiertas por personas que utilizan y entiende la tecnología un protocolo o un servicio. A medida que evolucionemos en este campo, encontraremos diferentes servicios con los que interactuar, y necesitaremos evolucionar y aprender nuevas tecnologías constantemente.

Para tener éxito en el ataque a un servicio, necesitamos `conocer su propósito`, cómo interactuar con él, qué herramientas podemos usar y qué podemos hacer con él. Esta sección se centrará en los servicios comunes y en cómo podemos interactuar con ellos.

## Servicios de uso compartido de archivos

Un servicio de uso compartido de archivos es un tipo de servicio que proporciona, media y supervisa la transferencia de archivos informáticos. Hace años, las empresas solían utilizar sólo servicios internos para compartir archivos, como `SMB, NFS, FTP, TFTP, SFTP`, pero a medida que crece la adopción de la nube, la mayoría de las empresas ahora también tiene servicios en la nube de terceros como `Dropbox, Google Drive, OneDrive, SharePoint` u otras formas de almacenamiento de archivos como `AWS S3, Azure Blog Storage o Google Cloud Storage`. Estaremos expuestos a una mezcal de servicios de intercambio de archivos internos y externos, y necesitamos estar familiarizados con ellos.


## Bloque de mensajes del servidor (SMB)

SMB se usa comúnmente en redes de Windows y, a menudo, encontraremos carpetas compartidas en una red de Windows. Podemos interactuar con SMB mediante la `GUI`, la `CLI` o las herramientas. Vamos a cubrir algunas formas comunes de interactuar con SMB usando **Windows** y **Linux**.

##### Windows

Hay diferentes formas en las que podemos interactuar con una carpeta compartida usando Windows, y exploraremos un par de ellas. En la `GUI` de Windows, podemos presionar `[WINKEY] + [R]` para abrir el cuadro de diálogo Ejecutar y escribir la ubicación del recurso compartido de archivos, por ejemplo: `\\192.168.220.129\Finance\`

![Pasted image 20250618182023.png](/img/user/imgs/Pasted%20image%2020250618182023.png)

Supongamos que la carpeta compartida permite la autenticación anónima, o que estamos autenticados con un usuario que tiene privilegios sobre esta carpeta compartida. En ese caso, no recibiremos ningún tipo de solicitud de autenticación y mostrará el contenido de la carpeta compartida.

![Pasted image 20250618182148.png](/img/user/imgs/Pasted%20image%2020250618182148.png)

Si no tenemos acceso, recibiremos una solicitud de autenticación.

![Pasted image 20250618182216.png](/img/user/imgs/Pasted%20image%2020250618182216.png)

Windows tiene dos Shells de línea de comandos: el Command Prompt (`CMD`) y el `Powershell`. El comando dir muestra una lista de los archivos y subdirectorios de un directorio.

![Pasted image 20250618182433.png](/img/user/imgs/Pasted%20image%2020250618182433.png)

El comando `net use` conecta o desconecta un equipo de un recurso compartido o muestra información sobre las conexiones del equipo.  El parámetro `n` es para conectarnos a un recurso compartido de archivos.

![Pasted image 20250618182546.png](/img/user/imgs/Pasted%20image%2020250618182546.png)

También podemos proporcionar un `username y un password` para autenticarse en el recurso compartido.

![Pasted image 20250618182632.png](/img/user/imgs/Pasted%20image%2020250618182632.png)

Con la carpeta compartida asignada podemos ejecutar comandos de **Windows** *como si esta carpeta compartida estuviera en nuestro ordenador local*. Averigüemos cuántos archivos contienen la carpeta compartida y sus subdirectorios :)

![Pasted image 20250618182917.png](/img/user/imgs/Pasted%20image%2020250618182917.png)


| Sintaxis |     | Descripción                                                                   |
| -------- | --- | ----------------------------------------------------------------------------- |
| dir      |     | Aplicación                                                                    |
| n:       |     | Directorio o unidad para buscar                                               |
| /a-d     |     | `/a` es el atributo y `-d` significa no directorios                           |
| /s       |     | Muestra los archivos de un directorio especificado y todos los subdirectorios |
| /b       |     | Utiliza formato naked (sin información de encabezado ni resumen)              |

![Pasted image 20250618183307.png](/img/user/imgs/Pasted%20image%2020250618183307.png)

---


## Windows Powershell

Powershell se hizo para ampliar las capacidades del Shell de comandos para ejecutar comandos de PowerShell llamados `cmdslets`. Los `cmdlets` son similares a los comandos de Windows, pero proporcionan un lenguaje de scripting más extensible.

![Pasted image 20250618183443.png](/img/user/imgs/Pasted%20image%2020250618183443.png)
Para proporcionar un nombre de usuario y un password con Powershell, debemos crear un `objeto PSCredential`. Ofrece una forma centralizada de adminsitrar nombres de usuario, passwords y credenciales.

![Pasted image 20250619071315.png](/img/user/imgs/Pasted%20image%2020250619071315.png)

##### Windows Powershell - GCI

![Pasted image 20250619071415.png](/img/user/imgs/Pasted%20image%2020250619071415.png)

Podemos usar el inmueble `-Include` para buscar elementos específicos del directorio especificado por el parámetro Path.

![Pasted image 20250619071501.png](/img/user/imgs/Pasted%20image%2020250619071501.png)

##### Windows Powershell: select-string

![Pasted image 20250619071550.png](/img/user/imgs/Pasted%20image%2020250619071550.png)

`CLI` permite que las operaciones de TI automaticen tareas rutinarias como la administración de cuentas de usuario, copias de seguridad nocturnas o interacción con muchos archivos. Podemos realizar operaciones de manera más eficiente mediante el uso de *scripts* que la interfaz de usuario o la `GUI`.

---
## Linux

Las máquinas Linux (UNIX) también se pueden usar para examinar y montar recursos compartidos SMB. Tenga en cuenta que esto se puede hacer tanto si el servidor de destino es una máquina Windows como un servidor Samba. Aunque algunas distros de Linux admiten una interfaz gráfica de usuario, nos centraremos en las utilidades y herramientas de línea de comandos de Linux para interactuar con el SMB. 

![Pasted image 20250619071934.png](/img/user/imgs/Pasted%20image%2020250619071934.png)
`credentials=/path/credentialfile`

El fichero `credentialfile` tiene que estar estructurado de la siguiente manera:

##### Archivo de credenciales

``` txt
username=plaintext
password=Password123
domina=.
```

Necesitamos instalar `cifs-utils` para conectarse a una carpeta compartida SMB. Para instalarlo podemos ejecutarlo desde línea de comandos `sudo apt install cifs-utils`.

Una vez que se monta una carpeta compartida, puede usar herramientas comunes de Linux como `find` o `grep` para interactuar con la estructura de archivos. Ahora busquemos un nombre de archivo que contenga la cadena `cred`:

## Linux - find

![Pasted image 20250619075015.png](/img/user/imgs/Pasted%20image%2020250619075015.png)

A continuación, busquemos los archivos que contienen la cadena `cred`:

![Pasted image 20250619075042.png](/img/user/imgs/Pasted%20image%2020250619075042.png)


## Other services

Existen otros servicios de compartición de archivos como `FTP, TFTP, NFS` que podemos adjuntar (montar) utilizando diferentes herramientas y comandos. Sin embargo, una vez que montamos un servicio de compartición de archivos, debemos entender que podemos utilizar las herramientas disponibles en Linux o Windows para interactuar con archivos y directorios. A medida que descubramos nuevos servicios de intercambio de archivos, tendremos que investigar cómo funcionan y qué herramientas podemos utilizar para interactuar con ellos.

## Email

Por lo general, necesitamos dos protocolos para enviar y recibir mensajes, uno para enviar y otro para recibir. `El protocolo simple de transferencia de correo (SMTP)` es un protocolo de entrega de correo electrónico utilizado para enviar correo a través de Internet. Del mismo modo, se debe utilizar un protocolo de soporte para recuperar un correo electrónico de un servicio. Hay dos protocolos principales que podemos usar: `POP3 && IMAP`.

Podemos usar un cliente de correo llamado `Evolution`, el administrador oficial de información personal, y un cliente de correo para el entorno de escritorio *GNOME*. Podemos interactuar con un servidor de correo electrónico para enviar o recibir mensajes con un cliente de correo. 

## Linux - Install Evolution

![Pasted image 20250619080033.png](/img/user/imgs/Pasted%20image%2020250619080033.png)

Nota: Si aparece un error al iniciar `evolution` que indica "bwrap": No se puede crear el archivo en ...", usa este comando para iniciar evolution `export WEBKIT_FORCE_SANDBOX=0 && evolution`.

## Video - Connecting to IMAP and SMTP using Evolution

Podemos utilizar el nombre de dominio o la dirección IP del servidor de correo. Si el servidor utiliza SMTPS o IMAPS, necesitaremos el método de cifrado adecuado (TLS en un puerto dedicado o STARTTLS después de conectarse). Podemos usar el método `Check for Supported Types` en Autenticación para confirmar si el servidor es compatible con el método seleccionado.


![Pasted image 20250619080955.png](/img/user/imgs/Pasted%20image%2020250619080955.png)

![Pasted image 20250619081010.png](/img/user/imgs/Pasted%20image%2020250619081010.png)

Exploraremos las utilidades de línea de comandos y una aplicación GUI.

## Utilidades de línea de comandos

### MSSQL
Para interactuar con MSSQL (Microsoft SQL Server) con Linux podemos usar `sqsh` o `sqlcmd` si se está utilizando Windows. `Sqsh` es mucho más que un mensaje amistoso. Está diseñado para proporcionar gran parte de la funcionalidad proporcionada por un shell de comandos, como variables, aliasing, redirección, tuberías, conexión a tierra, control de trabajos, historial, sustitución de comandos y configuración dinámica. Podemos iniciar una sesión SQL interactiva de la siguiente manera:

![Pasted image 20250619081330.png](/img/user/imgs/Pasted%20image%2020250619081330.png)

---

## Herramientas para interactuar con los servicios comunes

![Pasted image 20250619081429.png](/img/user/imgs/Pasted%20image%2020250619081429.png)


### Solución de problemas generales

Dependiendo de la versión de Windows o Linux con la que estemos trabajando o a la que nos dirijamos, podemos encontrarnos con diferentes problemas al intentar conectarnos a un servicio.

Algunas razones por las que es posible que no tengamos acceso a un recurso:

![Pasted image 20250619081542.png](/img/user/imgs/Pasted%20image%2020250619081542.png)

