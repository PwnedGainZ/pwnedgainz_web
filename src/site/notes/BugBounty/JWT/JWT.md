---
{"dg-publish":true,"permalink":"/bug-bounty/jwt/jwt/"}
---


--------------------

-------------------------

## Qué son JWTs?

Los tokens web JSON (JWT) son un formato estandarizado para enviar datos JSON firmados criográficamente entre sistemas. En teoría pueden contener cualquier tipo de datos, pero se utilizan más comúnmente para enviar información ("reclamaciones") sobre los usuarios como parte de los mecanismos de autenticación, manejo de sesiones y control de acceso.

A diferencia de los clásicos fichas de sesión, todos los datos que necesita un servidor se almacenan en el propio cliente dentro del propio JWT. Esto hace que JWTs sea una opción popular para sitios web altamente distribuidos donde los usuarios necesitan interactuar sin problemas con múltiples servidores de back-end.


### JWT formato

Un JWT consta de 3 partes: una cabecera, una carga útil y una firma. Cada uno está separado por un punto, como se muestra en el siguiente ejemplo:

`eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA`

La cabecera y las partes de carga útil de un JWT son sólo objetos JSON codificados base64url. La cabecera contiene metadatos sobre el silbido en sí mismo, mientras que la carga útil contiene las "reclamos" reales sobre el usuario. Por ejemplo, puede decodificar la carga útil de la muestra anterior para revelar las siguientes reclamaciones:

`{ "iss": "portswigger", "exp": 1648037164, "name": "Carlos Montoya", "sub": "carlos", "role": "blog_author", "email": "carlos@carlos-montoya.net", "iat": 1516239022 }`

En la mayoría de los casos, estos datos pueden ser fácilmente leídos o modificados por cualquier persona con acceso al símbolo. Por lo tanto, la seguridad de cualquier mecanismo basado en JWT depende en gran medida de la firma criptográfica.

### Firma de JWT

El servidor que emite el token típicamente genera la firma hashing la cabecera y la carga útil. En algunos casos, también cifran el hach hechón resultante. De cualquier manera, este proceso implica una clave secreta de firma. Este mecanismo proporciona una manera para que los servidores verifiquen que ninguno de los datos dentro del token ha sido manipulado desde que se emitió:

- Como la firma se deriva directamente del resto del símbolo, cambiar un solo byte de la cabecera o carga útil resulta en una firma desajustada.
    
- Sin conocer la clave secreta de firma del servidor, no debería ser posible generar la firma correcta para una cabecera o carga útil dada.




# Ataque

- En este ataque modificamos el contenido del token indicandole que somos el usuario administrador, para asi poder llegar a acceder al panel de administrator.

![Pasted image 20240713173002.png](/img/user/imgs/Pasted%20image%2020240713173002.png)


### Aceptando fichas sin firma

Entre otras cosas, el encabezado JWT contiene un `alg`parámetro. Esto le dice al servidor qué algoritmo se utilizó para firmar el token y, por lo tanto, qué algoritmo necesita usar al verificar la firma.

`{ "alg": "HS256", "typ": "JWT" }`

Esto es inherentemente defectuoso porque el servidor no tiene otra opción que confiar implícitamente en la entrada controlable del usuario desde el punto de ficha que, en este punto, no ha sido verificado en absoluto. En otras palabras, un atacante puede influir directamente en cómo el servidor comprueba si el símbolo es confiable.

Los JWT se pueden firmar usando una gama de algoritmos diferentes, pero también se pueden dejar sin firmar. En este caso, el `alg`parámetro está listo para `none`, que indica un llamado "JWT inseseable". Debido a los peligros obvios de esto, los servidores suelen rechazar fichas sin firma. Sin embargo, como este tipo de filtrado se basa en el análisis de cuerdas, a veces se pueden eludir estos filtros utilizando técnicas clásicas de ofuscación, como la capitalización mixta y las codificaciones inesperadas.


![Pasted image 20240714003736.png](/img/user/imgs/Pasted%20image%2020240714003736.png)
