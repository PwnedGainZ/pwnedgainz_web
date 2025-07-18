---
{"dg-publish":true,"permalink":"/hacking/web/solicitudes-y-respuestas-http/","dgPassFrontmatter":true}
---


----------------

--------

## Solicitud HTTP

Comenzamos examinando el siguiente ejemplo HTTP request:

![raw_request](https://academy.hackthebox.com/storage/modules/35/raw_request.png)

La imagen de arriba muestra una petición HTTP GET a la URL:

- `http://inlanefreight.com/users/login.html`

La primera línea de cualquier solicitud HTTP contiene tres campos principales 'separados por espacios':

|**Campo**|**Ejemplo**|**Descripción**|
|---|---|---|
|`Method`|`GET`|El método HTTP o verbo, que especifica el tipo de acción a realizar.|
|`Path`|`/users/login.html`|El camino al recurso al que se accede. Este campo también se puede sufijar con una cadena de consulta (por ejemplo. `?username=user`).|
|`Version`|`HTTP/1.1`|El tercer y último campo se utiliza para denotar la versión HTTP.|

El siguiente conjunto de líneas contienen pares de valores de encabezado HTTP, como `Host`, `User-Agent`, `Cookie`, y muchas otras cabeceras posibles. Estas cabeceras se utilizan para especificar varios atributos de una solicitud. Las cabeceras se terminan con una nueva línea, que es necesaria para que el servidor valide la solicitud. Por último, una solicitud puede terminar con el órgano de solicitud y los datos.

**Nota:** HTTP versión 1.X envía solicitudes como texto claro, y utiliza un carácter de nueva línea para separar diferentes campos y diferentes solicitudes. HTTP versión 2.X, por otro lado, envía solicitudes como datos binarios en un formulario de diccionario.

---

## Respuesta HTTP

Una vez que el servidor procesa nuestra solicitud, envía su respuesta. El siguiente es un ejemplo de respuesta HTTP:

![raw_response](https://academy.hackthebox.com/storage/modules/35/raw_response.png)

La primera línea de una respuesta HTTP contiene dos campos separados por espacios. El primero es el `HTTP version`(e.g. `HTTP/1.1`), y el segundo denota el `HTTP response code`(e.g. `200 OK`).

Los códigos de respuesta se utilizan para determinar el estado de la solicitud, como se discutirá en una sección posterior. Después de la primera línea, la respuesta enumera sus cabeceras, similar a una petición HTTP. Tanto la solicitud como los encabezados de respuesta se discuten en la siguiente sección.

Finalmente, la respuesta puede terminar con un cuerpo de respuesta, que está separado por una nueva línea después de las cabeceras. El cuerpo de respuesta se define generalmente como `HTML`código. Sin embargo, también puede responder con otros tipos de código, como `JSON`, recursos del sitio web como imágenes, hojas de estilo o scripts, o incluso un documento como un documento PDF alojado en el servidor web.