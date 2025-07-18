---
{"dg-publish":true,"permalink":"/programacion-web/obfuscacion/java-script/","dgPassFrontmatter":true}
---


----------

-------

[JavaScript](https://en.wikipedia.org/wiki/JavaScript) es uno de los idiomas más usados del mundo. Se utiliza principalmente para el desarrollo web y el desarrollo móvil. `JavaScript`se utiliza generalmente en la parte delantera de una aplicación para ejecutar dentro de un navegador. Aún así, hay implementaciones de JavaScript final usado para desarrollar aplicaciones web enteras, como [NodeJS](https://nodejs.org/en/about/).

Mientras que `HTML`y `CSS`son principalmente los encargados de cómo se ve una página web, `JavaScript`habitualmente se utiliza para controlar cualquier funcionalidad que la portada de la página web final requiere. Sin `JavaScript`, una página web sería mayormente estática y no tendría mucha funcionalidad o elementos interactivos.

---

#### Ejemplo

Dentro del código fuente de la página, `JavaScript`código está cargado con el `<script>`tag, como sigue:

Código: html

```html
<script type="text/javascript">
..JavaScript code..
</script>
```

Una página web también puede cargar remoto `JavaScript`código con `src`y el enlace del script, como sigue:

Código: html

```html
<script src="./script.js"></script>
```

Un ejemplo de uso básico de `JavaScript`Dentro de una página web es la siguiente:

Código: javascript

```javascript
document.getElementById("button1").innerHTML = "Changed Text!";
```

El ejemplo anterior cambia el contenido de la `button1`Espectafo HTML. A partir de ahora, hay muchos más usos avanzados de `JavaScript`en una página web. Lo siguiente muestra un ejemplo de lo que antecede `JavaScript`código haría cuando se enlataba a un clic de botón:

Al igual que con HTML, hay muchos sitios disponibles en línea para experimentar con `JavaScript`. Un ejemplo es [JSFiddle](https://jsfiddle.net/) que se puede utilizar para probar `JavaScript`, `CSS`, y `HTML`y guardar fragmentos de código. `JavaScript`es un lenguaje avanzado, y su sintaxis no es tan simple como `HTML`o o `CSS`.

---

## Uso

La mayoría de las aplicaciones web comunes se basan en gran medida en `JavaScript`para conducir todas las funcionalidades necesarias en la página web, como actualizar la vista de la página web en tiempo real, actualizando dinámicamente el contenido en tiempo real, aceptando y procesando la entrada del usuario, y muchas otras funcionalidades potenciales.

`JavaScript`También se utiliza para automatizar procesos complejos y realizar solicitudes HTTP para interactuar con los componentes de back end y enviar y recuperar datos, a través de tecnologías como [Ajax](https://en.wikipedia.org/wiki/Ajax_(programming)).

Además de la automatización, `JavaScript`también se utiliza a menudo junto a `CSS`, como se mencionó anteriormente, para impulsar animaciones avanzadas que no serían posibles con `CSS`solo. Cada vez que visitamos una página web interactiva y dinámica que utiliza muchas animaciones avanzadas y visualmente atractivas, estamos viendo el resultado de la web activa `JavaScript`código que se ejecuta en nuestro navegador.

Todos los navegadores web modernos están equipados con `JavaScript`motores que pueden ejecutar `JavaScript`código en el lado del cliente sin depender del servidor web de extremo posterior para actualizar la página. Esto hace el uso de `JavaScript`una manera muy rápida de lograr un gran número de procesos rápidamente.

---

## Marcos

A medida que las aplicaciones web se adelanzan, puede ser ineficiente usar puro `JavaScript`para desarrollar toda una aplicación web desde cero. Es por eso que una multitud de `JavaScript`se han introducido marcos para mejorar la experiencia de desarrollo de aplicaciones en la web.

Estas plataformas introducen bibliotecas que hacen muy simple recrear funcionalidades avanzadas, como el inicio de sesión de los usuarios y el registro de usuarios, e introducen nuevas tecnologías basadas en las existentes, como el uso de cambios dinámicos `HTML`código, en lugar de usar estático `HTML`código.

Estas plataformas utilizan `JavaScript`como su lenguaje de programación o la aplicación de `JavaScript`que compila su código en `JavaScript`código.

Algunos de los extremos delanteros más comunes `JavaScript`marcos son:

- [Angular](https://www.w3schools.com/angular/angular_intro.asp)
- [Reacto](https://www.w3schools.com/react/react_intro.asp)
- [Vue](https://www.w3schools.com/whatis/whatis_vue.asp)
- [jQuery](https://www.w3schools.com/jquery/)