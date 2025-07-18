---
{"dg-publish":true,"permalink":"/soc-analyst/incident-handling-process/","dgPassFrontmatter":true}
---


#Cyber-Kill #SOC

### ¿Qué Es El Cyber Kill Chain?

Este **ciclo de vida** se describe cómo los ataques se manifiestan. La comprensión de este **ciclo de vida** nos **proporcionará información valiosa** en la `red`, un `atacante` que es y lo que se puede tener acceso durante la fase de investigación de un incidente.


El `cyber kill chain` consta de siete (7) de diferentes etapas, como se muestra en la siguiente imagen:

![Pasted image 20250529175608.png](/img/user/imgs/Pasted%20image%2020250529175608.png)


##### Fase de Reconocimiento (**Recon**):

- Objetivo: Recopilar información sobre el objetivo para planificar ataques.

- Métodos: 
	1. Pasivo: Consultar fuentes públicas (`LinkedIn, Instagram, páginas web de la empresa, ofertas de trabajo`).

	2. Activo: **Escanear** **aplicaciones web** y direcciones IP de la organización.
---
- Datos útiles:
1. Tecnologías usadas (`antivirus, sistemas operativos, redes`).
2. Estructura organizacional (`empleados, socios`).
3. Importancia: La información obtenida **se usa en todas las etapas del ataque**.

Es la **fase donde el atacante estudia a su víctima para encontrar puntos débiles**.

---
---
##### Fase de Weaponización (**Arsenalización**)

- Objetivo: Crear malware indetectable para ganar acceso inicial a sistemas objetivo.
---
- Proceso: **Desarrollar o adaptar malware** ligero y evasivo (`evita antivirus/EDR`).
---
- Preparación: Se usa información previa (`reconocimiento`) para **evadir defensas específicas** (`antivirus/EDR detectados`).
---
- Características clave del malware: **Acceso remoto persistente** (`sobrevive reinicios`). También permite descargar herramientas adicionales después del compromiso.


---
---

##### Fase de Entrega (**Delivery**)

En esta etapa, el atacante envía el malware o exploit a la víctima. Los métodos más usados son:

- Phishing por correo: Adjuntan archivos maliciosos (`Word, PDF, etc.`) imitando sitios web reales para robar credenciales.
---
- Ingeniería social: Llamadas (`vishing`) para engañar a la víctima y que ejecute el malware. **USB infectados** dejados en lugares estratégicos.
---
- Páginas web fraudulentas: Copian sitios legítimos para distribuir malware o engañar al usuario.

El objetivo es que la víctima interactúe con el `payload` (`ej: haciendo clic en un archivo o enlace`). Los formatos comunes son *.exe, .js, .bat* o **documentos con macros maliciosas.**

---
---
##### Fase de explotación (**exploitation**)

En esta tapa es el momento cuando un **exploit** o una entrega de carga se activa. Durante la etapa de explotación de la `cyber kill chain`, *el atacante normalmente intenta ejecutar código* en el sistema de destino con el fin de **obtener acceso o control**.


##### Fase de instalación (**installation**)

En el **installation** la etapa inicial de stager es ejecutado y se ejecutan en la máquina comprometida. Como ya hemos comentado, la etapa de instalación puede llevarse a cabo de varias maneras, dependiendo del atacante objetivos y la naturaleza del compromiso. 