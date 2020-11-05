## **Tarea 4 - Cifrado Asimétrico**              
### Criptografía y Seguridad en Redes (02-2020)
### Sebastián Ignacio Toro Severino 
---
Dentro de la carpeta principal se podrán encontrar varias carpetas que representan lo siguiente:

| Carpeta       | Descripción                                                                         |   |
|---------------|-------------------------------------------------------------------------------------|---|
| archivos_hash | Carpeta que contiene los archivos hash a ser crackeados.                            |   |
| diccionarios  | Carpeta que contiene los diccionarios para utilizar en el ataque.                   |   |
| exports       | Carpeta para almacenar los outputs con los resultados obtenidos de las ejecuciones (Formato predeterminado: **hash:pass**). |   |
| hashcat-6.1.1 | Carpeta contenedora del software Hashcat.                                           |   |
| plain_pwds | Carpeta que contiene los archivos con las contraseñas crackeadas para luego realizar el nuevo proceso de hash. | |

### Consideraciones importantes
---
* Para asegurar un correcto funcionamiento, ejecutar el archivo Python desde donde está ubicado y no mover o cambiar de nombre las carpetas que vienen por defecto.
* Las rutas solicitadas (**archivo hash**, **diccionario**) deben ser **rutas absolutas** (Ej: C:\Users\... o /home/...) y no relativas.
* Al momento de realizar la ejecución, no es necesario eliminar el archivo **hashcat.potfile** que almacena Hashcat al finalizar cada procesamiento, debido a que el código lo realiza automáticamente.

      try:
        # Se elimina el registro de la ejecución en .potfile en caso de existir previamente
        os.remove('hashcat.potfile')
      except:
        pass

      os.system(hashcat_cmd) # Se ejecuta el CMD correspondiente
      os.remove('hashcat.potfile') # Se elimina el registro de la ejecución en .potfile 

* Por defecto, el modo de ataque es 'Straight' (0).
* Para el paso de re-hashear las contraseñas crackeadas, se utiliza la librería bcrypt, la cual puede ser instalada de la siguiente forma:

        pip install bcrypt o pip3 install bcrypt
