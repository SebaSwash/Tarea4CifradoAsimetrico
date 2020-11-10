## **Tarea 4 - Cifrado Asimétrico**              
### Criptografía y Seguridad en Redes (02-2020)
### 11 de noviembre de 2020
### Sebastián Ignacio Toro Severino 
---
Dentro de la carpeta principal se podrán encontrar varias carpetas que representan lo siguiente:

| Carpeta       | Descripción                                                                         |   |
|---------------|-------------------------------------------------------------------------------------|---|
| archivos_hash | Carpeta que contiene los archivos hash a ser crackeados.                            |   |
| archivos_rehash | Carpeta que contiene los textos rehasheados con el algoritmo Bcrypt. | |
| cifrados_ecies  | Carpeta que contiene los archivos cifrados con ECIES a partir de los archivos rehasheados.                   |   |
| diccionarios  | Carpeta que contiene los diccionarios para utilizar en el ataque.                   |   |
| exports       | Carpeta para almacenar los outputs (passwords crackeadas) con los resultados obtenidos de las ejecuciones (formato en texto plano). |   |
| hashcat-6.1.1 | Carpeta contenedora del software Hashcat.                                           |   | 

### **Consideraciones importantes**
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

* Para el proceso de cifrado asimétrico, se utiliza la librería de ECIES (https://pypi.org/project/eciespy/), la cual puede ser instalada de la siguiente forma:

        pip install eciespy o pip3 install eciespy

* En las carpetas se encuentran los archivos generados al realizar los procedimientos solicitados. Al volver a ejecutar, estos son reemplazados, no así la base de datos SQLite, donde todo se va agregando al archivo.

* Dentro de la carpeta **cifrados_ecies** se podrá encontrar el archivo **ecies_decrypt_results.db**, que corresponde al archivo contenedor de la base de datos SQLite.

* Los procedimientos se realizan con el archivo **cracker**, mientras que el archivo **key_generator** funciona como servidor para la entrega de llave pública y descifra los mensajes cifrados con la llave pública anteriormente.

* El archivo **ecies_dec_export** contiene los mensajes descifrados por el servidor en la ejecución (los mismos que se almacenan en la base de datos, pero sin la relación con su correspondiente mensaje cifrado).

* En caso de querer transformar el archivo de la base de datos SQLite a formato XLSX (Excel), se recomienda la siguiente página: https://www.rebasedata.com/convert-sqlite-to-xlsx-online