# ┌─────────────────────────────────────────────┐
# │ Tarea 4 - Cifrado Asimétrico                │
# │ Criptografía y Seguridad en Redes (02-2020) │
# │ Sebastián Ignacio Toro Severino             │
# └─────────────────────────────────────────────┘

import os, time, bcrypt
from os import listdir

# Ruta actual
CURRENT_PATH = os.getcwd()
# Ruta de exportación para resultados de hashcat
EXPORT_PATH = os.path.join(CURRENT_PATH,'exports')
# Ruta de Hashcat
HASHCAT_PATH = os.path.join(CURRENT_PATH,'hashcat-6.1.1')
# Ruta de passwords en texto plano
PLAIN_PWD_PATH = os.path.join(CURRENT_PATH,'plain_pwds')
# Ruta de archivos hash
HASHFILES_PATH = os.path.join(CURRENT_PATH,'archivos_hash')
# Ruta de diccionarios
DICTFILES_PATH = os.path.join(CURRENT_PATH,'diccionarios')
# Ruta de archivos rehasheados
REHASHFILES_PATH = os.path.join(CURRENT_PATH,'archivos_rehash')

# Selección de archivo a crackear y diccionario a utilizar
def config_options():
  clear_screen()
  print('''
  ┌──────────────────────────────────────────────┐
  │ Configuraciones - Selección de archivo hash  │
  ├──────────────────────────────────────────────┤
  │ [1] Seleccionar de la lista de archivos hash │
  │ [2] Especificar otra ruta                    │
  └──────────────────────────────────────────────┘''')
  op = input('> ')

  while op not in ['1','2']:
    op = input('> ')

  if op == '1':
    hash_file_list = [f for f in listdir(HASHFILES_PATH) if os.path.isfile(os.path.join(HASHFILES_PATH, f))]
    print('')
    for i in range(len(hash_file_list)):
      print('['+str(i)+'] '+str(hash_file_list[i])+'')
    print('')
    file_index = input('[Posición del archivo] > ')

    try:
      # En caso de que se haya obtenido correctamente el nombre del archivo
      # según el index, se establece su ruta
      filename = hash_file_list[int(file_index)]
      file_path = os.path.join(HASHFILES_PATH, filename)

    except Exception as err:
      print('[Error] Se ha producido el siguiente error:')
      print(str(err))
      return

  else:
    file_path = input('Ingrese la ruta del archivo a crackear: ')

    while os.path.exists(file_path) is not True:
      print('[Error] La ruta del archivo no existe.')
      file_path = input('Ingrese la ruta del archivo a crackear: ')
  
  print('''
  ┌─────────────────────────────────────────────┐
  │ Configuraciones - Selección de diccionario  │
  ├─────────────────────────────────────────────┤
  │ [1] Seleccionar de la lista de diccionarios │
  │ [2] Especificar otra ruta                   │
  └─────────────────────────────────────────────┘''')
  op = input('> ')

  while op not in ['1','2']:
    op = input('> ')
  
  if op == '1':
    dict_file_list = [f for f in listdir(DICTFILES_PATH) if os.path.isfile(os.path.join(DICTFILES_PATH, f))]
    print('')
    for i in range(len(dict_file_list)):
      print('['+str(i)+'] '+str(dict_file_list[i])+'')
    print('')
    dict_index = input('[Posición del archivo] > ')

    try:
      # En caso de que se haya obtenido correctamente el nombre del diccionario
      # según el index, se establece su ruta
      filename = dict_file_list[int(dict_index)]
      dict_path = os.path.join(DICTFILES_PATH, filename)

    except Exception as err:
      print('[Error] Se ha producido el siguiente error:')
      print(str(err))
      return
  
  elif op == '2':
    dict_path = input('Ingrese la ruta del diccionario a utilizar: ')

    while os.path.exists(dict_path) is not True:
      print('[Error] La ruta del diccionario no existe.')
      dict_path = input('Ingrese la ruta del diccionario a utilizar: ')
  
  print('')
  export_filename = input('Ingrese el nombre del archivo de exportación de resultados: ')
  
  while len(export_filename) == 0:
    print('[Error] No se ha especificado un nombre de archivo.')
    export_filename = input('Ingrese el nombre del archivo de exportación de resultados: ')

  print('''  
  ┌──────────────────────────────┐
  │ Configuraciones establecidas │
  └──────────────────────────────┘''')
  print('- Ruta del archivo hash seleccionado: '+str(file_path))
  print('- Ruta del diccionario seleccionado: '+str(dict_path))
  print('- Nombre del archivo de exportación de resultados: '+str(export_filename))

  continue_op = input('¿Desea continuar? [S/N]: ')
  while continue_op.lower() != 's' and continue_op.lower() != 'n':
    continue_op = input('¿Desea continuar? [S/N]: ')
  
  # En caso de que no se confirmen las configuraciones, se devuelve al menú
  if continue_op.lower() != 's':
    return

  # Se accede a la función de crackeo para configuración y ejecución del CMD
  cracker(file_path,dict_path,export_filename) 

# Crackeo del archivo según el diccionario especificado
def cracker(file_path,dict_path,export_filename):
  try:
    hashcat_cmd = 'hashcat.exe' # CMD principal de hashcat
    
    if os.name != 'nt':
      # Posix / Darwin / ...
      hashcat_cmd = hashcat_cmd.replace('\\','/') # Se modifica el formato para acceder a la carpeta de Hashcat
    
    exportfile_path = str(os.path.join(EXPORT_PATH,export_filename)) # Ubicación para el output

    # En caso de que exista el archivo de output con el nombre seleccionado, se elimina
    if os.path.exists(exportfile_path):
      os.remove(exportfile_path)
    
    # --- Configuraciones para el CMD de Hashcat ---
    # Modo de ataque predefinido como 0 o 'Straight'
    hash_type = input('Seleccione el ID del hash a utilizar (Hash Mode - https://hashcat.net/wiki/doku.php?id=example_hashes): ')

    while hash_type.isnumeric() is not True:
      hash_type = input('Seleccione el ID del hash a utilizar (Hash Mode - https://hashcat.net/wiki/doku.php?id=example_hashes): ')

    # Se agrega el hash type al comando a ejecutar
    hashcat_cmd += ' -m'+str(hash_type)
    hashcat_cmd += ' -a0 '+file_path+' '+dict_path+' --outfile='+exportfile_path
    
    os.chdir(HASHCAT_PATH) # Se cambia a la carpeta de hashcat para ejecutar el CMD
    
    try:
      # Se elimina el registro de la ejecución en .potfile en caso de existir previamente
      os.remove('hashcat.potfile')
    except:
      pass

    os.system(hashcat_cmd) # Se ejecuta el CMD correspondiente
    os.remove('hashcat.potfile') # Se elimina el registro de la ejecución en .potfile
 
    # En caso de que haya resultado, se revisa el archvio exportado para
    # obtener los textos planos
    plain_pwds_list_path = fetch_plain_text(exportfile_path)

    # Una vez guardado los archivos con las passwords en texto plano
    # se revisa si se desea realizar el proceso de re-hash
    print('')
    rehash_op = input('¿Desea realizar el proceso de rehash? [S/N]: ')

    while rehash_op.lower() != 's' and rehash_op.lower() != 'n':
      rehash_op = input('¿Desea realizar el proceso de rehash? [S/N]: ')
    
    if rehash_op.lower() != 's':
      return
    
    # Se realiza el proceso de rehash con el archivo exportado
    hash_generator(plain_pwds_list_path)

  except Exception as err:
    print('[Error] Se ha producido el siguiente error: ')
    print(str(err))

def fetch_plain_text(file_path):
  try:
    output_file = open(file_path,'r') # Archivo output de Hashcat
    print('')
    plain_filename = input('Ingrese el nombre del archivo para almacenar los textos planos: ')
    # Se abre el archivo para almacenar las passwords en texto plano (w mode -> overwrite)
    plain_file = open(os.path.join(PLAIN_PWD_PATH,plain_filename),'w')

    for line in output_file:
      line = line.strip()
      plain_text = tuple(line.split(':',1))[1] # Tupla (hash,texto_plano)
      plain_file.write(plain_text+'\n')
    
    plain_file.close() # Se cierra el archivo con las contraseñas en texto plano 
    print('* * Archivo con passwords en texto plano en: '+str(os.path.join(PLAIN_PWD_PATH,plain_filename)))

    return os.path.join(PLAIN_PWD_PATH,plain_filename)

  except Exception as err:
    print('[Error] Se ha producido el siguiente error: ')
    print(str(err))

def view_files():
  return

def hash_generator(plain_filepath=None):

  print('''
  ┌────────────────────────────────────────┐
  │ Rehash Bcrypt para password crackeadas │
  └────────────────────────────────────────┘''')

  salt = bcrypt.gensalt() # Generación de salt random para Bcrypt
  
  if plain_filepath:
    try:
      plain_pwd_file = open(plain_filepath,'r')
      # Se crea un nuevo archivo para almacenar las contraseñas rehasheadas
      rehash_filename = input('Ingrese el nombre del archivo para almacenar los nuevos hash: ')
      rehash_file_path = os.path.join(REHASHFILES_PATH,rehash_filename)
      rehash_file = open(rehash_file_path,'w')

      # Se recorren las contraseñas planas y se vuelve a hashear con Bcrypt
      hash_start_time = time.time() # Se obtiene el tiempo inicial del proceso
      password_count = 0 # Cantidad de contraseñas a hashear
      for line in plain_pwd_file:
        # Se genera el hash Bcrypt codificado en UTF-8 a partir de la contraseña en texto plano
        line = line.strip()
        pwd_hash = bcrypt.hashpw(line.encode(encoding='UTF-8'),salt)
        # Se almacena el valor decodificado (UTF-8) en el nuevo archivo 
        rehash_file.write(pwd_hash.decode('UTF-8')+'\n')
        password_count += 1

      hash_end_time = time.time() # Se obtiene el tiempo final del proceso

      print('................................................................................')
      print('* Se ha aplicado correctamente el algoritmo hash sobre las passwords.')
      print('- Cantidad de password hasheadas: '+str(password_count))
      print('- Tiempo de procesamiento: '+str(hash_end_time-hash_start_time))
      print('- Ruta del archivo exportado: '+str(rehash_file_path))
      print('................................................................................')
      print('')

      input('Presione ENTER para volver al menú.')

    except Exception as err:
      print('[Error] Se ha producido el siguiente error: ')
      print(str(err))

  return


def main_menu():
  print('''
  ┌──────────────────────────────────────────────────────────────────┐
  │ Tarea 4 - Cifrado Asimétrico - Criptografía y Seguridad en Redes │
  ├──────────────────────────────────────────────────────────────────┤
  │ [1] Crackear archivos                                            │
  │ [2] Ver archivos                                                 │
  │ [3] Generar hash sobre archivos                                  │
  │ [4] Salir                                                        │
  └──────────────────────────────────────────────────────────────────┘''')

def clear_screen():
  if os.name == 'nt':
    os.system('cls')
  else:
    os.system('clear')

if __name__ == '__main__':
  clear_screen()

  try:
    while True:
      clear_screen()
      main_menu()
      op = input('> ')

      while op not in ['1','2','3','4']:
        op = input('> ')
      
      if op == '1':
        config_options()
      elif op == '2':
        view_files()
      elif op == '3':
        hash_generator()
      elif op == '4':
        exit()
  
  except KeyboardInterrupt:
    exit()