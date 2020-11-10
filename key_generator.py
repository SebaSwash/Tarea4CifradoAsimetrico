# ┌─────────────────────────────────────────────┐
# │ Tarea 4 - Cifrado Asimétrico                │
# │ Criptografía y Seguridad en Redes (02-2020) │
# │ Sebastián Ignacio Toro Severino             │
# └─────────────────────────────────────────────┘

# Código que actúa como servidor para envío de llave pública y descifrado de archivos
import os, socket, threading, pickle, sqlite3
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt

class Server:
  def __init__(self,host,port):
    self.host = host
    self.port = port
    self.sending_ecies_filepath = False # Flag para obtener en un ciclo el archivo
    self.db_filepath = os.path.join(os.getcwd(),'cifrados_ecies','ecies_decrypt_results.db') # Ruta de archivo sqlite (.db)

    self.db_connect() # Se conecta a la base de datos SQLite

    # Se crea la tabla Hashes en caso de que no exista
    try:
      sql_query = '''
        CREATE TABLE Hashes (
          ecies_enc_msg TEXT,
          ecies_dec_msg TEXT
        )
      '''
      self.cursor.execute(sql_query)
      self.db_conn.commit()
    
    except:
      pass

    self.db_conn.close()
    
    try:
      # Se intenta realizar la conexión según el host y puerto especificados
      self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      self.sock.bind((host,int(port)))
      self.sock.listen(5)
      print('* Servidor correctamente enlazado en '+str(self.host)+':'+str(self.port))

      # Se generan las llaves correspondientes
      self.ecies_key_generator()

    except Exception as err:
      print('[Error] Se ha producido el siguiente error:')
      print(str(err))
  
  def db_connect(self):
    # Conexión a la base de datos SQLite
    self.db_conn = sqlite3.connect(self.db_filepath)
    self.cursor = self.db_conn.cursor()
  
  def ecies_key_generator(self):
    # Se generan las llaves pública y privada utilizando ECIES
    self.private_key = generate_eth_key() # Genera una llave privada aleatoria
    self.private_key_hex = self.private_key.to_hex() # Transformación de la llave privada a hexadecimal
    self.public_key_hex = self.private_key.public_key.to_hex() # Obtención de llave pública (en hexadecimal) a partir de la llave privada

    print('')
    print('---------------------------------------------------------------------')
    print('Llave privada generada (hexadecimal): '+str(self.private_key_hex))
    print('Llave pública generada (hexadecimal): '+str(self.public_key_hex))
    print('---------------------------------------------------------------------')
    print('')

  def handler(self,connection,client_address):
    # Controlador de envío y recibo de datos con una conexión específica
    while True:
      data = connection.recv(4096) # Se obtienen datos desde el cliente específico

      if not data:
        break

      if self.sending_ecies_filepath:
        # Se obtiene la ruta del archivo cifrado con ECIES en el programa 1
        ecies_enc_filepath = data.decode('UTF-8')
        # Se abre un nuevo archivo para almacenar los mensajes decifrados con ECIES
        output_dec_file = open(os.path.join(os.getcwd(),'cifrados_ecies','ecies_dec_export'),'w')

        # Se abre el archivo cifrado con ECIES
        with open(ecies_enc_filepath,'r') as ecies_enc_file:
          for line in ecies_enc_file:
            # Se remueve el salto de línea
            ecies_msg = line.replace('\n','')
            
            # Se realiza el proceso de descifrado con la llave privada y se almacena en el archivo
            ecies_dec_msg = decrypt(self.private_key_hex,bytes.fromhex(ecies_msg)).decode('UTF-8')
            ecies_dec_msg = ecies_dec_msg.replace('\n','')

            # Se almacena el mensaje decifrado con ECIES en el archivo abierto
            output_dec_file.write(ecies_dec_msg+'\n')

            # Se almacena el mensaje decifrado con ECIES en la base de datos SQLite
            sql_query = '''
              INSERT INTO Hashes (ecies_enc_msg,ecies_dec_msg)
                VALUES (?,?)
            '''
            self.db_connect() # Se conecta a la base de datos SQLite
            self.cursor.execute(sql_query,(ecies_msg,ecies_dec_msg))
            self.db_conn.commit()
        
        # Se cierra el archivo de exportación de mensajes cifrados con ECIES
        output_dec_file.close()

        # Se cierra la conexión con la base de datos SQLite
        self.db_conn.close()
        # Se notifica al cliente sobre el registro en la base de datos
        connection.send('Los registros han sido almacenados correctamente en la base de datos.'.encode(encoding='UTF-8'))

        self.sending_ecies_filepath = False
        
        # Se cierra la conexión con el cliente
        connection.close()
        break

      data = pickle.loads(data) # Transforma el byte object a un objeto nuevamente
      print('* Recibido desde '+str(client_address[0])+':'+str(client_address[1])+': '+str(data))

      if data == 1:
        # Solicitud de llave pública
        print('Envío de llave pública a cliente desde '+str(client_address[0])+':'+str(client_address[1])+'')
        connection.send(self.public_key_hex.encode(encoding='UTF-8'))
      
      elif data == 2:
        # Señal para activar el ciclo de recibo de archivo
        self.sending_ecies_filepath = True
    
  def run(self):
    # Método para obtener conexiones al servidor
    while True:
      connection, client_address = self.sock.accept()
      print('* Conexión establecida con '+str(client_address[0])+':'+str(client_address[1]))
      client_thread = threading.Thread(target=self.handler,args=(connection,client_address))
      client_thread.daemon = True
      client_thread.start()

if __name__ == '__main__':
  host = input('Ingrese el host del servidor: ')
  port = input('Ingrese el puerto del servidor: ')
  server = Server(host,port)
  server.run()
