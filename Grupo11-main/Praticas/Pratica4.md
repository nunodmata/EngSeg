##### Pergunta P.V.1.1


Relembre a pergunta P.IV.1.1 da semana passada, assim como a sua resposta. Deve-se ter apercebido que para utilizar o ChaCha20, a chave tinha de ter 32 bytes (i.e., 256 bits).

1. Altere o programa que fez, de modo a permitir que o utilizador forneça uma chave com o tamanho que considerar adequado, e utilize uma função KDF para amplificar a entropia da chave que o utilizador lhe forneceu.

   Justifique as opções tomadas.
   Comentário a justificar a opção na linha referente à questão.
    ```python
	from Crypto.Cipher import ChaCha20
	from Crypto.Hash import SHA256
	from Crypto.Protocol.KDF import HKDF
	import sys
	import string
	import random
	from base64 import b64decode, b64encode
	from Crypto.Random import get_random_bytes


	def saveNonceOnFile(nonce):
	    with open('noncetmp','a') as file :
		file.write(b64encode(nonce).decode('utf-8') + '\n')

	def readNonceFile():
	    tmp = set()
	    try:
		with open('noncetmp','r') as file :
		    file_data = file.readline()
		    while file_data:
			# Remove \n from string
			data = file_data[:-1]
			tmp.add(data)
			file_data = file.readline()
	    except:
		return set()
	    print(tmp)
	    return tmp

	def getNonce(noncesUsed):
	    nonce_rfc7539 = get_random_bytes(12)
	    while nonce_rfc7539 in noncesUsed:
		nonce_rfc7539 = get_random_bytes(12)

	    saveNonceOnFile(nonce_rfc7539)
	    return nonce_rfc7539

	def encrypt(noncesUsed,key):
	    nonce_rfc7539 = getNonce(noncesUsed)
	    cipher = ChaCha20.new(key=key,nonce=nonce_rfc7539)
	    filename = 'sometextfile.txt'
	    with open(filename, "rb") as file:
		# read all file data
		file_data = file.read()
		file_b = b64encode(file_data)
		# encrypt data
		encrypted_data = cipher.encrypt(file_b)
		# print nonce in b64 to console
		print(b64encode(cipher.nonce).decode('utf-8'))
		# write the encrypted file
	    with open(filename, "wb") as file:
		file.write(encrypted_data)

	def decrypt(key,nonce):
	    cipher = ChaCha20.new(key=key, nonce=nonce)
	    filename = 'sometextfile.txt'
	    with open(filename, "rb") as file:
		# read the encrypted data
		encrypted_data = file.read()
		# decrypt data
		decrypted_data = cipher.decrypt(encrypted_data)
		# write the original file
		fdecrypted = b64decode(decrypted_data)
	    with open(filename, "wb") as file:
		file.write(fdecrypted)

	def generateFile():
	    with open('sometextfile.txt',"x") as file:
		for i in range(1,100000):
		    word = random.choice(string.ascii_letters)
		    file.write(word)

	if __name__ == "__main__":
	    #generateFile()
	    noncesUsed = readNonceFile()
	    if len(sys.argv) > 1:
		password = bytes(sys.argv[1],'utf-8')
	    else:
		keyinp = input('Insira a chave\n')
		password = bytes(keyinp,'utf-8')
	    key = HKDF(password, 32 , b'', SHA256, 1) ## Extender a chave para 32 bytes , usando um salt vazio(de forma a ser sempre constante para ser possivel decifrar o ficheiro , aumentando assim a segurança da chave e fazendo com que o cipher com chacha20 aceite a chave ( o qual só aceita chaves de 32bytes como é referido)
	    if len(sys.argv) > 2:
		nonce = b64decode(sys.argv[2])
		decrypt(key,nonce)
	    else:
		encrypt(noncesUsed,key)
   ```
   
##
##### Pergunta P.V.1.2

1. Explique porque não deve utilizar uma função de hash normal para guardar a hash de uma password. 

   Para esta exercício vamos usar como exemplo o algoritmo SHA-256. 
   Tudo pode ser resumido a reduzir o risco geral de perda de informação. Um bom algoritmo de hash torna impossível reverter o valor de hash para calcular o texto original, no entanto, as passwords são muito curtas geralmente. Por isso, ao adivinhar uma senha, o atacante pode comparar a saída do seu SHA-256 com o SHA-256 que ele encontra na base de dados. E como as passwords são muito curtas, testar muitas tentativas de password dessa forma é uma tarefa fácil para um computador. De forma a entender a dimensão de um cenário de ataque podemos dar o seguinte exemplo: Com alguns milhares de euros, podemos construir um pequeno supercomputador dedicado ao teste SHA-256, que permite que um atacante teste 16 triliões de "adivinhações" de password diferentes por segundo. O que é muito mais eficaz do que tentar quebrar o SHA-256.
   
   O exemplo de um algoritmo mais seguro seria o PBKDF2 que executa um algoritmo de hash como SHA-256 centenas, milhares ou milhões de vezes, dependendo de como é configurado. Assim, aumenta a quantidade de trabalho que um atacante precisa de ter para executar um único teste. Se o PBKDF2 for configuardo para executar um milhão de iterações, reduziria a eficácia do supercomputador acima mencionado para testar apenas 16 milhões de suposições de password por segundo por conta. Um invasor só seria capaz de testar um milionésimo das senhas na base de dados comparativamente ao cracking de uma base de dados onde as passwords foram armazenadas como hashes de SHA-256 bits únicos. Reduzindo o risco de uma forma dramática comparando com o exemplo anterior.


##

2. Foi publicado na internet um ficheiro de passwords de acesso a um serviço online, tendo sido referido que a aplicação de guarda de passwords desse serviço utiliza o SHA256 e guarda essa representação das passwords em hexadecimal. Ou seja, a password do utilizador é guardada do seguinte modo: hex(SHA256(password)).

   Sabendo que a passsword representada por `96cae35ce8a9b0244178bf28e4966c2ce1b8385723a96a6b838858cdd6ca0a1e` faz parte do top200 das passwords mais comuns (https://nordpass.com/most-common-passwords-list/), indique qual é essa password, e explique os passos que deu para a encontrar, assim como o código que desenvolveu.
   ```python
   import hashlib

   def crackPassword():
       tmp = []
       with open('common-passwords.txt','r') as file :
           file_data = file.readline()
           while file_data:
               # Remove \n from string
               data = file_data[:-1]
               tmp.append(data)
               file_data = file.readline()

       for password in tmp:
           hashed = hashlib.sha256(password.encode()).hexdigest()
           if hashed == '96cae35ce8a9b0244178bf28e4966c2ce1b8385723a96a6b838858cdd6ca0a1e':
               return password
   if __name__ == "__main__":
       password = crackPassword()
       print(password)
   ```
   A password é 123123
   
##
##### Pergunta P.V.1.3

1. Utilizando o openssl indique qual é o comando linha que tem de utilizar para obter o HMAC-SHA1 de todos os ficheiros numa diretoria.
  
   openssl dgst -hmac -sha1 *
   
##

2. O que teria de fazer para saber se (e quais) os ficheiros foram alterados, desde a última vez que efetuou a operação indicada no ponto anterior?
   
   Comparar os hashs da altura com os de agora. Os que forem diferentes , referem-se aos ficheiros alterados

### Parte VI: Acordo de chaves

##### Pergunta P.VI.1.1

Desenvolva, na linguagem que preferir e utilizando uma biblioteca criptográfica à sua escolha, um programa linha de comando que permita **visualizar** o acordo de chave entre a Alice e o Bob, utilizando o protocolo Diffie-Hellman, assim como a posterior comunicação de mensagens cifradas (pela chave acordada) entre esses mesmos dois intervenientes.


Implementação em python do protocolo de troca de chaves Diffie-Hellman, também com um protocolo de cifra simples usado para a cifra de mensagens na comunicação entre os intervenientes.

```python
import random
import time

def main():
	# message we wish to send
	msg = 'Hello, how are you?'

	# create our two devices
	d1 = Device()
	d2 = Device()

	# perform Diffie-Hellman key exchange
	print('\nPerforming key exchange...\n')
	Device.keygen(d1, d2)

	# encrypt the message to be sent
	encrypted = d1.encrypt(msg)
	print('Bob encrypting message ', msg)

	# 'send' the message
	print('Alice sending message...\n')
	time.sleep(0.5)

	# decrypt the encrypted message using the other device
	decrypted = d2.decrypt(encrypted)
	print('Bob received message')
	print('Alice decrypted message as ',  decrypted, '\n')
	

class Device: 
	n = random.randint(1000, 5000)
	g = 15319

	def __init__(self):
		self.private = random.randint(1, Device.n)
		self.public = (Device.g**self.private)%Device.n
		self.key = None

	@staticmethod
	def keygen(d1, d2):
		d1.key = (d2.public**d1.private)%Device.n
		d2.key = (d1.public**d2.private)%Device.n

	def encrypt(self, msg):
		unencrypted = []
		encrypted = []
		final = []
		for letter in msg:
			unencrypted.append(ord(letter))
			encrypted.append(ord(letter) + self.key)
		for byte in encrypted:
			final.append(byte - self.key)
		return encrypted

	def decrypt(self, encrypted):
		unencrypted = ''
		for byte in encrypted:
			unencrypted += chr(byte - self.key)
		return unencrypted



if __name__ == "__main__":
    main()
    ```

