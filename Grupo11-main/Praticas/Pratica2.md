## Parte I: Criptografia – conceitos básicos
### Pergunta P1.1

A segurança por obscuridade indica que um sistema é mantido em segredo, ocultando os mecanismos de segurança, pressupondo que isso é suficiente para proteger o sistema. Ora isso leva a uma falsa sensaçáo de segurança, que geralmente é mais perigosa do que não abordar a segurança de todo.

Como observou Kerchoffs em 1883, "o sistema não deve exigir segredo e deve poder cair mãos do inimigo sem causar problemas". Isto aplica-se, visto que se a segurança por obscuridade não for aplicada em conjunto com outros mecanismos de segurança e regras de defesa, pode ser comprometedor se os segredos forem revelados, ou seja, todo o sistema entra em colapso quando a primeira pessoa descobre como o mecanismo de segurança funciona. O que deve ser garantido é que nenhum mecanismo é responsável pela segurança de todo o sistema.

Kerchoffs refenciava que conceber um sistema criptográfico seguro da melhor forma, já era objeto de discussão no final do século XIX e propôs que "um sistema deverá ser seguro mesmo que o adversário conheça tudo sobre ele", incluindo as técnicas, o processo de cifra ou até a própria mensagem cifrada, exceto a chave secreta, sendo esta proposta considerada a negação de todas as abordagens à segurança por obscuridade.

*"Security through obscurity"* pode ser uma maneira muito eficaz de reduzir as chances de um ataque quando usado juntamente com outras camadas de segurança e não servir como um substituto para a segurança real do sistema e os profissionais de segurança sabem que o sigilo é um elo adicional para toda a cadeia de segurança.

## Parte II: Exemplos de Cifras Clássicas
### Pergunta P1.1
```python
import os
from math import log10
import re
from pycipher import Caesar

def chain_caesar(ctext , nchain):
    ctext = re.sub('[^A-Z]','',ctext.upper())
    secured = ctext
    for i in range(nchain):
      secured = Rot13().encipher(secured)
    return secured


def de_chain_caesar(tsec,nchain):
  secured = tsec
  for i in range(nchain):
      secured = Rot13().decipher(secured)
  return secured
  
  
class ngram_score(object):
    def __init__(self,ngramfile,sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        self.ngrams = {}
        for line in open(ngramfile):
            key,count = line.split(sep) 
            self.ngrams[key] = int(count)
        self.L = len(key)
        print(self.ngrams.items())
        self.N = sum(iter(self.ngrams.values()))
        #calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key])/self.N)
        self.floor = log10(0.01/self.N)

    def score(self,text):
        ''' compute the score of text '''
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text)-self.L+1):
            if text[i:i+self.L] in self.ngrams: score += ngrams(text[i:i+self.L])
            else: score += self.floor          
        return score
fitness = ngram_score('english_quadgrams.txt') # load our quadgram statistics

def break_caesar(ctext):
    # make sure ciphertext has all spacing/punc removed and is uppercase
    ctext = re.sub('[^A-Z]','',ctext.upper())
    # try all possible keys, return the one with the highest fitness
    scores = []
    for i in range(26):
        scores.append((fitness.score(Caesar(i).decipher(ctext)),i))
    return max(scores)
    
def bruteforce_caesar(ctext, nchain):
  tmp = ctext
  for i in range(nchain):
    max_key = break_caesar(tmp)
    tmp = Caesar(max_key[1]).decipher(tmp)
  return tmp
```

Na cifra de César encadear várias cifras é irrelevante , pois não importa quantas vezes encriptamos o texto que o texto vai sempre ficar entre os limites do alfabeto e portanto o shift que damos para encriptar vai conseguir ser sempre verificado por um valor singular. Sendo assim o total de chaves avaliadas vai ser sempre 26( numero de letras no alfabeto) , e portanto, independente do numero de cifras sequenciais que tivermos , o tempo para as atacar vai ser sempre igual.

### Pergunta 2.1
O ciphertext OXAO não pode ser correspondente a DATA pois se D(plainText) = O(ciphertext) então OXAO nunca pode ser Data pois o O repete-se tanto no inicio como no fim e Data não começa e acaba com D. Pois numa cifra mono-alfabética , o alfabeto gerado é só um. Cada letra tem uma correspondência e uma só correspondência.

### Pergunta 3.1
A cifra de Hill está implementada com o uso de 2 ficheiros. O ficheiro commons, que vai fazer o tratamento dos dados da mensagem a ser cifrada e também a criação da matriz da nossa chave. Neste passo a mensagem é transformada num array que divide as suas letras para que depois estas sejam convertidas em números através da tabela ASCII e usadas no vetor que juntamente com a matriz de crifra vão ser usados para fazer o calculo da mensagem original. Já no ficheiro main é cifrada e decifrada a mensagem, e os passos referentes ao calculo da mensagem original.
#### Ficheiro main
```python
import numpy as np
from sympy import Matrix
import commons


def main():

    msg = "Mensagem privada"

    key = "ABCDEFGHJ"
    
    # Obter a matriz da chave 3x3
    keyMatrix = commons.getKeyMatrix(3, key)

    # Verificar se a matriz é quadrada
    keyMatrix = np.array(keyMatrix)
    print(keyMatrix)

    # Calcular o determinante da matriz e verificar se é != 0, para o calculo da matriz inversa ser != 0
    det = np.linalg.det(keyMatrix) != 0
    print(det)

    msg = commons.preprocessing(msg)

    # Variavel com o array das letras da mensagem separadas 
    plainText = commons.lettersOfPlaintext(msg)

    plainText_idx= []

    # Transforma a letra em um numero (atraves da tabela ASCII)
    for i in plainText:
        plainText_idx.append(commons.letterToNumber(i))   

    plainTextMatrix = np.array(plainText_idx)

    plainTextMatrix.resize(5,3)

    cipherText, encryptionMatrix = encrypt(plainTextMatrix, keyMatrix)
            
    orignalMsg = decrypt(encryptionMatrix, keyMatrix)

    # Nova lista com a mensagem cifrada
    finalOriginalMsg = ' '.join([str(elem) for elem in orignalMsg])

    print("Plain text message: ", plainText)
    print("Cipher text message: ", cipherText)
    print("Mensagem original depois de decifrada é: ", finalOriginalMsg.upper())

# Cifrar mensagem dado as duas matrizes
def encrypt(matrix, key_matrix):

    # Multiplicar a matriz do plain text * a matriz da key, com modulo 26
    encryptionMatrix = np.matmul(matrix, key_matrix) % 26

    encryptionMatrix.resize(1,15)
    
    cipherText = []

    # Converter o resultada da multiplicação das matrizes em letras de novo e obtemos o cipher text
    for i in encryptionMatrix.tolist()[0]:
        cipherText.append(commons.numberToLetter(i))

    return cipherText, encryptionMatrix

# Decifrar a mensagem dado as duas matrizes
def decrypt(encryptionMatrix, keyMatrix):
    
    # Criar a inversa da matriz da key com modulo 26
    invKey = Matrix(keyMatrix).inv_mod(26)
    
    # Criar um array com a chave inversa
    invKey = np.array(invKey)

    # Converter os valores para float
    invKey = invKey.astype(float)

    # Multiplciar a matriz key pela sua inversa
    np.matmul(keyMatrix, invKey) % 26

    encryptionMatrix.resize(5,3)

    # Matriz com os valores decifrados (em numero)
    decryptionMatrix = np.matmul(encryptionMatrix, invKey) % 26

    decryptionMatrix.resize(1,15)

    originalMsg = []
    # Converter os valores da decryptionMatrix em letras para obter a msg
    for i in decryptionMatrix.tolist()[0]:
        originalMsg.append(commons.numberToLetter(i))

    return originalMsg



if __name__ == "__main__":

    main()
```
#### Ficheiro commons
```python
import string

# Tratamento do texto da mensagem - tranforma tudo em maisculas e apaga espaços 
def preprocessing(m):
    
    m = m.replace(" ","").replace(",","").replace(".","").replace("'","").replace(":","").replace(";","")
    m = m.upper()
    
    return m

# Separar letras da mensagem num array
def lettersOfPlaintext(m):

    letters = []
    
    for i in range(0, len(m)):

        letters.append(m[i])

    return letters

# Return do numero da tabela ascii na posiçao do valor letra 
def letterToNumber(letter):

    return string.ascii_uppercase.index(letter)

# Retorna o a letra correspondente ao numero
def numberToLetter(number):

    return chr(int(number) + 97)

def getKeyMatrix(leng, key):

    # preencher o array com 0s 
    keyMatrix = [[0] * leng for i in range(leng)]

    # contador
    k = 0

    # Gerar a matriz da chave
    #Loop pelas linhas da matriz
    for i in range(leng):
        
        # Loop pelas colunas
        for j in range(leng):

            # Transformar a letra de cada posicao no numero correspondente
            keyMatrix[i][j] = ord(key[k]) % 65
            
            # Incrementar contador em 1
            k += 1
            
    return keyMatrix

def validateMatrix(keyMatrix):
    
    keyRows = keyMatrix.shape[0]
    keyColumns = keyMatrix.shape[1]
    
    if keyRows != keyColumns:
        raise Exception('key must be square matrix!')
```

### Pergunta 4.1
A cifra *one-time-pad* é uma técnica de criptografia que é inquebrável se for utilizada corretamente. No entanto esta cifra raramente se utiliza no mundo real visto que:
- **A chave deve ser verdadeiramente aleatória.** Isso pode ser um problema porque computadores convencionais não conseguem gerar sequências de números verdadeiramente aleatórios e a segurança da cifra depende da qualidade do gerador de números aleatórios.
- **A chave e a mensagem a cifrar devem ter o mesmo tamanho.** Como a chave é aleatória, se a mensagem for muito grande, é necessário um valor muito alto de aleatoriedade. *Por exemplo*, para criptografar todos os dados num disco rígido seria necessária uma segunda unidade, com o mesmo tamanho, para armazenar a chave.
- **A chave nunca pode ser reutilizada ou redistribuída.** A chave deve ser transmitida de um ponto a outro e mantida até que a mensagem esteja emitida ou recebida. Para uma nova mensagem, deve ser gerada uma nova chave.

### Pergunta 5.1

```python

import re
import math

key = "MINHO"
  
def encryptMessage(msg):
    cipher = ""
  
    k_indx = 0
  
    msg_len = float(len(msg))
    msg_lst = list(msg)
    key_lst = sorted(list(key))
  
    # Calcula as colunas da matriz
    col = len(key)
      
    # Calcula a máxima linha da matriz
    row = int(math.ceil(msg_len / col))
  
    # Cria a matriz e insere a mensagem
    matrix = [msg_lst[i: i + col] 
              for i in range(0, len(msg_lst), col)]
  
    # Lê a matriz em colunas, usando a chave
    for _ in range(col):
        curr_idx = key.index(key_lst[k_indx])
        cipher += ''.join([row[curr_idx] 
                          for row in matrix])
        k_indx += 1
  
    return cipher
    
def decryptMessage(cipher):
    msg = ""
  
    k_indx = 0
  
    msg_indx = 0
    msg_len = float(len(cipher))
    msg_lst = list(cipher)
  
    col = len(key)
      
    row = int(math.ceil(msg_len / col))
  
    # Converte a chave numa lista e ordena alfabeticamente
    key_lst = sorted(list(key))
  
    # Cria uma matriz vazia para armazenar a mensagem decifrada
    dec_cipher = []
    for _ in range(row):
        dec_cipher += [[None] * col]
  
    # Organize a coluna da matriz de acordo com a ordem de permutação adicionando na nova matriz
    for _ in range(col):
        curr_idx = key.index(key_lst[k_indx])
  
        for j in range(row):
            dec_cipher[j][curr_idx] = msg_lst[msg_indx]
            msg_indx += 1
        k_indx += 1
  
    # Converte matriz da msg decifrada numa string
    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        raise TypeError("Palavras repetidas")
        
    null_count = msg.count('_')
  
    if null_count > 0:
        return msg[: -null_count]
  
    return msg
    
msg = "este exemplo mostra a transposicao dupla"
  
cipher = encryptMessage(msg)
print("Mensagem cifrada: {}".
               format(cipher))
  
print("Mensagem decifrada: {}".
       format(decryptMessage(cipher)))
```

