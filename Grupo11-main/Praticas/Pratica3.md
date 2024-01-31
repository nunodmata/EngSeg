## Parte III: Segurança da informação
### Pergunta 1 - P.IV.1.1

O ChaCha20 é uma das duas cifras simétricas escolhidas para a encriptação dos novos protocolos de transporte, nomeadamente o TLS 1.3 (cf. IETF RFC 8446), embora a sua utilização seja opcional.

Desenvolva em python (utilizando a biblioteca PyCryptodome) uma aplicação linha de comando que utilize o Chacha20 para cifrar um ficheiro, em que o tamanho do nonce é de 12 bytes (conforme boas práticas definidas no IETF RFC RFC 7539).

No interface da linha de comando (CLI - command line interface) deve poder indicar a chave (mas se o utilizador não a colocar, deve-lhe perguntar no inicio de execução do programa), a operação a efetuar (cifra/decifra), ficheiro de input e ficheiro de output.

```python
from Crypto.Cipher import ChaCha20
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
        key = bytes(sys.argv[1],'utf-8')
    else:
        keyinp = input('Insira a chave\n')
        key = bytes(keyinp,'utf-8')
    if len(sys.argv) > 2:
        nonce = b64decode(sys.argv[2])
        decrypt(key,nonce)
    else:
        encrypt(noncesUsed,key)


```

##
### Pergunta 2 - P.IV.2.1
O AES é uma das duas cifras simétricas escolhidas para a encriptação dos novos protocolos de transporte, nomeadamente o TLS 1.3 (cf. IETF RFC 8446), sendo a sua utilização obrigatória, nomeadamente com tamanho de chave de 128 bits e no modo de operação GCM (i.e., AES-128-GCM).

O modo de operação GCM (Galois Counter Mode) é cada vez mais utilizado devido à sua performance, e combina o CTR (Counter Mode, visto na aula teórica) com a autenticação de Galois. O resultado do modo de operação GCM é uma sequência de bytes que contém o IV, ciphertext, e uma authentication tag (utilizada para verificar a autenticação e integridade da restante sequência de bytes).

Desenvolva em java (utilizando os providers da Sun fornecidos por omissão) uma aplicação linha de comando que utilize o AES-128-GCM (com IV de 12 bytes aleatório e diferente em cada utilização, e Tag de 128 bits) para cifrar um ficheiro.

No interface da linha de comando (CLI - command line interface) deve poder indicar a chave (mas se o utilizador não a colocar, deve-lhe perguntar no inicio de execução do programa), a operação a efetuar (cifra/decifra), ficheiro de input e ficheiro de output.

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

public class AES {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int T_LEN = 128;
    private Cipher encryptionCipher;

//criaçao das chaves de cifra (no metodo AES só se usa 1 chave)
    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }
//funcao que faz a cifra da mensagem
    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();  //converter mensagem em um array de bytes       
        
        //criar encription cypher
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding"); 
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes); //variavel que guarda a mensagem em bytes cifrada
        return encode(encryptedBytes);
    }

// funcao que decifra a mensagem
    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);  //converter mensagem em um array de bytes
        
        //criar decryption cypher
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes); //variavel que guarda a mensagem em bytes decifrada
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            AES aes = new AES();
            aes.init();
            String encryptedMessage = aes.encrypt("Mensagem secreta :)");
            String decryptedMessage = aes.decrypt(encryptedMessage);

            System.err.println("Encrypted Message : " + encryptedMessage);
            System.err.println("Decrypted Message : " + decryptedMessage);
        } catch (Exception ignored) {
        }
    }
}
```
