# Aula TP - 05/Abr/2022

Cada grupo deve colocar a resposta às **perguntas** (note que pode colocar as respostas às **experiências**, mas estas não irão contar para avaliação) dos seguintes exercícios na área do seu grupo no Github até ao final do dia 26/Abr/22. Por cada dia de atraso será descontado 0,15 valores à nota desse trabalho.

## Exercícios - Parte IX: Criptografia aplicada


### 1\. Números aleatórios/pseudoaleatórios
#### Pergunta P1.1

Na diretoria das aulas (Aula7/PseudoAleatorio) encontra o ficheiro *generateSecret-app.py* baseado no módulo eVotUM.Cripto (https://gitlab.com/eVotUM/Cripto-py) - siga as instruções de instalação na [branch develop](https://gitlab.com/eVotUM/Cripto-py/-/tree/develop) que já é _compliant_ com o Python 3 -. Para instalar o módulo eVotUM.Cripto poderá efetuar o comando `git clone -b develop git@gitlab.com:eVotUM/Cripto-py.git`.

1. Analise e execute esse programa de geração de segredo aleatório e indique o motivo do output apenas conter letras e dígitos (não contendo por exemplo caracteres de pontuação ou outros).

    Este programa de geração de segredo aleatório que recebe um tamanho como argumento,  chama uma função do módulo eVotUM.Cripto (shamirsecret.generateSecret(length)). Esta função gera uma string aleatória com o tamanho pretendido. O output desta apenas contem letras e digitos porque é feita uma verificação se o byte está contido na lista das ascii_letters e digitos.

2. O que teria de fazer para não limitar o output a vogais e dígitos? Altere o código.

    Modificar os argumentos da função de forma aceitar uma lista de caracteres diferentes que incluissem outros caracteres que não vogais e digitos.
    ```python 
    def generateSecret(secretLength,chars):
    """
    This function generates a random string with secretLength characters (chars).
    Args:
        secretLength (int): number of characters of the string
        chars (list): list of available characters to the string
    Returns:
        Random string with secretLength characters (chars list)
    """
    l = 0
    secret = ""
    while (l < secretLength):
        s = utils.generateRandomData(secretLength - l)
        for c in s:
            if (c in chars and l < secretLength): # printable character
                l += 1
                secret += c
    return secret
    ```


### 2\.  Partilha/Divisão de segredo (Secret Sharing/Splitting)
#### Pergunta P2.1

Na diretoria das aulas (Aula2/ShamirSharing) encontra os ficheiros *createSharedSecret-app.py*, *recoverSecretFromComponents-app.py* e *recoverSecretFromAllComponents-app.py* baseado no módulo eVotUM.Cripto (https://gitlab.com/eVotUM/Cripto-py) - siga as instruções de instalação na [branch develop](https://gitlab.com/eVotUM/Cripto-py/-/tree/develop) que já é _compliant_ com o Python 3 -. 

A. Analise e execute esses programas, indicando o que teve que efectuar para dividir o segredo "Agora temos um segredo extremamente confidencial" em 7 partes, com quorom de 3 para reconstruir o segredo, assim como posteriormente para o reconstruir.

Note que a utilização deste programa é ``python createSharedSecret-app.py number_of_shares quorum uid private-key.pem`` em que:

+ number_of_shares - partes em que quer dividir o segredo
+ quorum - número de partes necessárias para reconstruir o segredo
+ uid - identificador do segredo (de modo a garantir que quando reconstruir o segredo, está a fornecer as partes do mesmo segredo)
+ private-key.pem - chave privada, já que cada parte do segredo é devolvida num objeto JWT assinado, em base 64

     Para cifrar o segredo , geramos a chave privada com o openssl , de seguida usamos o createSharedSecret para criar os 7 componentes com quorum = 3 e o uid = 1 e a chave privada que acabamos de criar. Inserimos a password da chave privada e o segredo. Guardamos os 7 componentes que nos foram dados.

     Para decifrar , criamos o certificado com o openssl e convertemo-lo num .pem. De seguida usamos o recoverSecretFromComponents-app.py ``python recoverSecretFromComponents-app.py number_of_shares uid cert.pem``. Vai nos ser pedido os componentes como input, após inserirmos todos temos então o segredo decifrado.

B. Indique também qual a diferença entre *recoverSecretFromComponents-app.py* e *recoverSecretFromAllComponents-app.py*, e em que situações poderá ser necessário utilizar *recoverSecretFromAllComponents-app.py* em vez de *recoverSecretFromComponents-app.py*.



O recoverSecretFromAllComponents faz a verificação se foram passados todos os componentes do segredo. Este chama a função que o recoverSecretFromComponents chama mas muda um argumento que indica se é suposto ter todos os componentes. Este é util quando não temos a certeza se temos todos os componentes de um segredo.

Nota: Relembre-se que a geração do par de chaves pode ser efetuada com o comando ``openssl genrsa -aes128 -out mykey.pem 1024``. O correspondente certificado pode ser gerado com o comando ``openssl req -key mykey.pem -new -x509 -days 365 -out mykey.crt``

### 3\. Authenticated Encryption

#### Pergunta 3.1

Utilizando o conhecimento de técnicas criptográficas, implemente um programa que permita

1. cifrar um ficheiro com uma técnica de _Authenticated encryption_;
2. validar um ficheiro que tenha sido cifrado com uma técnica de _Authenticated encryption_;
3. decifrar um ficheiro que tenha sido cifrado com uma técnica de _Authenticated encryption_.

A técnica de _Authenticated encryption_ a utilizar é a seguinte:

+ EtM (Encrypt-then-MAC) em Java;

    ```java
    import javax.crypto.*;
    import javax.crypto.spec.IvParameterSpec;
    import javax.crypto.spec.PBEKeySpec;
    import javax.crypto.spec.SecretKeySpec;
    import java.io.*;
    import java.security.*;
    import java.security.spec.InvalidKeySpecException;
    import java.security.spec.KeySpec;
    import java.util.Arrays;
    import java.util.Random;
    import java.util.Scanner;

    public class AESFileEncryption {
        private static String filename;
        private static SecretKey key;
        private static IvParameterSpec iv;
        public static void main(String[] args) {
            //generateFile(10000);
            try {
                Scanner sn = new Scanner(System.in);
                System.out.println("Nome do ficheiro: ");
                filename = sn.nextLine();
                System.out.println("Password: ");
                key = getKeyFromPassword(sn.nextLine(),"123456789");
            }
            catch(Exception e ) {
                System.out.println(e.getMessage());
            }

            iv = generateIv();
            try {
                encrypt(key, iv);
                mac("hdfile.lock",true);
                decrypt(key,iv);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }



        }


        private static boolean checkSameMac(String filename, byte[] b2) throws IOException {
            FileInputStream inputStream = new FileInputStream(filename);
            byte[] b1 = inputStream.readAllBytes();
            inputStream.close();
            return Arrays.equals(b1, b2);
        }
        private static boolean checkSameMac(byte[] b1, byte[] b2) {
            return Arrays.equals(b1, b2);
        }

        private static void generateFile(int length) {
            try {
                FileOutputStream fs = new FileOutputStream("toenc.txt");
                Random r = new Random();
                for (int i = 0; i < length; i++) {
                    char c = (char) (r.nextInt(26) + 'a');
                    fs.write(c);
                }
            }catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        private static void encrypt(SecretKey key , IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
            File f = new File(filename);
            if(!f.exists()) {
                System.out.println("Falha ao abrir o ficheiro");
                return;
            }
            FileInputStream fileInputStream = new FileInputStream(f);

            String filename_locked =filename + ".lock";
            FileOutputStream fileOutputStream = new FileOutputStream(filename_locked);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,key,iv);
            byte[] buffer = new byte[64];
            int bytesRead = 0;
            while ((bytesRead = fileInputStream.read(buffer,0,buffer.length)) != -1) {
                byte[] output = cipher.update(buffer,0,bytesRead);
                if (output != null) {
                    fileOutputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fileOutputStream.write(outputBytes);
            }
            fileInputStream.close();
            fileOutputStream.close();
        }

        private static void decrypt(SecretKey key , IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
            String filename_locked =filename + ".lock";
            byte[] tmpMac = mac("",false);
            if (checkSameMac("hdfile.lock",tmpMac))
                System.out.println("Autenticidade Verificada");
            else {
                System.out.println("Autenticidade quebrada");
                return;
            }
            FileInputStream fileInputStream = new FileInputStream(filename_locked);
            String filename_unlocked = filename + ".unlock";
            FileOutputStream fileOutputStream = new FileOutputStream(filename_unlocked);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE,key,iv);
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer,0,buffer.length)) != -1) {
                byte[] output = cipher.update(buffer,0,bytesRead);
                if (output != null) {
                    fileOutputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fileOutputStream.write(outputBytes);
            }
            fileInputStream.close();
            fileOutputStream.close();
        }

        public static byte[] mac(String fileToHash,boolean saveToFile) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
            FileOutputStream outputStream = null;
            if (!fileToHash.equals(""))
             outputStream = new FileOutputStream(fileToHash);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update(iv.getIV());
            String filename_locked =filename + ".lock";
            FileInputStream fileInputStream = new FileInputStream(filename_locked);
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer,0,buffer.length)) != -1) {
                mac.update(buffer,0,bytesRead);
            }
            byte[] tmp = mac.doFinal();
            if(saveToFile && outputStream != null) {
                outputStream.write(tmp);
                outputStream.close();
            }
            fileInputStream.close();
            return tmp;

        }

        public static SecretKey getKeyFromPassword(String password, String salt)
                throws NoSuchAlgorithmException, InvalidKeySpecException {

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            return new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), "AES");
        }


        public static IvParameterSpec generateIv() {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
        }



    }
    ```

Ciframos e depois fazemos o hmac do ciphertext. Guardamos o hmac num ficheiro e o ciphertext noutro. Na decifragem , validamos o hmac do ficheiro e procedemos a decifração do ficheiro

### 4\.  Algoritmos e tamanhos de chaves
#### Pergunta P4.1

Através do acesso ao site <https://esignature.ec.europa.eu/efda/tl-browser/#/screen/home> pudemos observar os vários certificados emitidos pela Entidade de Certificaçáo (EC) "Bank-Verlag GmbH" da Alemanha. Ao selecionar o separador *"Qualified certificate for eletronic signature"* encontram-se apenas dois certificados. 

Dado que se pretende considerar apenas o último certificado emitido, escolhe-se então esse certificado, apesar de ambos terem uma igual validade, visto que o tempo que separa a data de emissão de um certificado e do outro é de minutos. As características do certificado escolhido são as seguintes:

+ **Algortimo de assinatura:** RSA com SHA256
+ **Algoritmo de chave pública:** RSA
+ **Tamanho da chave:** 4096 bit
    
Após gravarmos o conteúdo do Base 64-encoded do certificado "BVsign" num ficheiro chamado *bvsign.crt* executamos o comando ``openssl x509 -in cert.crt -text -noout`` e obtimos as seguintes informaçóes respetivas ao certificado digital.

```plain
 $ openssl x509 -in bvsign.crt -text -noout
 Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            55:22:34:26:6b:fd:b6:a6:4c:cc:be:f0:7e:50:17:4e:7c:32:e2:4f
        Signature Algorithm: rsassaPss
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0x20
         Trailer Field: 0xBC (default)
        Issuer: CN = BVtrust qSig CA R2020, OU = BVtrust, O = Bank-Verlag GmbH, C = DE
        Validity
            Not Before: Mar 25 10:37:31 2020 GMT
            Not After : Mar 31 22:59:59 2030 GMT
        Subject: CN = BVtrust qSig CA R2020, OU = BVtrust, O = Bank-Verlag GmbH, C = DE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:84:9f:9a:cc:b3:ba:30:10:da:84:2b:de:96:f8:
                    1d:8a:6c:b2:71:b8:8e:d5:ef:27:e1:b1:13:e3:9d:
                    d7:e1:e8:e5:98:c2:3b:4d:1a:2c:02:8d:88:42:a8:
                    ab:f0:50:7b:d8:f0:7b:ee:44:85:bb:7b:e4:df:b5:
                    ac:e1:8c:4f:2e:9e:05:24:fb:5c:7d:88:82:1f:86:
                    ac:b9:0e:4c:9d:67:7c:09:eb:a3:66:e0:47:c4:df:
                    e4:a2:1c:1a:2a:aa:91:01:ae:83:74:74:c2:58:eb:
                    d5:26:4d:40:f2:ed:a6:ea:b2:2c:e7:a4:d5:3a:1e:
                    c5:12:ae:a6:b9:31:49:86:0a:98:99:27:44:3d:81:
                    ca:97:4e:16:64:0e:60:89:8d:f5:ac:25:1e:e7:c4:
                    7a:d0:65:68:cb:2e:20:3d:3b:04:3b:fe:ab:92:37:
                    49:32:98:93:bb:9e:6a:2d:55:af:c9:50:1b:ac:c8:
                    cc:6d:ae:be:c9:92:09:8f:c0:63:3e:a9:44:4e:54:
                    b1:29:94:76:be:c8:1c:a3:34:85:5f:ae:95:e1:83:
                    2a:dd:2a:7a:b3:37:db:ae:bb:e9:b8:26:8a:4a:b5:
                    ca:be:14:6e:97:d9:48:8e:f0:79:ed:b8:c7:b8:e9:
                    71:b5:f0:27:5c:8a:0b:80:c2:4b:0f:66:b1:62:ba:
                    ae:72:0d:79:b8:a2:b5:b1:9d:34:26:22:73:25:13:
                    a7:31:68:cc:22:60:fe:a7:0b:d7:f4:44:45:e4:df:
                    5b:25:a7:f0:2b:64:a8:5b:cf:b0:c4:f4:ab:36:c4:
                    df:94:ad:6f:cf:8c:9c:57:1f:36:94:6f:b1:f4:52:
                    a0:22:81:47:45:44:e4:e9:e0:5f:74:6d:c7:b2:b4:
                    1e:9c:30:6e:f6:4b:2f:df:9b:c5:1e:ca:fe:a7:bc:
                    a7:c4:bd:ad:8e:b6:d9:fe:55:15:88:3a:65:39:19:
                    1a:91:8f:b0:8e:7d:38:12:58:00:35:84:4e:ae:7e:
                    00:4f:62:9d:18:1d:44:18:5a:47:1f:1a:57:0c:eb:
                    03:19:9f:f1:11:85:7c:fc:8e:63:0d:f2:87:c6:ee:
                    db:82:be:39:bb:d2:e5:c3:40:0b:27:14:18:d7:42:
                    4f:46:af:3a:e8:7d:24:09:6a:f9:16:49:24:54:57:
                    9d:a6:bf:e6:3e:68:85:32:6c:7d:dd:7e:b4:77:71:
                    79:52:b2:5a:be:e7:96:7f:b0:e0:ce:89:f0:d2:89:
                    14:2f:83:22:63:7f:80:3a:8f:1c:a7:0e:48:ab:a3:
                    76:da:23:31:60:61:ec:d7:a4:4b:b0:0d:3b:77:71:
                    20:78:d5:ec:8e:45:b4:7b:b7:8f:d5:be:80:10:d5:
                    ee:42:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Authority Key Identifier:
                keyid:04:49:EF:7D:F1:6F:5B:62:52:11:0F:95:66:1F:11:BD:EC:1B:23:B0

            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.50833.1.4.2
                  CPS: https://www.bank-verlag.de/bvtrust-bvsign

            X509v3 Subject Key Identifier:
                04:49:EF:7D:F1:6F:5B:62:52:11:0F:95:66:1F:11:BD:EC:1B:23:B0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: rsassaPss
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0x20
         Trailer Field: 0xBC (default)

         12:a0:1f:7e:19:e4:ad:e3:06:cd:4d:de:ff:fd:b5:f6:5e:18:
         d8:8b:d4:6f:e9:4b:95:23:54:40:e5:2b:f1:0a:71:ab:0e:5a:
         ec:07:80:93:b5:b3:70:73:d0:f8:a5:70:d6:66:75:41:b6:37:
         82:14:86:b9:be:b4:92:8d:7c:1e:93:8b:89:ed:b4:ed:d0:57:
         bd:e7:32:03:9b:5b:b3:ec:14:d4:8b:7e:15:2d:90:d1:94:37:
         f1:44:b4:c4:ff:26:37:38:20:bb:09:59:15:03:c5:2c:b0:4e:
         2e:72:5f:6b:e5:f5:a8:50:d9:41:4e:33:9a:d2:b5:bb:ee:23:
         43:3c:42:01:ba:09:b2:a7:f3:14:22:c9:86:be:ae:8a:9c:94:
         af:f8:e3:0a:e8:68:1b:6a:c3:e0:fa:3d:e6:4d:8c:47:34:4e:
         56:f6:39:ba:94:3c:87:f2:46:07:3a:84:a8:77:85:c1:b6:f3:
         c2:5b:f1:45:86:39:86:7a:8e:10:33:5b:23:2b:3e:62:8b:b5:
         ad:ce:d1:6f:2a:51:93:71:b5:ff:9d:77:d0:ca:23:85:12:2c:
         9a:5c:0f:62:f5:96:60:48:dc:72:b9:53:69:f7:5e:11:8d:de:
         aa:3c:a5:7c:43:63:77:96:cd:07:81:08:21:99:ee:a5:38:2a:
         63:94:f6:38:6b:a7:ca:87:be:a1:18:b0:23:a4:4d:33:13:74:
         03:24:ae:54:e9:1e:74:cf:ce:73:2b:2a:e5:3a:04:07:33:52:
         c1:f7:0a:75:63:9b:a4:d4:b4:30:b3:46:54:dd:7b:0f:6a:c0:
         a2:37:b8:a5:01:0c:7e:c8:cd:ba:17:ef:40:39:9c:dc:12:7d:
         ac:be:d1:15:e9:e5:fe:14:82:01:66:d3:56:38:0e:1f:6d:ab:
         90:a2:57:22:81:e2:23:78:13:dc:55:fc:58:48:5f:dc:0b:01:
         bb:59:f3:3c:17:34:25:fa:19:f9:37:cc:bf:b1:ec:84:a4:db:
         c7:e3:e3:0e:11:f4:a7:9a:d3:36:ef:59:a6:35:8e:f6:22:65:
         c3:53:28:63:41:ce:08:3d:5a:15:31:f0:32:73:91:4e:fb:e3:
         4e:6a:2d:78:2c:16:17:e8:e8:8a:e4:ef:2d:3f:37:d6:d4:c0:
         08:15:9a:e0:d1:e1:b1:e9:85:8a:9c:b3:df:9c:f5:6f:93:b6:
         fd:33:b7:d0:a8:79:b0:c1:43:c9:77:98:ea:b7:10:0e:04:56:
         0b:3a:c4:27:38:d9:08:8d:e6:f7:c7:f4:8e:35:a3:2b:51:2a:
         62:07:fc:47:c3:63:4a:91:52:43:eb:e5:b4:4d:6e:f7:2d:5b:
         c0:f9:ef:95:ca:22:cf:4e
```

#### Conclusões

O NIST aconselha o uso de qualquer algoritmo de hahs da família SHA-1 e SHA-2 (que inclui o algoritmo SHA256) e portanto podemos assim afirmar que este é um algoritmo seguro.

Quanto ao algoritmo de chave pública, o NIST recomenda no mínimo uma chave de 2048 bit. Este certificado é válido até 2030, e o NIST diz que a partir de 2030 a chave deverá ter no mínimo 3072 bits. Assim sendo, mesmo a partir de 2030, este certficado encontrar-se-á atualizado para ir de encontro às recomendações do NIST.



### 5\.  Assinaturas cegas (Blind signatures) baseadas no Elliptic Curve Discrete Logarithm Problem (ECDLP)
#### Pergunta P5.1

Para a realização desta questão, foi primeiro gerados o par de chaves e o certificado utilizando o openssl através dos comandos listados na Experiência 5.1. Feito isto, os códigos disponibilizados foram alterados da seguinte forma:

+ [init-app.py](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/BlindSignature/init-app.py)
+ [blindSignature-app.py](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/BlindSignature/init-app.py)
+ [ofusca-app.py](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/BlindSignature/ofusca-app.py)
+ [desofusca-app.py](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/BlindSignature/desofusca-app.py)
+ [verify-app.py](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/BlindSignature/verify-app.py)

##

### 6\.  Criptografia homomórfica
#### Pergunta P6.1

Foi contratado para ajudar uma conhecida empresa de análises a guardar todos os dados das análises dos seus clientes em ambiente cloud.
O que a empresa pretende guardar é um ficheiro com a seguinte estrutura por cada linha: NIC do cliente, seguido de uma lista de tuplos (tipo de análise, valor). Por exemplo, uma linha pode ser: "123456789, (A23, 12,2), (B4, 32,1), (A2, 102), (CAA2, 34,5)". Adicionalmente foi-lhe indicado que poderá ser necessário obter a média de uma ou mais tipos de análise.

O seu trabalho é:

1. Indicar o modo mais adequado de guardar estes ficheiros em ambiente cloud;
2. Indicar o modo mais adequado de calcular as médias em ambiente cloud, sem que os dados sejam decifrados;
3. Desenvolver dois programas que permitam à empresa de análise testar, localmente, a solução que propõe.

## 

**1.**  De forma a mantar este tipo de dados sensíveis guardados , com segurança, num ambiente cloud podemos tomar algumas medias. Inicialmente e a mais importante é a cifra de toda a informação que for guardada neste ambiente, já que a informação guardada em cloud é essencialmente informação guardada noutro computador. Ter a noção de que nunca devem ser transmitidas informações não cifradas pela internet. A segunda medida é manter backups, estes também cifrados, caso ocorra perda de informações. Tomar medidas de restrição ao acesso às informações guardadas é também muito importante para reduzir o risco de vazamento de informações ou acessos indevidos. 

##

**2.**  Existem algumas técnicas que tornam possível o uso de um input de dados sensíveis (cifrados) que produzem um outoput de dados não sensíveis (não cifrados), sem que os dados produzidos possam decifrar como foram alcançados, adquirindo os dados de input. 
 
**SMC - Secure multi-party computation**, é um protocolo criptográfico que distribui computação entre várias partes, onde nenhuma parte individual pode ver os dados das outras partes. Os protocolos desta técnica podem permitir que cientistas e analistas de dados calculem dados distribuídos de forma conjunta, segura e privada sem nunca expô-los ou movê-los.

**FHE - Fully homomorphic encryption** é um esquema de criptografia que permite que funções analíticas sejam executadas diretamente em dados cifrados, produzindo os mesmos resultados cifrados como se as funções fossem executadas em texto simples.

**DH - Differential privacy**, é uma tecnologia que possibilita uma facilidade na obtenção das informações úteis em bases de dados, contendo informações (cifradas) pessoais de utilizadores, sem que sejam divulgados estes dados sensíveis.


##

**3.1. Implementação da homomorphic encryption - FHE**

```python 
import numpy as np
from numpy.polynomial import polynomial as poly

def polymul(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) % modulus, poly_mod)[1] % modulus)
    )


def polyadd(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(x, y) % modulus, poly_mod)[1] % modulus)
    )

def gen_binary_poly(size):
    return np.random.randint(0, 2, size, dtype=np.int64)


def gen_uniform_poly(size, modulus):
    return np.random.randint(0, modulus, size, dtype=np.int64)


def gen_normal_poly(size):
    return np.int64(np.random.normal(0, 2, size=size))

def keygen(size, modulus, poly_mod):
    sk = gen_binary_poly(size)
    a = gen_uniform_poly(size, modulus)
    e = gen_normal_poly(size)
    b = polyadd(polymul(-a, sk, modulus, poly_mod), -e, modulus, poly_mod)
    return (b, a), sk

def encrypt(pk, size, q, t, poly_mod, pt):
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    ct0 = polyadd(
            polyadd(
                polymul(pk[0], u, q, poly_mod),
                e1, q, poly_mod),
            scaled_m, q, poly_mod
        )
    ct1 = polyadd(
            polymul(pk[1], u, q, poly_mod),
            e2, q, poly_mod
        )
    return (ct0, ct1)

def decrypt(sk, size, q, t, poly_mod, ct):
    scaled_pt = polyadd(
            polymul(ct[1], sk, q, poly_mod),
            ct[0], q, poly_mod
        )
    decrypted_poly = np.round(scaled_pt * t / q) % t
    return int(decrypted_poly[0])


def mul_plain(ct, pt, q, t, poly_mod):
    size = len(poly_mod) - 1
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    new_c0 = polymul(ct[0], m, q, poly_mod)
    new_c1 = polymul(ct[1], m, q, poly_mod)
    return (new_c0, new_c1)

# Scheme's parameters
# polynomial modulus degree
n = 2**4
# ciphertext modulus
q = 2**15
# plaintext modulus
t = 2**8
# polynomial modulus
poly_mod = np.array([1] + [0] * (n - 1) + [1])
# Keygen
pk, sk = keygen(n, q, poly_mod)
# Encryption
pt1, pt2 = 73, 20
cst1, cst2 = 7, 5
ct1 = encrypt(pk, n, q, t, poly_mod, pt1)
ct2 = encrypt(pk, n, q, t, poly_mod, pt2)

print("[+] Ciphertext ct1({}):".format(pt1))
print("")
print("\t ct1_0:", ct1[0])
print("\t ct1_1:", ct1[1])
print("")
print("[+] Ciphertext ct2({}):".format(pt2))
print("")
print("\t ct1_0:", ct2[0])
print("\t ct1_1:", ct2[1])
print("")

# Evaluation
ct3 = add_plain(ct1, cst1, q, t, poly_mod)
ct4 = mul_plain(ct2, cst2, q, t, poly_mod)

# Decryption
decrypted_ct3 = decrypt(sk, n, q, t, poly_mod, ct3)
decrypted_ct4 = decrypt(sk, n, q, t, poly_mod, ct4)

print("[+] Decrypted ct3(ct1 + {}): {}".format(cst1, decrypted_ct3))
print("[+] Decrypted ct4(ct2 * {}): {}".format(cst2, decrypted_ct4))
```

##

**3.2. [Implementação do Secure multi-party computation - SMC](https://github.com/uminho-mei-engseg-21-22/Grupo11/tree/main/Praticas/Secure%20multi-party%20computation)**

Para a implementação do SMC foi usado o protocolo SPDZ, permitindo que na realização de operações como a multiplicação, se mantenham os números cifrados privados durante os cálculos, pois este protocolo usa um "crypto provider" que não está envolvido no cálculo.





