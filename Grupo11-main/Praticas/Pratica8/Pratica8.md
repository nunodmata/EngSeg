## Exercícios - Parte X: Aplicações e protocolos

### 1. Protocolo TLS

#### Pergunta 1.1

Para a pergunta 1, foi-nos pedido que escolhessemos dois sites de empresas não bancárias cotadas na Bolsa Portuguesa e pertencentes ao PSI 20. Depois de escolhidas as empresas, a [NOS](https://www.nos.pt/) e a [GALP](https://galp.com/pt/), efetuamos um SSL Server test a cada um dos websites, usando o site [SSL labs](https://www.ssllabs.com/ssltest/).

i. **Anexo de resultados do SSL Server test**

Os resultados dos testes efetuados encontram-se nestes *pdfs*, na seguinte diretoria:
- [GALP](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/Pratica8/SSL%20Server%20Test%20-%20GALP.pdf)
- [NOS](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/Pratica8/SSL%20Server%20Test%20-%20NOS.pdf)

ii. **Análise do resultado do SSL Server test relativo ao site com pior rating e comentários acerca da segurança**

O pior *website* em termos de *rating* foi o *site* da empresa **NOS**. Este *site* obteve uma **classificação B**, o que por si só não é nada mau, mas fica abaixo do esperado: uma classificação A ou A+, uma classificação perfeita.

Como é possível observar no *pdf* anexado em cima, o *site* não usa a versão mais recente do *TLS 1.3*, utiliza versões já algo ultrapassadas como a versão mais antiga *1.2* e *1.1* sendo esta a principal razão da atribuição da **classificação B**. Para além disto, quase todas as *Cipher suites* são consideradas fracas, por várias razões. Algumas pelo uso do modo *CBC* em vez do modo *GCM*, outras pelo algoritmo SHA usado (SHA em vez de SHA256 ou até mesmo SHA384) e ainda outras devido a usarem apenas RSA em vez de ECDHE. Em relação ao certificado do site podemos ver que este possui um certificado transparente e de confiança e que não possui *DNS CAA*.

iii. **OpenSSL CCS vuln. (CVE-2014-0224) na secção de detalhe do protocolo**

A vulnerabilidade de injeção CCS *CVE-2014-0224* é uma vulnerabilidade grave no *OpenSSL* e que afeta esta biblioteca nas seguintes versões:

- versões anteriores a 0.9.8za
- 1.0.0 antes de 1.0.0m
- 1.0.1 antes de 1.0.1h

Esta vulnerabilidade pode permitir um ataque *man-in-the-middle* contra uma conexão cifrada, intercetando o fluxo de dados cifrado, permitindo decifrar, visualizar e manipular esses dados.

A vulnerabilidade só pode ser explorada se o *servidor* e o *cliente* estiverem vulneráveis a esse problema. No caso de um dos dois ser vulnerável, não há risco de exploitation.
#

### 2. Protocolo SSH

#### Pergunta 2.1

Para esta pergunta foi necessário criar uma conta no *Shodan* de modo a pesquisar os vários servidores *ssh* para as 2 empresas escolhidas. De seguida, no intento da escolha de dois servidores ssh de empresas cotadas na Bolsa Portuguesa, realizou-se, neste *site*, as seguintes pesquisas: **port:22 org:"NOS"** e **port:22 org:"CTT"**. 

É importante referir que o método de seleção dos servidores baseou-se na escolha do primeiro servidor apresentado como resultado de pesquisa para as empresas **NOS** - **a79-168-252 233.cpe.netcabo.pt** (NOS) e **CTT** **62.28.37.132.mailtec.pt** (CTT). 

1. **Anexo dos resultados do ssh-audit**

- [NOS](https://www.shodan.io/host/79.168.252.233)
    - [Output do SSH-Audit](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/Pratica8/ssh-audit%20NOS.txt)

- [MEO](https://www.shodan.io/host/62.28.223.183)
    - [Output do SSH-Audit](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/Pratica8/ssh-audit%20MEO.txt)

2. **Software e versão utilizada pelos servidores ssh**

    NOS - *OpenSSH 8.2*
    ```plain
    # general
    (gen) banner: SSH-2.0-OpenSSH_8.2
    (gen) software: OpenSSH 8.2
    (gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+
    (gen) compression: enabled (zlib@openssh.com)
    ```


    MEO - *Dropbear SSH 2016.74*
    ```plain
    # general
    (gen) banner: SSH-2.0-dropbear_2016.74
    (gen) software: Dropbear SSH 2016.74
    (gen) compatibility: OpenSSH 3.9-6.6, Dropbear SSH 2013.57+
    (gen) compression: disabled
    ```

3. **Qual das versões de software tem mais vulnerabilidades?**

- NOS
    - [CVE Details - OpenSSH 8.2](https://www.cvedetails.com/vulnerability-list/vendor_id-97/product_id-585/version_id-639204/Openbsd-Openssh-8.2.html) - 1 vulnerabilidade

- MEO
    - [CVE Details - Dropbear SSH 2016.74](https://www.cvedetails.com/vulnerability-list/vendor_id-15806/product_id-33536/version_id-214300/Dropbear-Ssh-Project-Dropbear-Ssh-2016.74.html) - 0 vulnerabilidades
    - [SSH-AUDIT](https://github.com/uminho-mei-engseg-21-22/Grupo11/blob/main/Praticas/Pratica8/ssh-audit%20MEO.txt) - 3 vulnerabilidades


4. **Vulnerabilidade mais grave**

A vulnerabilidade mais grave encontrada, foi a vulnerabilidade encontrada no servidor da **MEO** através do *ssh-audit*. A mais grave foi o [CVE-2017-9078](https://www.cvedetails.com/cve/CVE-2017-9078/?q=CVE-2017-9078), com um *CVSS Score* de **9.3**.


5. **A vulnerabilidade indicada no ponto anterior é grave? Porquê?**

A vulnerabilidade, classificada com um score 9.3, é muito grave pois pode permitir que utilizadores locais elevem os seus privilégios para *root* sob certas condições, mediante a execução remota de código raiz pós-autenticação.

#

### 3. TOR (The Onion Router)

#### Pergunta P3.1

Para aceder a alguns sites nos EUA tem que estar localizado nos EUA.

1. Efetuando o comando `sudo anonsurf start` consegue garantir que está localizado nos EUA?

    - Não, isso não é possível através do comando `sudo anonsurf start`. 

2. Porquê? Utilize características do protocolo TOR para justificar.

    - Não é possível, porque, apesar do *Onion Proxy (OP)* estabelecer um circuito através da rede *TOR*, o processo é feito de forma aleatória e independemente do     utilizador. Como o processo é aleatório não existe forma de garantir que o **IP** final do circuito (nodo de saída) está localizado nos Estados Unidos.


#### Pergunta P3.2
1. O circuito para este site: 

![image](https://user-images.githubusercontent.com/57006792/166817110-6fe0602e-f632-4448-b028-a9f4e1a88143.png)

2. Os serviços Onion requerem 6 saltos porque é importante que ninguém, nem mesmo o rendezvous point, seja capaz de desanonimizar o cliente ou o serviço, mesmo que exista algum "adversário" a controlar um dos pontos. Apesar de tornar as conexões mais lentas, é um método utilizado para manter o utilizador anónimo.

3. O rendezvou point é o terceiro relay na janela de exibição do circuito do Tor quando nos conectamos a um serviço onion. Neste caso o ![image](https://user-images.githubusercontent.com/57006792/166823264-d4f88fac-6565-4a80-80dc-b0570c1dad2c.png)


#
### 4. Blockchain


#### Experiência 4.1

Neste exemplo siga o artigo [Building a blockchain](https://medium.com/@akshaykore/building-a-blockchain-7579c53962dd) e os vários passos indicados no mesmo.


#### Pergunta 4.1

Na experiência anterior, altere o método que cria o Genesis Block, de modo a que o timestamp seja a data do dia de hoje e o dado incluído nesse Bloco seja "Bloco inicial da koreCoin".

```python

const SHA256 = require('crypto-js/sha256');

class Block{
    constructor (index, timestamp, data, previousHash = ''){
        this.index = index;
        this.timestamp = timestamp;
        this.data = data;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
    }
    
    calculateHash(){
        return SHA256(this.index + this.previousHash + this.timestamp + JSON.stringify(this.data)).toString();
    }
    }



class Blockchain{
    constructor(){
        this.chain = [this.createGenesisBlock()];
    }
    
    createGenesisBlock(){

        return new Block(0, today, Block[0], "0");
    }
    
    getlatestBlock(){
        return this.chain[this.chain.length - 1];
    }
    
    addBlock(newBlock){
        newBlock.previousHash = this.getlatestBlock().hash;
        newBlock.hash = newBlock.calculateHash();
        this.chain.push(newBlock);
    } //In reality we cannot add a new block so easily. There are numerous checks in place like 'Proof of work', 'Proof of stake' etc.
    
    isChainValid(){
        for(let i = 1; i < this.chain.length; i++){
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i-1];
            
            if(currentBlock.hash !== currentBlock.calculateHash()){
                return false;
            } //check for hash calculations
            
            if(currentBlock.previousHash !== previousBlock.hash){
                return false;
            } //check whether current block points to the correct previous block
            
        }
        
         return true;
    }
    
}

var today = new Date();
var dd = String(today.getDate()).padStart(2, '0');
var mm = String(today.getMonth() + 1).padStart(2, '0'); //January is 0!
var yyyy = today.getFullYear();

today = dd + '/' + mm + '/' + yyyy;

let koreCoin = new Blockchain();

koreCoin.addBlock(new Block (1, today, {amount: 20}));
koreCoin.addBlock(new Block (2, today, {amount: 40}));
koreCoin.addBlock(new Block (3, today, {amount: 40}));

console.log('Is Blockchain valid? ' + koreCoin.isChainValid());

//tampering with blockchain
koreCoin.chain[1].data = { amount: 100 };
console.log("tampering with data...");
koreCoin.chain[1].hash = koreCoin.chain[1].calculateHash();

console.log('Is Blockchain valid? ' + koreCoin.isChainValid());


```

##

#### Pergunta 4.2

Na experiência anterior, adicione alguns blocos simulando várias transações em cada um deles.

```python 
next_block(last_block){
        this_index = last_block.index + 1
        this_timestamp = today;
        this_data = "Hey! I'm block " + str(this_index)
        his_hash = last_block.hash
        return Block(this_index, this_timestamp, this_data, this_hash)
    }
    
previous_block = Blockchain[0];
num_of_blocks_to_add = 10;
for (let i = 1; i < num_of_blocks_to_add; i++){
  block_to_add = next_block(previous_block)
  Blockchain.append(block_to_add)
  previous_block = block_to_add

  console.log("Block #{} has been added to the blockchain!".format(block_to_add.index));
  console.log("Hash: {}\n".format(block_to_add.hash));
}
```
##

#### Pergunta 4.3

Na experiência anterior, altere a dificuldade de minerar para 2 e veja qual o tempo que demora, utilizando o comando time do Linux (ou similar no seu sistema operativo), por exemplo `time node main.experiencia2.1.js`.
Repita o exemplo para dificuldade de minerar 3, 4 e 5.

Apresente os tempos e conclua sobre os mesmos.

Alterando a dificuldade para este programa de mineração foram possíveis observar os seguintes tempos de execução:
1. Dificuldade 2 : 0.1s

![image](https://user-images.githubusercontent.com/57006792/166612287-9667e7c9-d610-4e01-934b-7fdb01a7ae45.png)

2. Dificuldade 3 : 0.3s

![image](https://user-images.githubusercontent.com/57006792/166612394-f6926c5e-e515-4a18-9396-4d2b8f6d9b9f.png) 

3. Dificuldade 4 : 1.4s

![image](https://user-images.githubusercontent.com/57006792/166612472-8a1c589c-eff3-49d2-b748-c5645651339f.png)

4. Dificuldade 5 : 18.5s

![image](https://user-images.githubusercontent.com/57006792/166612558-cb8cd7c8-8383-4ea8-a703-df1c420d68b1.png)

O problema é que existem vários miners a tentar resolver o mesmo bloco, e para selecionar um miner que será designado para resolver um bloco de transações, criamos um quebra-cabeças matemático difícil de resolver. O quebra-cabeças geralmente é encontrar um número muito longo (valor de hash) onde o computador tenta adivinhar cada dígito. Quem resolver o quebra-cabeça primeiro consegue minar o bloco e receber uma recompensa. Após cada transação bem-sucedida, o quebra-cabeça começa a aumentar em complexidade, ou seja, os miners precisam procurar um valor de hash ainda maior, é aqui que a a variável de “dificuldade” do programa entra em função. Neste programa conseguimos escolher um nível de dificuldade que vai controlar o quão longo é o número que precisa de ser adivinhado pelos miners. Por isso, o tempo de execução deste programa vai variar diretamente do valor escolhido para a dificuldade.

##

#### Pergunta 4.4

1. Na experiência anterior, qual é o algoritmo de 'proof of work' ?

O algoritmo de proof of work é o que implementa dificuldade na criação de um bloco, assim podemos provar que foi gasto muito poder de computação para fazer um bloco. Sendo que é este o conceito de que existiu muito trabalho na criação do bloco o que dá valor ao sistema de mineração. Este conceito é comprovado no exemplo da mineração de bitcoin.


2. Parece-lhe um algoritmo adequado para minerar? Porquê?

Sim, com o uso do SHA-256, que é considerada a função de hash mais utilizada no mundo. Tem as características de ser um algoritmo muito seguro e com possibilidade de mineração por CPU.
