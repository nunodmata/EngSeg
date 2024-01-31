## 1\. _Buffer Overflow_

### **Pergunta P1.1 - Buffer overflow**

Analise e teste os programs escritos em C RootExploit.c e 0-simple.c .


- Indique qual a vulnerabilidade de _Buffer Overflow_ existente e o que tem de fazer (e porquê) para a explorar e (i) obter a confirmação de que lhe foram atribuídas permissões de root/admin, sem utilizar a _password_ correta, (ii) obter a mensagem "YOU WIN!!!".


#### **1.** `RootExploit`

<br/>

**1.1. Descrição do programa:**
 
Para este ficheiro o principal objetivo passa por forçar permissões de root/admin sem usar uma *password* válida. O programa `RootExploit` começa por criar 2 variáveis de instância. A variável `pass` será usada para controlar o acesso root/admin do utilizador e a variável `buff` para armazenar a password fornecida pelo utilizador. Após isso o programa pede ao utilizador que introduza uma palavra passe, lida pela função `gets`. Caso a palavra-passe introduzida esteja válida, esta passa a assumir o valor **1** e tendo esse valor, o utilizador passa a ter funções de root/admin. A vulnerabilidade existente está relacionada com a não validação do tamanho do *input*, associado à password inserida, lido pela função *gets*.

<br/>

**1.2. Vulnerabilidades do programa:**

A vulnerabilidade do programa está essencialmente no uso da função `gets`, visto que a função não efetua a verificação do tamanho de *input*, associado à *password* inserida. Se pensarmos em termos de *Slack*, as variáveis são declaradas do endereço mais alto para o mais baixo ***(LIFO)*** e então a variável `pass` vai ocupar um espaço de 4 bytes e a variável `buff` irá ocupar os 4 bytes seguintes. 

Apesar da *Stack* assumir uma estrutura LIFO, o processo de escrita nos espaços das variáveis vão do endereço mais baixo para o mais alto. Se a escrita continuar, o programa acaba por escrever para fora dos limites estabelecidos para o `buff` causando um *Buffer Overflow* e permitindo romper o espaço de memória do `buff`, fazendo com que se suba na slack, levando à modificação do valor da variável `pass` que controla esta obtenção de privilégios. É necessário ter em atenção que o último caracter tem de ser diferente de '0' pois só assim a *password* é reconhecida como válida e só assim o utilizador recebe os privilégios administrativos.

Abaixo apresenta-se o processo executado e o *output* obtido.

<p align="center">
  <img width="" height="" src= "https://user-images.githubusercontent.com/57008189/171070686-94ecb053-748d-42bc-84bc-e7759254637a.jpg">
</p>

<br/>

#### 2. `0-simple`

<br/>

**2.1. Descrição do programa:**

Para este ficheiro, o objetivo passar por conseguir forçar a obtenção da mensagem "YOU WIN!!!". No programa `0-simple` a ideia é a mesma, sendo que aqui a variável `buffer` é um array de 64 bytes e password é guardada novamente através da função `gets`. A variável `control` é inicializada a 0 e caso esta possua um valor diferente, é imprimida a mensagem "YOU WIN!!!"

<br/>

**2.2. Vulnerabilidades do programa:**

A vulnerabilidade do programa está novamente relacionada com o uso da função `gets` e a respetiva não validação do tamanho de *input*. 

Em termos de *slack* a ideia seria semelhante ao exemplo anterior, ou seja, a escrita para além dos 64 bytes do `buffer` permite o acesso à variável `control`. Apenas se o *input* for igual ou superior a 77 caracteres, leva a que a variável `control` seja modificada no seu valor e então ao aparecimento da mensagem "YOU WIN!!!".

Abaixo apresenta-se o processo executado e o *output* obtido.

<p align="center">
  <img width="" height="" src= "https://user-images.githubusercontent.com/57008189/171200650-b70ded4e-13dc-46bd-81c3-72fc6c8c42c6.jpg">
</p>

<br/>

### **Pergunta P1.2 - Read overflow**

Analise e teste o program escrito em C ReadOverflow.c

- O que pode concluir?

<p>

#### **1.** `ReadOverflow`


**1.1. Descrição do programa:**

Neste programa são inicializadas 4 variáveis de instância e é solicitado ao utilizador que introduza um número de caracteres, sendo essa quantidade de caracteres, i.e, o tamanho do buffer, verificado para onde está a ser escrito, através do uso da função `fgets`. Uma vez que o valor lido do *stdin* vem em modo string, converte essa string para inteiro. Depois é pedido ao utilizador que introduza uma frase e lê/armazena a mesma do mesmo modo utilizado para a quantidade de caracteres. Entra-se então num ciclo *for* que imprime apenas os **n** primeiros caracteres armazenados no `buf` e se este não tiver, pelo menos, os **n** caracteres, imprime um `.`. O ciclo é repetido.

<br/>

**1.2. Vulnerabilidades do programa:**

A vulnerabilidade a este programa está associada ao facto do ciclo que está a imprimir o ***buffer*** está a considerar apenas no número de caracteres que o utilizador afirma que vai introduzir no ínicio da execução do programa, ou seja, não verifica se o tamanho de ***buffer*** é ou não ultrapassado. 

Uma vez que o ***buffer*** em si nunca chega a ser libertado e que o número de caracteres nunca é comparado com o tamanho da string fornecida pelo utilizador, pode chegar a existir um problema de **Read Oveflow**, i.e, possibilidade de ler o conteúdo de zonas do ***buffer*** que não foram escritas pela frase fornecida, mas sim por anteriores a esta. Na figura seguinte é possível observar esse tipo de falhas que permitem o acesso a informação que não deveria ser visualizada pelo utilizador, se este por exemplo introduzir 120 na quantidade de caracteres solicitada - são lidas 120 posições e não 100 como era suposto.

<p align="center">
  <img width="" height="" src= "https://user-images.githubusercontent.com/57008189/171211288-1518aa63-162f-41b0-bff9-b7c94b3bf4f1.jpg">
</p>

Continua a não existir uma verificação do número de caracteres fornecido pelo utilizador, ou seja, se corresponde realmente a um inteiro ou não. Esta situação acaba por ser controlada pelo uso da função `atoi`.  Caso o input seja do tipo `12asas` o programa tem em consideração os 12 caracteres definidos antes das letras.

<br/>

### **Pergunta P1.3 - Buffer overflow na Heap**

Como foi visto nos *slides* e na *videoaula*, o input introduzido pelo utilizador no programa, caso excedesse um determinado tamanho, conseguia modificar uma variável que deveria estar fora do controlo do utilizador. Esse tipo de problemas pode ser facilmente **mitigado** se tivermos em atenção os limites das variáveis alocadas.

Desta maneira foram adotadas as seguintes medidas:

- Utilização da função `strncpy` para controlar o tamanho das strings que são copiadas;
- Verificação do espaço alocado antes de copiar os dados, criando uma variável `sizearg` de forma a alocar apenas o espaço suficiente;
- Utilização do `strlen` para fazer um número de comparações antes de efetuar cópias de strings e funções, para não acontecer overflow;
- Validação dos argumentos de input;

O resultado final do programa `overflowHeap.1.c` já com as alterações efetuadas, encontra-se descrito abaixo:

``` C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
	printf("Número inválido de argumentos");
	return 0;
    }

    int sizearg = strlen(argv[1]);
           	
    char *dummy = (char *) malloc (sizeof(char) * (sizearg +1));
    char *readonly = (char *) malloc (sizeof(char) *10);
    
    strncpy(readonly, "laranjas", sizeof("laranjas"));

    strncpy(dummy, argv[1], sizearg);

    dummy[sizearg] = '\0';  //fechar o array

    printf("%s\n", readonly);
    printf("%s\n", dummy);

}
```

<br/>


### **Pergunta P1.4 - Buffer overflow na Stack**
Em https://github.com/npapernot/buffer-overflow-attack encontra o programa stack.c com um problema de buffer overflow. Utilize as várias técnicas de programação defensiva introduzidas na aula teórica para mitigar essas vulnerabilidade

Explique as alterações que fez.
``` C
/* stack.c */
/* This program has a buffer overflow vulnerability. */
/* Our task is to exploit this vulnerability */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int bof(char *str)
{
	char buffer[24];
	/* The following statement has a buffer overflow problem */

	strncpy(buffer, str,24);
	return 1;
}

int main(int argc, char **argv)
{
	char str[517];
	FILE *badfile;
	badfile = fopen("badfile", "r");
	fread(str, sizeof(char), 517, badfile);
	bof(str);
	printf("Returned Properly\n");
	return 1;
}


```

- Substituimos o `strcpy` pelo `strncpy` de forma a este nunca passar mais de 24 bytes (o tamanho do buffer) corrigindo assim o nosso problema de buffer overflow;

----
----

## **2\. Vulnerabilidade de inteiros**

### Pergunta P2.1 - Analise o programa underflow.c.

**1.**	Mais uma vez, neste caso existe o uso do método `malloc` e também `memcpy` apenas com controlo do valor máximo que é passado. Isto pode causar vulnerabilidades de **underflow**, caso o número usado seja menor do que aqueles capazes de ser utilizados pelo programa/sistema (por exemplo caso seja um grande número negativo), neste caso não ocorrerá buffer overflow já que o número passado pela variável `tamanho` é verificado, controlando que não seja maior que 2048. Algumas consquências do buffer underflow podem ser a modificação de dados em memória, crash na execução do programa, Denial of Service quando usado em ataques DoS que emitem pedidos a velocidades muito baixas mantendo o serviço à espera da sua resposta, entre outros.


**2.** Uma variável do tipo `size_t` implica um valor inteiro de pelo menos 16 bits, o que pode admitir valores entre -32768 a +32767. 


**3.** Dependendo do valor pode dar um erro de **Segmentation fault**, caso a variavel `tamanho_real` seja um número negativo.

**4.**

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int MAX_SIZE = 2048;
const int MIN_SIZE = -2049;

void vulneravel (char *origem, size_t tamanho) {
        size_t tamanho_real;
        char *destino;
        if (tamanho < MAX_SIZE && tamanho > MIN_SIZE) {
            tamanho_real = tamanho - 1; // Não copiar \0 de origem para destino
            destino = (char *) malloc(tamanho_real);
            memcpy(destino, origem, tamanho_real);
            printf(" memcpy dest = %s\n", destino);

        }
}

int main(int argc, char *argv[]) {
    
    char *origem = "testetstestest";
    size_t tamanho = 1;
    
    vulneravel(*origem, tamanho);
    return 0;
}
```




















