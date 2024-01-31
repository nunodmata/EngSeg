### 1. Vulnerabilidade de codificação

#### Pergunta 1.1 - _Common Weakness Enumeration_ (CWE)

Tendo por base o **The CWE Top 25** de 2021 <https://cwe.mitre.org/top25/>,

1. Explique as características da _Weakness_ no ranking correspondente ao número do seu grupo, em que linguagens (e tecnologias, se aplicável) são mais prevalentes, e quais são as suas consequências mais comuns. Dê exemplo (e explique) de código e de CVE que inclua essa _Weakness_.

Sendo nós o grupo 11, a *Weakness* que será analisa e explicada será a weakness **CWE-306: Missing Authentication for Critical Function**, na posição 11 do ranking do **The CWE Top 25 de 2021.**

**Descrição:**

Esta **weakness** caracteriza-se por quando o **software** não efetua qualquer autenticação para funcionalidades que exijam uma identidade de utilizador demonstrável ou que consumam uma quantidade significativa de recursos. Esta fraqueza é causada pela falta de uma tática de segurança durante a fase de arquitetura e design.


**Linguagens:**

*Language-Independent*


**Consequências mais comuns:**

*Access control*: Essa ausência de verificação de autenticação de uma ou mais funcionalidades leva a que um atacante possa obter o nível de privilégio para essa funcionalidade e as consequências dependerão da funcionalidade associada, podendo variar desde a leitura, modificação de dados sensíveis, acesso a dados administrativos ou outras funcionalidades privilegiadas, ou possivelmente até a execução de código arbitrário.


**Exemplo de código:**

Neste exemplo de código em Java, o método *createBankAccount* é utilizado para criar um objeto *BankAccount* para uma aplicação de gestão bancária.	

  ```java
  public BankAccount createBankAccount(String accountNumber, String accountType,
                                       String accountName, String accountSSN, double balance) {
    BankAccount account = new BankAccount();
    account.setAccountNumber(accountNumber);
    account.setAccountType(accountType);
    account.setAccountOwnerName(accountName);
    account.setAccountOwnerSSN(accountSSN);
    account.setBalance(balance);
    
    return account;
  }
  ```

+ Verificamos que não existe um mecanismo de autenticação para assegurar que o utilizador que cria este objeto de conta bancária tenha autoridade para criar novas contas bancárias. Alguns mecanismos de autenticação devem ser utilizados para verificar se o utilizador tem autoridade para criar objetos de conta bancária.

**Exemplo de CVE:**
  + **CVE-2004-0213:** O *Utility Manager* no Windows 2000 inicia o *winhlp32.exe* enquanto está a ser executado com privilégios elevados, o que permite que os utilizadores locais obtenham privilégios do sistema por meio de um ataque estilo **"Shatter"** que envia uma mensagem do Windows para fazer com que o Utility Manager inicie o *winhlp32*, ignorando a GUI, enviando outra mensagem para *winhlp32* para abrir um ficheiro selecionado pelo utilizador.


#### Pergunta P1.2

Considere os três tipos de vulnerabilidades: de projeto, de codificação e operacional. Apresente para cada um deles dois exemplos e discuta a dificuldade de correção.

1. **Vulnerabilidades de projeto:**
  + **CWE-6: J2EE Misconfiguration: Insufficient Session-ID Length:** Se um atacante conseguir adivinhar ou roubar um *ID de sessão*, então poderá ser capaz de assumir a sessão do utilizador (chamado "sequestro de sessão"). O número de possíveis IDs de sessão aumenta com o aumento da duração da sessão, tornando mais difícil adivinhar ou roubar um ID de sessão.
  + **CWE-358: Improperly Implemented Security Check For Standard:** Acontece quando não se tem em conta que um software não está a implementar completamente um algoritmo/técnica standardizada, o que pode resultar numa quebra de segurança visto que existe a possibilidade desse algoritmo ou técnica ser vulnerável.

2. **Vulnerabilidades de codificação:**
  + **CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'):** Esta vunerabilidade *path transversal*, permite que um atacante consiga sair do diretório raiz e aceder a qualquer ficheiro no servidor no qual a aplicação vulnerável está a ser executada. Isso pode dar ao atacante a capacidade de visualizar ficheiros restritos.
  + **CWE-129: Improper Validation of Array Index:** O *software* utiliza *input* não validado que quando calcular ou usar o índice de um *array* poderá ser um posição inválida do *array.* Para mitigar deve-se também seguir um estratégia de validação de *input*.

3. **Vulnerabilidades operacionais:**
  + **CWE-12: ASP.NET Misconfiguration: Missing Custom Error Page:** Se uma aplicação *ASP.NET* não habilitar páginas de erro personalizadas, uma configuração incorreta do *ASP.NET* permite que um atacante possa extrair informações das respostas internas da estrutura.
  + **CWE-209: Generation of Error Message Containing Sensitive Information:** Esta vulnerabilidade ocorre quando os erros de uma aplicação revelam informação sensível para um atacante. Para mitigar deve-se assegurar que as mensagens de erro apenas têm a informação mínima necessária. 


#### Pergunta P1.3

O que é que distingue uma vulnerabilidade dia-zero de outra vulnerabilidade de codificação que não seja de dia-zero?

Uma vulnerabilidade dia-zero ainda não é conhecida pelos developers nem há patchs de segurança para a corrigir , enquanto que uma vulnerabilidade de codificação pode já ser conhecida, até já ter sido corrigida , mas pode haver pessoas que ainda não atualizaram a aplicação em questão o que faz com que seja ainda possível explorar.


  

  
  
