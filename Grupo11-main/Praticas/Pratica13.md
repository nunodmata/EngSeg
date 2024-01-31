## **1\. Validação de Input**

### **Pergunta 1.1**

Analise o programa readfile.c que imprime no écran o conteúdo do ficheiro passado como argumento, a que acrescenta o sufixo ".txt" de modo a garantir que só deixa ler ficheiros em texto.

1. Existe pelo menos uma vulnerabilidade estudada na aula teórica de "Validação de Input" (em conjunto com outra que já estudou) que permite que o programa imprima ficheiros que não terminam em ".txt". Explique.
2. Indique a linha de comando necessária para aceder ao ficheiro _/etc/passwd_.

<br/>

Fazendo uma pequena análise do conteúdo/*source code* do programa `readfile.c` consegue-se deduzir que o mesmo trata de receber um nome de um ficheiro como argumento na linha de comandos, devolvendo como output o conteúdo do ficheiro em causa.

<p align="center">
  <img width="" height="" src= "https://user-images.githubusercontent.com/57008189/172484922-ffe92f34-385a-4f3d-bd48-c16a03a6306a.jpg">
</p>

<br/>

**1. Vulnerabilidades do programa:**

Tendo em conta as vulnerabilidades estudadas na aula teórica de "Validação de Input", existe uma vulnerabilidade associada ao programa `readfile.c`, inserida no "pacote" de vulnerabilidades dos ***Metacaracteres*** e é do tipo injeção de separadores. Como a função *system* permite executar programas no terminal e não existe verificação da string colocado como *input* pelo utilizador, é possível que esta vunlnerabilidade possa ser explorada. Existe também outra vulnerabilidade associada à não averiguação se o tamanho de *input* argv[1] é ou não o expectável, neste caso 65 caracteres.

**2. Comando necessário para aceder a */etc/passwd*:**

Tendo em conta a não verificação da string, se o ficheiro `readfile.c` fosse chamado através do comando `./readfile /etc/passwd | cat /etc/shadow` iria ser possível aceder ás passwords do sistema, caso a execução tivesse as permissões necessárias.

<p align="center">
  <img width="" height="" src= "https://user-images.githubusercontent.com/57008189/172494218-0ad9348b-b1da-436b-af6a-f309741e7d42.jpg">
</p>

----

### **Pergunta 1.2**

**Desenvolva um programa (na linguagem em que tiver mais experiência) que pede:**

+ valor a pagar,
+ data de nascimento,
+ nome,
+ número de identificação fiscal (NIF),
+ número de identificação de cidadão (NIC),
+ numero de cartão de crédito, validade e CVC/CVV.

Valide esse input de acordo com as regras de validação "responsável", apresentadas na aula teórica.

#### Para resolução do problema, foram feitas validações dos inputs da seguinte forma:

```python
import re, string, datetime

def valor():
    while True :
        valor = input("\nValor a pagar: \n")
        if re.match(r'^[1-9]\d*([.,]\d{1,2})?$', valor) is not None and len(valor) < 20: 
            return valor
        else :
            print("\nInsira o valor corretamente!")


def data_nasc():
    while True :
        data_nasc = input("\nInsira a data de nascimento (no formato DD-MM-AAAA): \n")
        try:
            date = datetime.datetime.strptime(data_nasc, '%d-%m-%Y')
            today = datetime.datetime.today()
            if (date < today):
                return data_nasc
            else:
                print("\nData superior à data atual! Insira novamente.")
        except ValueError:
            print("\nData inválida. Insira no formato DD/MM/AAAA")


def nome():
    while True :
        nome = input("\nInsira o nome completo (apenas carateres do alfabeto): \n")
        if re.match("^([A-Z][a-z]{2,15})(\s[A-Z][a-z]{2,15}){1,5}$", nome):
            return nome
        else:
            print("\nEscreva o nome corretamente, sem acentos!")
            
            
def Nif():
        nif = input("\nInsira o NIF (no formato xxxxxxxxx): \n")
        if (not re.match("^[0-9]{9}$", nif)):
            print("\nEscreva o NIF no formato correto")
            return Nif()
        if not nif.isdigit() or len(nif)!=9:
            print("\nEscreva o NIF no formato correto")
            return Nif()
	
        soma = sum([int(dig) * (9 - pos) for pos, dig in enumerate(nif)])
        resto = soma % 11
        if nif[-1] == '0' and resto == 1:
            resto = (soma + 10) % 11
        if (resto == 0):
            return nif
        else:
            print("\n Nif inválido!")
            return Nif()
        
        
def getNumberFromChar(letra):
    charDict = {
        "0" : "0",
        "1" : "1",
        "2" : "2",
        "3" : "3",
        "4" : "4",
        "5" : "5",
        "6" : "6",
        "7" : "7",
        "8" : "8",
        "9" : "9",
        "A" : "10",
        "B" : "11",
        "C" : "12",
        "D" : "13",
        "E" : "14",
        "F" : "15",
        "G" : "16",
        "H" : "17",
        "I" : "18",
        "J" : "19",
        "K" : "20",
        "L" : "21",
        "M" : "22",
        "N" : "23",
        "O" : "24",
        "P" : "25",
        "Q" : "26",
        "R" : "27",
        "S" : "28",
        "T" : "29",
        "U" : "30",
        "V" : "31",
        "W" : "32",
        "X" : "33",
        "Y" : "34",
        "Z" : "35",
    }
    return int(charDict[letra])   


def Nic():
        nic = input("\nInsira o número de identificação de cidadão (no formato xxxxxxxx x XXX): \n")
        if (not re.match("^[0-9]{8}\s[0-9]\s([A-Z]|[0-9]){2}[0-9]$", nic) ):
            print("\nEscreva o NIC no formato correto")
            return Nic()
                
        soma = 0
        secondDigit = False
        nic = nic.replace(" ","")
        
        if len(nic)!=12:
            print("\nEscreva o NIC no formato correto: \n")
            return Nic()
        
        for i in range(len(nic) - 1, -1, -1):
            valor = getNumberFromChar(nic[i])
            if (secondDigit):
                valor = valor * 2
                if (valor > 9):
                    valor = valor - 9
            soma = soma + valor
            secondDigit = not secondDigit
                
        if( (soma % 10) == 0 ):
            return nic
        else:
            print("\nEscreva o NIC no formato correto")
            return Nic()
        
        
def nr_cartao():
    cartao = input("\nInsira o número do cartão de crédito (no formato XXXX XXXX XXXX XXXX): \n")
    if (not re.match("^[0-9]{4}\ [0-9]{4}\ [0-9]{4}\ [0-9]{4}$", cartao) ):
        print("\nInsira novamente, no formato correto")
        return nr_cartao()
    
    cartao = cartao.replace(" ","")
    soma = 0
    parity = len(cartao) % 2
    for i, digit in enumerate(int(x) for x in cartao):
        if i % 2 == parity:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        soma = soma + digit
        
    if( (soma % 10) == 0 ):
        return cartao
    else:
        print("\nInsira novamente, no formato correto")
        return nr_cartao()
    
    
def validade_cartao():
    while True :
        validade = input("\nIndique a validade do cartão (no formato MM/AAAA): \n")
        try:
            date = datetime.datetime.strptime(validade, '%m/%Y')
            today = datetime.datetime.today()
            if (date < today):
                print("\nCartão de crédito expirado!")
            else:
                return validade 
        except ValueError:
            print("\nData inválida. Insira no formato MM/AAAA")
     
    
def ccv():
    while True :
        ccv = input("\nInsira o CVC/CVV do cartão: ")
        if re.match("^[0-9]{3}$", ccv):
            return ccv
        else:
            print("\nEscreva o CCV/CVV corretamente.") 

            
def main():
    valor()
    data_nasc()
    nome()
    Nif()
    Nic()
    nr_cartao()
    validade_cartao()
    ccv()
        
if __name__ == "__main__":
    main()

```
