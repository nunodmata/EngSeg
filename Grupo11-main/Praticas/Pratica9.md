### 1. Secure Software Development Lifecycle (S-SDLC)

#### Pergunta P1.1

1. Em que função de negócio, prática de segurança e actividade do SAMM deve ser levada em linha de conta o regulamento europeu RGPD?

- O *Regulamento Geral de Proteção de Dados* deve ser tido em conta em todo o ciclo, sobretudo na fase de negócio, *Construction*, na prática de segurança *Security Requirements* e numa atividade que consitutui o nível de maturidade mais elevado, o **nível 3**, mais concretamente a seguinte:
  - A. Build security requirements into supplier agreements.

  É aplicado o regulamento nesta fase, visto que é nesta fase primordial, que se definem os requisitos mínimos de segurança que o software em questão deve satisfazer.


2. Em que nível de maturidade dessa prática de segurança tem de estar a empresa, para levar em conta o regulamento europeu RGPD nos seus projetos? Justifique.

- Nessa prática de segurança, a empresa deve estar no **nível 3** de maturidade, para levar em conta o *RGPD* nos seus projetos, visto que é nesse nível que terá de haver uma maior formalização das atividades que constituem essa prática de segurança, dado que estamos a falar da privacidade dos dados pessoais de uma pessoa singular, sendo essencial garantir uma cobertura de segurança adequada para fornecedores externos, fornecendo objetivos claros.

#### Pergunta P1.2

No seu projeto de desenvolvimento 1 (PD1, no âmbito da avaliação prática 2) utiliza certamente componentes, bibliotecas ou APIs _open source_.

1. Quais são as que utiliza, que versão, e que licenciamento é que têm?

- Utilizamos a biblioteca do *bouncyCastle* e uma biblioteca *open source* para cifragem de um segredo, esta tem licenciamento da apache.

2. Face ao licenciamento que têm, que restrições/permissões impõem sobre a utilização das mesmas no seu código?

- A da bouncy castle é *free to use* , podemos usar em qualquer lado, sendo assim *free to use* também no nosso código. A do segredo, é licenciada pela **apache** e portanto, também não impõe restrições. Nenhuma destas garante que sejam 100% seguras. Ambas são parecidas, apenas a da apache tem algumas questões legais mais apuradas.

3. Que boas práticas considera importantes para a utilização de código _open source_ no seu programa?

- A licença deve ser *commercial friendly* , o código open source deve ter atualizações recentes de forma a perceber se o projeto é mantido; verificar se tem uma boa comunidade a manter o mesmo; boa documentação e sem vulnerabilidades de segurança conhecidas.

##

#### Pergunta P2

1. Identifique a maturidade de três práticas de segurança (à sua escolha) que utiliza no projeto de desenvolvimento 2 (PD2) da UC de Engenharia de Segurança (Fase Assess do SAMM)

Como práticas de segurança que se podem encontrar no PD2, temos o **Threat Assessment** a nível do desenvolvimento de uma "atacker profile" de forma a poder-mos analisar mais abrangentemente o tipo de ataques que poderiam vir a ocorrer, ao qual o nível de maturidade é classificado com o nível 1, que representa um entendimento inicial das práticas de segurança deste tópico. 

Temos ainda o **Secure Architecture**, através dos passos tomados durante o desenvolvimento do software com o desenvolvimento de componentes reutilizáveis, e também promovemos sempre o uso de frameworks recomendadas pela sua segurança, o nível de maturidade que se verifica no PD2 relativamente a este tópico é o 1 e 2 que representa um nível mais elevado de eficiência/eficácia das práticas de segurança. 

Por fim, o  **Environment Hardening** através do desenvolvimento de um software que deve correr constantemente sem falhas visto que não é esperado que existam componentes que deteriorem ao longo do tempo, podendo havendo eventualmente deterioração das librarias externas usadas. Relativamente a este tópico podemos atribuir um nível de maturidade de 1, já que nao existem rotinas previstas para a gestão/monitorização do software.  

##

2. Para cada uma das práticas de segurança identificadas na pergunta anterior, estabeleça o objetivo para a mesma (Fase Set the Target do SAMM), i.e., o nível de maturidade pretendido;

Inicialmente a nível da prática de segurança **Threat Assessment** seria interessante o desenvolvimento de um modelo detalhado de avaliação do risco associado a ameaças ao nosso sistema que podem ser provenientes dos componentes externos (third-party software) que são usados. Este estudo elevaria a avaliação da maturidade deste tópico para o nível 3, que representa um domínio abrangente relativamente a esta prática de segurança. 

Relativamente à prática **Secure Architecture**, seria um bom objetivo o estudo de padrões de desenvolvimento seguros de forma a podermos identificar uma arquitetura ideal para o nosso software. Este objetivo poderia elevar a avaliação de maturidade da prática de segurança "Secure Architecture" para o nível 2.

Por fim, no **Environment Hardening**, um objetivo sólido passaria pelo estabelecimento de períodos regulares para patches de rotina, e também a implementação de auditorias ao software, que poderiam incluir avaliações ao próprio software, hardware, componentes do sistema, third party software usado, ambientes de configuração associados, etc. A implementação destes objetivos poderia elevarar a avaliação do nível de maturidade deste tópico para o nível 2 ou 3. 

##

3. Desenvolva o plano para atingir o nível de maturidade pretendido identificado na pergunta anterior, em quatro fases (Fase Define the Plan do SAMM).

As 4 fases para atingir o nível de maturidade desejado, como documentado no website [owaspsamm](https://owaspsamm.org/guidance/quick-start-guide/), são a **preparação,  a avaliação, o estabelecimento de objetivos, a e definição do plano**. 

Inicialmente na fase de **preparação**, o objetivo é assegurar o começo do projeto. Aqui envolvem-se atividades como a atruição de recursos que vão ser usados, a comunicação com stakeholders e entidades interessadas para assegurar que as ideias estão de acordo em ambas as partes e eles vão apoiar no desenvolvimento (seja com financiamento ou outro tipo de apoio). 

Seguidamente, na fase de **avaliação**, o objetivo é identificar e entender a maturidade do projeto escolhido em cada uma das 15 práticas de segurança de software, aqui surgem atividades como: A calendarização de reuniões com as partes interessadas e stakeholders relevantes para entender o estado atual das práticas na própria empresa e avaliar as práticas atuais. E também, baseando-se nos resultados das reuniões, determinar para cada prática de segurança o nível de maturidade de acordo com o sistema de pontuação de maturidade SAMM.

Relativamente à fase de **estabelecimento de objetivos**, o objetivo é desenvolver uma pontuação-alvo que se possa usar como medida para orientar os passos tomados nas atividades mais importantes em diferentes situações. As atividades que podem ocorrer nesta fase são, a definição ou atualização do objetivo, identificando quais atividades são ideias de implementar (de acordo com a empresa e stakeholders). E também a estimativa do impacto relativamente ao objetivo escolhido, tentando representar esses valores em argumentos orçamentais.

Por fim na fase de **definição do plano**, o objetivo é desenvolver ou atualizar o plano/objetivo de forma a dirigir a empresa para um melhor nível. Para isso realizam-se atividades como a escolha uma nova estratégia de mudança realista em termos de número e duração das fases, e por fim a distribuição da implementação de atividades adicionais pelas diferentes fases, tendo em consideração o esforço necessário para implementá-las.
