# Semana 8

## Exercício 1)

## Exercício 2)

## Exercício 3)

## Exercício 4)

Dois exemplos de casos onde o **ARM TrustZone** é vantajoso em **comparação** com a arquitetura x86 associada ao **Intel SGX**:

1. O ARM TrustZone é amplamente utilizado em sistemas embutidos e dispositivos móveis, como *smartphones* e *smartwatches*, onde a eficiência energética e o baixo consumo de recursos são essenciais. Nestes cenários, o TrustZone permite a criação de um ambiente seguro (*Secure World*) para proteger dados sensíveis como biometria, senhas e operações criptográficas, sem a necessidade de *hardware* adicional. Já o Intel SGX, por se relacionar a processadores x86, não é tão adequado para estes dispositivos de baixo consumo. 

2. O TrustZone é particularmente eficaz para garantir o *secure boot*, ou seja, o processo de inicialização segura. Este permite verificar a integridade do sistema operativo antes de o  executar. Apesar de o Intel SGX oferecer uma forte proteção para partes isoladas de aplicações (os enclaves), ele não protege o sistema operativo desde o momento em que o dispositivo é ligado.

## Exercício 5)

Ao desenvolver um serviço de gestão de dados com *hardware* confiável, uma abordagem vantajosa é manter este componente abstrato durante a fase inicial de desenvolvimento. Isto permite uma maior flexibilidade na escolha da tecnologia a ser utilizada, como Intel SGX ou ARM TrustZone, facilitando eventuais mudanças futuras sem exigir grandes reestruturações do projeto. 

Para além disso, ao separar a lógica do "negócio" do ambiente de execução seguro, é possível desenvolver e testar a aplicação mais facilmente. Este ponto também contribui para a flexibilidade do sistema, ao permitir que o mesmo seja executado em diferentes dispositivos ou plataformas. 

Por fim, outro benefício importante é a redução da complexidade inicial do projeto, já que as APIs e requisitos de segurança das tecnologias de *hardware* confiável costumam ser complexos e exigem cuidados específicos. 

## Exercício 6)

### a)

### b)

### c)