# Exercício 1

Foi descarregado o JavaCard SDK 2.2.2.

# Exercício 2

O exemplo executado, no simulador **jCardSim**, utilizou a ferramenta **APDUScriptTool** para simular a execução de comandos **APDU** num *applet* **Java Card**.

Criou-se o ficheiro ```jcardsim.cfg``` com ```{index}``` = 0, segundo o exemplo. Este ficheiro de configuração foi utilizado para definir o **AID** e a classe do *applet* a ser utilizado no simulador.

``` java 
com.licel.jcardsim.card.applet.0.AID=010203040506070809
com.licel.jcardsim.card.applet.0.Class=com.licel.jcardsim.samples.HelloWorldApplet
```

Adicionalmente, criou-se o ***apdu script*** ```helloworld.apdu```:

``` java
// CREATE APPLET CMD
0x80 0xb8 0x00 0x00 0x10 0x9 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x05 0x00 0x00 0x02 0x0f 0x0f 0x7f;
// SELECT APPLET CMD
0x00 0xa4 0x00 0x00 0x09 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x02;
// TEST NOP
0x00 0x02 0x00 0x00 0x00 0x02;
// test hello world from card
0x00 0x01 0x00 0x00 0x00 0x0d;
// test echo
0x00 0x01 0x01 0x00 0x0d 0x48 0x65 0x6c 0x6c 0x6f 0x20 0x77 0x6f 0x72 0x6c 0x64 0x20 0x21 0x0d;
```
Estre *script* foi então executado e enviou sequências de comandos ao simulador, que respondeu com os resultados esperados, incluindo a mensagem *"Hello World !"*. Obteve-se o seguinte resultado:

![exemplo_cli](images/exemplo_cli.png)

# Exercício 3

## 3.1

De modo a compilar o código do *applet* **Echo**, executou-se o seguinte:

``` bash
$ javac -g -cp lib/api.jar -source 1.5 -target 1.5 Echo/Echo.java
```

Adicionalmente, o ficheiro *class* foi convertido para `.cap` da seguinte forma:

![cap](images/cap.png)

Finalmente, foi possível executar o *applet* no **jCardSim** utilizando o *script* `Echo.apdu`, o qual retornou a mensagem esperada *"Hello World !"*

![echo](images/echo.png)

## 3.2

O próximo passo foi, então, modificar o ficheiro `Echo.java`, com o objetivo do *applet* manter o **número de APDU processadas** e devolva no R-APDU o **complemento binário dos dados que recebe**. 



