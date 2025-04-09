# Exercício 1

Foi descarregado o JavaCard SDK 2.2.2.

# Exercício 2

O exemplo executado, no simulador **jCardSim**, utilizou a ferramenta **APDUScriptTool** para simular a execução de comandos **APDU** num *applet* **Java Card**.

Criou-se o ficheiro ```jcardsim.cfg``` com ```{index}``` = 0, segundo o exemplo. Este ficheiro de configuração foi utilizado para definir o **AID** e a classe do *applet* a ser utilizado no simulador.

``` java 
com.licel.jcardsim.card.applet.0.AID=010203040506070809
com.licel.jcardsim.card.applet.0.Class=com.licel.jcardsim.samples.HelloWorldApplet
```

Adicionalmente, criou-se o ***script*** ```helloworld.apdu```:

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

De modo a simular um **Java Card** e reresolver os exercícios propostos, criou-se um projeto `Maven` com a seguinte dependência:

``` xml
<!-- https://mvnrepository.com/artifact/com.licel/jcardsim -->
<dependency>
    <groupId>com.licel</groupId>
    <artifactId>jcardsim</artifactId>
    <version>2.2.2</version>
</dependency>
```

Para além disso, para configurar o simulador, seguiu-se a documentação do [repositório oficial](https://github.com/licel/jcardsim).

## 3

Ao compilar e executar o código do *applet* **Echo**, através do `Maven`, com o comando `run sim=App`, obteve-se o seguinte:

![echo1](images/echo1.png)

A resposta (**R-ADPU**) obtida foi a esperada, já que é possível observar a mensagem *"Hello World !"* em hexadecimal.

![hex1](images/hex1.png)

---

O próximo passo foi, então, modificar o ficheiro `Echo.java`, com o objetivo do *applet* manter o **número de APDU processadas** e devolver na R-APDU o **complemento binário dos dados que recebe**. 

Para isso, foi adicionado um `apduCounter` que incrementa a cada APDU processada e uma linha que executa a operação **XOR**  de cada *byte* com **=0XFF**:

```java
for (short i = 0; i < bytesRead; i++) {
    echoBytes[echoOffset + i] = (byte) (buffer[ISO7816.OFFSET_CDATA + i] ^ (byte) 0xFF);
}
echoOffset += bytesRead;
```

Obteve-se o seguinte resultado:

![echo2](images/echo2.png)

A R-ADPU confirma-se pelo seguinte:

![hex2](images/hex2.png)

## 3.1

Inicialmente, foi compilado e executado o *applet* **Wallet**, através do `Maven`. O output obtido foi o seguinte:

![wallet1](images/wallet1.png)

No ficheiro `App.java` é criado um array *installData* com os dados da instalação do applet:

```java	
byte[] installData = new byte[] {
    (byte) aid.length,       // AID length (9)
    // AID (9 bytes)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    // PIN
    0x02,
    // PIN bytes
    0x12, 0x34
};
```

Cada linha de código abaixo simula uma ação do utilizador.

```java
send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x34 }); // Verifica PIN correto
send(simulator, new byte[] { 0x50, 0x30, 0x00, 0x00, 0x01, 0x20 }); // Credito
send(simulator, new byte[] { 0x50, 0x40, 0x00, 0x00, 0x01, 0x0F }); // Debito
send(simulator, new byte[] { 0x50, 0x50, 0x00, 0x00, 0x00 });       // Saldo
```

Depois de analisar o *applet* foi verificado o que acontece quando se manda o PIN incorreto.

```java
send(simulator, new byte[] { 0x50, 0x20, 0x00, 0x00, 0x02, 0x12, 0x35 }); // Verifica PIN incorreto
send(simulator, new byte[] { 0x50, 0x30, 0x00, 0x00, 0x01, 0x20 }); // Credita 32
send(simulator, new byte[] { 0x50, 0x40, 0x00, 0x00, 0x01, 0x0F }); // Debita 15
send(simulator, new byte[] { 0x50, 0x50, 0x00, 0x00, 0x00 });       // Ver saldo
```

A resposta foi a seguinte:

![walletpininvalid](images/wallet_invalid_pin.png)

Assim, conseguimos ver que o resultado foi `63 00` e `63 01` que correspondem a verificação errada e verificação necessária, respetivamente. Abaixo, podemos ver a confirmação do resultado obtido, que se encontra no *applet* `Wallet.java`.

```java
final static short SW_VERIFICATION_FAILED = 0x6300;
final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
```

De seguida, verificou-se o que acontece quando se manda várias vezes o PIN incorreto.

![walletblocked](images/wallet_pin_blocked.png)




