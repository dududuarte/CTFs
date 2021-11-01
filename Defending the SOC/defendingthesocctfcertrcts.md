## Written by duartemcg
# A simple challenge
Trata-se de uma string que foi varias vezes codificada com base64, apenas necessitamos de fazer a sua decoficação online
<br>

# Welcome to Lisbon!
Examinei a foto no forensically e pudi perceber mais ou menos a fotografia que estava a procura, reparei tambem que estava algo escrito em Portugues e por isso tinha o algoritmo do google a meu favor assim que pesquisa-se por "Victoria Secret".
Após alguma pesquisas com a imagem inicial, encontrei uma foto parecida com a que tinha (1), era a Sara Sampaio, mas se olharmos novamente bem para o forensically verificamos que a disposição da modelo não é igual: https://puu.sh/I2RQd/535d9e6d49.gif 

Entao procurei fotos da montra em que a modelo pode-se estar igual e finalmente encontrei (2). Agora apenas falta saber o nome da modelo.
Pesquisando pelos seus atributos "cabelo escuro e olhos azuis" chegamos a um número de modelos mais pequeno, resta agora tentar ver qual delas é... e após algum tempo podemos determinar que era a Adriana lima


(1)https://fastly.4sqi.net/img/general/200x200/1926325_Cm_1Bpf2_KsQT4ZlFbkKNqnRQBXS6Cyz3cNfaOu64YY.jpg
(2)https://fotos.web.sapo.io/i/Bf40107bb/15526902_qtTvi.jpeg

<br><br>

# Hiding in plain sight
Este exercicio trata-se novamente de usar o forensically, e ao olhar para a string extraction reparei que tinhamos "flag{}".

<br><br>

# Roman Encryption 
Devemos tar a falar da cifra de caesar ou uma evolucao sua a keyed caesar cipher, mas normalmente indicamos o numero de transcrição de letra na cifra de caesar por isso diria que apenas poderá ser a segunda "versão".
Após uma pesquisa online consegui encontrar um bom decoder (3) e tentei a keyword "Julius" visto que seria o possível keyword usado na cifra. Sem change acabei por tentar o Auto Solve do mesmo website ao qual obtive a seguinte várias possibildiades onde a chave "gxiusjwcerbdmhkafopqtvlnyz" é a que apresentava melhor score. 

(3)https://www.boxentriq.com/code-breaking/keyed-caesar-cipher
<br><br>

# Hextraordinary security:
Ao sacar o ficheiro podemos observar o que possivelmente é um hexaDump. Seguindo este raciocinio, podemos ver a sua conversão para ASCII e fazer grep "flag" para ver se encontramos alguma coisa.
cat garbage\?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjEzMywiZmlsZV9pZCI6NX0.YRKSag.mcJ2BhL6_7k9Tg5l7dir4-VzscU | xxd -r -p | grep "flag"

xxd:
-r tells it to convert hex to ascii as opposed to its normal mode of doing the opposite
-p tells it to use a plain format.

<br><br>

# Some type of juggling:
Ao ligar-nos ao webserver podemos observar um link com hyperligacao para o source code. Ao observarmos melhor o código podemos ver as seguintes linhas:
```
$value = "240610708";
        if (isset($_GET['hash'])) {
            if ($_GET['hash'] === $value) {
                die('It is not THAT easy!');
            } 
            $hash = md5($_GET['hash']);
            $key = md5($value);
            if($hash == $key) {
                include('flag.php');
                print "Congratulations! Your flag is: $flag";
            } else {
                print "Flag not found!";
            }
```
e podemos entao ver que o print da flag é feito quando $_GET['hash'] !== $value /\ md5($_GET['hash']) ==  $key

Após visualizar melhor como funcionam a Loose e Strict Comparison estava na hora de tentar no nosso sandbox.
```
<?php
$value = "240610708";
$hash = md5('240610708');
$key = md5($value);
if($hash == $key){
    echo("flag here\n\n");
}
echo("Hash:".$hash);
echo("\nKey: ".$key);
?>
flag here
```
Hash:0e462097431906509019562988736854
Key: 0e462097431906509019562988736854

Mas quando vou tentar inserir http://challenges.defsoc.tk:8080/?hash='240610708' passamos a primeira flag mas nao entra no if ($hash == $key)... porque será?

Após algum tempo de pesquisa pensei em consultar o CTF-Katana e deparei-me com Magic Hashes, e após tentar perceber um pouco melhor (https://www.whitehatsec.com/blog/magic-hashes/) tentei o valor QNKCDZO.
Obti a flag: flag{php_typ3_juggl1ng_1s_c00l}

<br><br>

# Exclusive access
Ao entrarmos no site http://challenges.defsoc.tk:9999/ podemos ver que a autenticação foi realizada por cookies, e no caso de usarmos Cookie-Editor (extenção do Mozilla) podemos facilmente observar o seu valor. Tentei descodificar o mesmo num base64 decoder(4) para ver se obtia algum valor, e obtive "guest7".
Desta maneira tentei então codificar "admin" em base64 visto que o site indica "ADMIN only".
Desta maneira obtive então a flag{br0k3n_auth3nt1c4t10n}

(4)-https://www.base64encode.net/


:Welcome to the challenge:
Ao sacar a imagem e tentar novamente o que fiz no anterior não consigo obter a meu ver, qualquer informação possível, sendo assim tento usar o binwalk para ver se posso extrair algo da propria imagem.


:About us:
Sendo que se trata de um ficheiro pdf a primeira ideia a cabeça foi de correr uma busca de strings com a palavra flag:

$ strings RCTSCERT-FCCN.pdf\?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjEzMywiZmlsZV9pZCI6OH0.YRK9mQ.lbC0MjuDLUT38rFuRydGEMp6xYg | grep "flag"
└─<pdfx:Flag>flag{4b0ut_us_4t_rcts_c3rt}</pdfx:Flag>
  
<br><br>

# It is Magic after all
```
<?php 
include "flag.php";  

class Magic {
    public $key;

    public function doMagic() {
        if ($this->key === true) {
          global $flag;
          echo $flag;
        }
        else {
            echo "Nothing...";
        }
    }
}

if (isset($_GET['magic'])) {  
    $magic = unserialize($_GET['magic']); 
    $magic->doMagic();
} else {
    print "Nothing...";
}  

?>
```
Ao olhar para o código podemos observar que para chegarmos a flag necessitamos de executar o doMagic() e enviar key=true para que passe o if clause.
É importante denotar que o objeto é criado apartir dos dados serializados recebidos pelo URL (?magic='').
Como não sei como é feita a tradução de objeto para serializado, vou tentar fazer uma pequena sandbox em que envio manualmente o objeto e dou echo do seu "serializable"
Eis a minha solução para saber o valor que teria de inserir no URL:
```
<?php 

class Magic {
    public $key = true;
/*
    public function doMagic() {
        if ($this->key === true) {
          echo $flag;
        }
        else {
            echo "Nothing...";
        }
    }
*/
}
$magic = new Magic;
    echo(serialize($magic));
    
?>
```
Result: O:5:"Magic":1:{s:3:"key";b:1;}
E ao inserir este valor no URL (?magic=O:5:"Magic":1:{s:3:"key";b:1;}) obti a flag{php_d3s3r14l1z4t10n_3xpl01ts}
<br><br>

# Something Suspicious
Ao sacar os dois log files tentei fazer o tipico grep "flag" e apos nao retornar nada tentei então simplesmente ler os logs.
Ao olhar para o log do ftp, ve-se vários logins, excepto que um deles está cifrado em base64 (ZmxhZ3tzMG0zdGgxbmc=), que corresponde a metade da flag ("flag{s0m3th1ng"). Como o log do ssh é um bocado maior decidi aplicar grep a tipicas keywords (password, user) e após aplicar user, reparo numa string codificada com o valor cifrado (X3N1c3AxYzEwdXN9):
└─``$ cat ssh.log\?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjEzMywiZmlsZV9pZCI6Mjl9.YRLFNQ.K6H3kyS7yBUHriMpFpI_5GO5wUs | grep "user"``

``                    
Jun 25 00:29:58 lockedout auth.info sshd[2875]: Connection closed by authenticating user root 192.128.1.23 port 53496 [preauth]
Jun 25 00:32:43 lockedout auth.info sshd[2897]: Disconnected from authenticating user root 192.128.1.23 port 53498 [preauth]
Jun 25 00:32:44 lockedout auth.info sshd[2899]: Disconnecting authenticating user root 192.128.1.23 port 53500: Too many authentication failures [preauth]
Jun 25 00:33:12 lockedout auth.info sshd[2905]: Disconnecting authenticating user root 192.128.1.23 port 53502: Too many authentication failures [preauth]
Jun 25 00:33:48 lockedout auth.info sshd[2910]: Disconnecting authenticating user root 192.128.1.23 port 53504: Too many authentication failures [preauth]
Jun 25 00:34:20 lockedout auth.info sshd[2912]: Disconnecting authenticating user root 192.128.1.23 port 53506: Too many authentication failures [preauth]
Jun 25 00:34:52 lockedout auth.info sshd[2921]: Disconnecting authenticating user root 192.128.1.23 port 53508: Too many authentication failures [preauth]
Jun 25 00:35:24 lockedout auth.info sshd[2927]: Disconnecting authenticating user root 192.128.1.23 port 53510: Too many authentication failures [preauth]
Jun 25 00:35:56 lockedout auth.info sshd[2932]: Disconnecting authenticating user root 192.128.1.23 port 53500: Too many authentication failures [preauth]
Jun 25 00:36:28 lockedout auth.info sshd[2938]: Disconnecting authenticating user root 192.128.1.23 port 53514: Too many authentication failures [preauth]
Jun 25 00:37:00 lockedout auth.info sshd[2944]: Disconnecting authenticating user root 192.128.1.23 port 53500: Too many authentication failures [preauth]
Jun 25 00:37:32 lockedout auth.info sshd[2949]: Disconnecting authenticating user root 192.128.1.23 port 53518: Too many authentication failures [preauth]
Jun 25 00:49:14 lockedout auth.info sshd[3029]: Invalid user X3N1c3AxYzEwdXN9 from 192.168.1.23 port 53522
Jun 25 00:49:16 lockedout auth.info sshd[3029]: Failed password for invalid user X3N1c3AxYzEwdXN9 from 192.168.1.23 port 53522 ssh2
Jun 25 00:49:16 lockedout auth.info sshd[3029]: Failed password for invalid user X3N1c3AxYzEwdXN9 from 192.168.1.23 port 53522 ssh2
Jun 25 00:49:17 lockedout auth.info sshd[3029]: Failed password for invalid user X3N1c3AxYzEwdXN9 from 192.168.1.23 port 53522 ssh2
Jun 25 00:49:17 lockedout auth.info sshd[3029]: Connection closed by invalid user X3N1c3AxYzEwdXN9 192.168.1.23 port 53522 [preauth]
Jun 25 00:57:31 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52518 [preauth]
Jun 25 00:57:34 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52520 [preauth]
Jun 25 00:57:50 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52526 [preauth]
Jun 25 00:57:54 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52528 [preauth]
Jun 25 00:57:31 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52530 [preauth]
Jun 25 00:57:34 lockedout auth.info sshd[2215]: Connection closed by authenticating user root 192.168.1.23 port 52532 [preauth]
``
Descodificando o valor temos a flag: flag{s0m3th1ng_susp1c10us}

# Decrypting the payload:
Dizem-nos que acham que o ficheiro .xls pode ter sido o ponto de entrada na rede, e ao sacar-o pela windows primeiramente aponta virus de facto. Saco então na máquina linux para proceder à procura de ficheiros escondidos dentro do xls:
```
binwalk -e Account_report.xlsm\?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjEzMywiZmlsZV9pZCI6MTh9.YRLJTQ.prd2PCATxD3x__dM6zhhZqcAj9g 
```
Obtemos alguns ficheiros, agora vamos proceder à procura do código malicioso.
Descobrimos algumas informações como que o ultima edição foi feita por FábioMestre às 2021-06-18T15:28:17Z
