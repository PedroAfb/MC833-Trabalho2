## Ambiente dos Estudantes

É através desse ambiente ao qual você irá realizar uma bagatela de experimentos e testes durante a disciplina.

Ele é feito em docker com inicialmente com cliente, roteador, servidor e badguy.

Os arquivos client.py, server.py e roteador.py e attacker_tcpscan.sh nas respectivas pastas são mapeados direto para os containers gerados pelo docker compose e docker file. Dessa forma, mantenha eles sempre com o mesmo nome e arvore de diretórios. Você pode criar novos arquivos e alterar como bem entender o corpo de cada um deses scripts desde que mantenha os nomes iguais.

O primeiro passo é instalar o [docker](https://docs.docker.com/desktop/setup/install/windows-install/). Siga os tutorias disponibilizados no site.

## Como usar

Abre um terminal dentro da pasta student-environment e execute o seguinte comando:

```bash
./lab.sh
```

Faça as alterações apenas no arquivo `./roteador/router.py` para enviar as alterações para os volumes/dockers, execute em outro terminal:

```bash
./copy-files.sh
```

Esse comando copia todos os arquivos das pastas `./client`, `./servidor`, `./roteador` `./badguy` para os volumes de cada container.

Depois basta executar os comandos para iniciar cada script.py

```bash
docker exec -it client python3 client.py
```
Em um outro terminal também execute:

```bash
docker exec -it badguy bash ./attacker_tcpscan.sh
```

Você pode verificar o tráfego no servidor através de alguma ferramenta de sniffer demonstrada na aula.