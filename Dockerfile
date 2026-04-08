FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Instala ferramentas de rede, Python e os serviços do servidor
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    iproute2 iputils-ping tcpdump \
    iptables \
    nginx mysql-server telnetd xinetd ngrep  -y \
    && rm -rf /var/lib/apt/lists/*

# Instala as bibliotecas Python para o gerador de tráfego e sniffer
RUN pip3 install scapy requests mysql-connector-python 

# Configuração prévia do banco de dados e usuário telnet (apenas para o lab)
RUN service mysql start && \
    mysql -e "CREATE USER 'aluno'@'%' IDENTIFIED BY 'lab123'; GRANT ALL PRIVILEGES ON *.* TO 'aluno'@'%'; FLUSH PRIVILEGES;" && \
    useradd -m -s /bin/bash aluno && echo "aluno:senha123" | chpasswd