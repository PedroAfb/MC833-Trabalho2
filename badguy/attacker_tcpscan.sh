#!/bin/bash

sed -i "/10.0.1.0/d" /etc/zamp/blacklist.conf 2> /dev/nnull || true

IP_ALVO="10.0.1.2"
SUBNET_ALVO="10.0.1.0/24"
INTERFACE="eth0"
GATEWAY="10.0.2.254"
IP_ORIGINAL="10.0.2.42"

change_ip() {
    local novo_ip=$1
    echo "[*] Alterando IP de Origem para: $novo_ip"
    ip addr flush dev $INTERFACE
    ip addr add $novo_ip/24 dev $INTERFACE
    ip link set $INTERFACE up
    ip route add default via $GATEWAY
}

###################################
# NMAP SCANS
###################################

tcp_syn_scan() {
    change_ip "10.0.2.101"
    echo "> nmap TCP SYN Scan -> $IP_ALVO"
    nmap -sS -Pn -n $IP_ALVO
}

tcp_connect_scan() {
    #TCP Connect Scan
    change_ip "10.0.2.102"
    echo "> nmap TCP Connect Scan -> $IP_ALVO"
    nmap -sT -Pn -n $IP_ALVO
}

tcp_null_scan() {
    #TCP NULL Scan
    change_ip "10.0.2.103"
    echo "> nmap TCP NULL Scan -> $IP_ALVO"
    nmap -sN -Pn -n $IP_ALVO
}

tcp_xmax_scan() {
    #TCP XMAS Scan
    change_ip "10.0.2.104"
    echo "> namp TCP XMAX Scan -> $IP_ALVO"
    nmap -sX -Pn -n $IP_ALVO
}


###################################
# HPING3 (Simulação de DoS/Probe)
###################################

hping3_tcp() {
    #hping3 TCP
    change_ip "10.0.2.110"
    echo "> hping TCP SYN Scan (1000 pacotes) -> $IP_ALVO"
    hping3 $IP_ALVO -c 1000 -d 120 -S -p 80 --fast
}

hping3_tcp_fin() {
    #hping3 TCP FIN
    change_ip "10.0.2.111"
    echo "> hping3 TCP FIN Scan -> $IP_ALVO"
    hping3 $IP_ALVO -c 1000 -F -p 80 --fast
}

###################################
# MASSCAN (Scan de alta velocidade)
###################################

masscan_fn() {
    change_ip "10.0.2.120"
    echo "> masscan na Rede A: $SUBNET_ALVO"
    masscan -p0-1000 $SUBNET_ALVO --rate 1000 -e $INTERFACE --route-ip $GATEWAY

}

ataques=("tcp_syn_scan" "tcp_connect_scan" "tcp_null_scan" "tcp_xmax_scan" "hping3_tcp" "hping3_tcp_fin" "masscan_fn")

total=${#ataques[@]}

while true; do
    sleep 5
    # Sorteia um índice aleatório entre 0 e (TOTAL-1)
    INDICE=$(( RANDOM % total ))
    
    echo "----------------------------------------------------"
    date
    ${ataques[$INDICE]}
done