## --------------------------------------------------------------------------
## Durante a resolução desse laboratório você NÃO DEVE alterar esse arquivo.
## --------------------------------------------------------------------------
import time
import random
import requests
import telnetlib
import mysql.connector

SERVER_IP = "10.0.1.2"

def gerar_trafego_http():
    try:
        for _ in range(10):
            requests.get(f"http://{SERVER_IP}", timeout=1)
        print("[HTTP].")
    except: pass

def gerar_trafego_telnet():
    try:
        tn = telnetlib.Telnet(SERVER_IP, 23, timeout=5)
        tn.read_until(b"login: ")
        time.sleep(1.5) # Delay proposital
        tn.write(b"aluno\n")
        tn.read_until(b"Password: ")
        time.sleep(2.0) # Delay proposital
        tn.write(b"lab123\n")
        tn.write(b"ls -la\n")
        tn.write(b"exit\n")
        print("[TELNET] Padrão DELAY executado.")
    except: pass

def gerar_trafego_mariadb():
    try:
        conn = mysql.connector.connect(host=SERVER_IP, user='aluno', password='lab123')
        cursor = conn.cursor()
        for _ in range(30):
            cursor.execute("SELECT VERSION(), DATABASE(), USER();")
            cursor.fetchall()
        conn.close()
        print("[MARIADB] Padrão BULK executado (30 queries).")
    except: pass

if __name__ == "__main__":
    while True:
        for tarefa in [gerar_trafego_http, gerar_trafego_mariadb, gerar_trafego_telnet]:
            tarefa()
            time.sleep(random.randint(0,100)/100)