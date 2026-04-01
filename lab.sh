#!/bin/bash

export UID_ALUNO=$(id -u)
export GID_ALUNO=$(id -g)
export USER=$(whoami)

# --- Caminhos Fixos (Sem data) ---
PASTA_LOCAL="/tmp/docker_lab_${USER}"
PASTA_NFS="./dados_de_persistencia"

# --- Função de Saída ---
salvar_e_sair() {
    echo -e "\n🛑 SINAL RECEBIDO! Encerrando ambiente..."
    
    # 1. Para os containers antes de mover os arquivos
    docker compose down 2>/dev/null || true

    # 2. Sincroniza Local -> NFS
    if [ -d "$PASTA_LOCAL" ]; then
        echo "💾 Salvando progresso no NFS..."
        mkdir -p "$PASTA_NFS"
        rsync -a --delete "$PASTA_LOCAL/" "$PASTA_NFS/"
    fi

    # 3. Limpeza Total do /tmp (agora podemos apagar pois o Docker parou)
    echo "🧹 Limpando arquivos temporários..."
    rm -rf "$PASTA_LOCAL"

    echo "✅ Trabalho salvo com sucesso no NFS!"
    exit
}

trap salvar_e_sair SIGINT SIGHUP SIGTERM

# --- 1. PREPARAÇÃO (NFS -> Local) ---
# Se houver lixo de uma sessão que travou, removemos para começar limpo
rm -rf "$PASTA_LOCAL"
mkdir -p "$PASTA_LOCAL"

if [ -d "$PASTA_NFS" ] && [ "$(ls -A $PASTA_NFS)" ]; then
    echo "🔄 Recuperando seus arquivos do servidor..."
    rsync -a "$PASTA_NFS/" "$PASTA_LOCAL/"
else
    echo "✨ Iniciando novo ambiente (pastas vazias)..."
    for servico in cliente servidor roteador; do
        mkdir -p "$PASTA_LOCAL/$servico"
    done
fi

# Ajusta permissão para o Docker não ter problemas
chmod -R 777 "$PASTA_LOCAL"

# --- 2. EXECUÇÃO ---
echo "🚀 Subindo o Docker..."
docker compose up -d

echo "-------------------------------------------------------"
echo "AMBIENTE ATIVO: Seus arquivos estão em $PASTA_NFS"
echo "PARA SAIR: CTRL+C ou feche a janela."
echo "-------------------------------------------------------"

docker compose logs -f &
wait $!

