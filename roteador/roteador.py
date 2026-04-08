# pyright: reportMissingImports=false

"""Monitor e defesa do roteador do laboratório.

O script usa Scapy para inspecionar o tráfego em tempo real e configura regras
de firewall para bloquear assinaturas de payload e padrões clássicos de scan.
"""

from __future__ import annotations

import ipaddress
import subprocess
import sys
import time
from collections import deque
from typing import Deque, Dict, Iterable, List, Optional

from scapy.all import IP, Raw, TCP, get_if_list, sniff


SERVER_IP = "10.0.1.2"
FIREWALL_CHAIN = "MC833_DEFENSE"
SYN_WINDOW_SECONDS = 2.0
SYN_THRESHOLD = 12

# Assinaturas de payload que o roteador bloqueia por conteúdo.
PAYLOAD_SIGNATURES = [
	"mc833::attack::",
	"drop table",
	"union select",
	"or 1=1",
	";cat /etc/passwd",
	"bash -i",
	"nc -e",
	"wget http",
	"curl http",
]


def run_command(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
	return subprocess.run(args, check=check, text=True, capture_output=True)


def rule_exists(args: List[str]) -> bool:
	completed = subprocess.run(args, text=True, capture_output=True)
	return completed.returncode == 0


def ensure_chain() -> None:
	run_command(["iptables", "-N", FIREWALL_CHAIN], check=False)
	run_command(["iptables", "-F", FIREWALL_CHAIN])

	if not rule_exists(["iptables", "-C", "FORWARD", "-j", FIREWALL_CHAIN]):
		run_command(["iptables", "-I", "FORWARD", "1", "-j", FIREWALL_CHAIN])

	base_rules = [
		["iptables", "-A", FIREWALL_CHAIN, "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"],
		["iptables", "-A", FIREWALL_CHAIN, "-p", "tcp", "--tcp-flags", "ALL", "FIN", "-j", "DROP"],
		["iptables", "-A", FIREWALL_CHAIN, "-p", "tcp", "--tcp-flags", "ALL", "FIN,PSH,URG", "-j", "DROP"],
		[
			"iptables",
			"-A",
			FIREWALL_CHAIN,
			"-p",
			"tcp",
			"--syn",
			"-d",
			SERVER_IP,
			"-m",
			"hashlimit",
			"--hashlimit-name",
			"mc833_syn_guard",
			"--hashlimit-mode",
			"dstip",
			"--hashlimit-above",
			"15/second",
			"--hashlimit-burst",
			"20",
			"--hashlimit-htable-expire",
			"60000",
			"-j",
			"DROP",
		],
	]

	for signature in PAYLOAD_SIGNATURES:
		base_rules.append(
			[
				"iptables",
				"-A",
				FIREWALL_CHAIN,
				"-p",
				"tcp",
				"-m",
				"string",
				"--algo",
				"bm",
				"--string",
				signature,
				"-j",
				"DROP",
			]
		)

	for rule in base_rules:
		run_command(rule)


def payload_bytes(packet) -> bytes:
	if packet.haslayer(Raw):
		return bytes(packet[Raw].load)
	return b""


def match_payload_signature(payload: bytes) -> Optional[str]:
	if not payload:
		return None

	lowered = payload.lower()
	for signature in PAYLOAD_SIGNATURES:
		if signature.encode("utf-8") in lowered:
			return signature
	return None


def classify_tcp_flags(flags_value: int) -> Optional[str]:
	if flags_value == 0:
		return "NULL"
	if flags_value == 0x01:
		return "FIN"
	if flags_value == 0x02:
		return "SYN"
	if flags_value == 0x29:
		return "XMAS"
	return None


def sniff_interfaces() -> Iterable[str] | str:
	interfaces = [
		iface
		for iface in get_if_list()
		if iface.startswith("eth") or iface.startswith("en")
	]
	if not interfaces:
		return "any"
	return "any" if "any" in interfaces else interfaces


def handle_packet(packet, syn_history: Deque[float], alert_state: Dict[str, bool]) -> None:
	if IP not in packet or TCP not in packet:
		return

	ip_layer = packet[IP]
	tcp_layer = packet[TCP]

	# O tráfego de interesse para o laboratório é o que chega ao servidor.
	if ip_layer.dst != SERVER_IP:
		return

	flags_value = int(tcp_layer.flags)
	payload = payload_bytes(packet)
	signature = match_payload_signature(payload)
	flag_label = classify_tcp_flags(flags_value)

	if signature:
		print(
			f"[ALERTA] assinatura de payload detectada em {ip_layer.src}:{tcp_layer.sport} -> "
			f"{ip_layer.dst}:{tcp_layer.dport} | assinatura={signature}"
		)
		return

	if flag_label in {"NULL", "FIN", "XMAS"}:
		print(
			f"[ALERTA] scan TCP suspeito detectado em {ip_layer.src}:{tcp_layer.sport} -> "
			f"{ip_layer.dst}:{tcp_layer.dport} | flags={flag_label}"
		)
		return

	if flag_label == "SYN" and not payload:
		now = time.monotonic()
		syn_history.append(now)

		while syn_history and now - syn_history[0] > SYN_WINDOW_SECONDS:
			syn_history.popleft()

		if len(syn_history) >= SYN_THRESHOLD and not alert_state["syn_burst_reported"]:
			alert_state["syn_burst_reported"] = True
			print(
				f"[ALERTA] burst de SYN identificado para {SERVER_IP} | "
				f"janela={SYN_WINDOW_SECONDS:.1f}s | pacotes={len(syn_history)}"
			)

	print(
		f"[OK] pacote aceito {ip_layer.src}:{tcp_layer.sport} -> "
		f"{ip_layer.dst}:{tcp_layer.dport} | flags={tcp_layer.sprintf('%TCP.flags%')} "
		f"| payload_bytes={len(payload)}"
	)


def main() -> int:
	try:
		ipaddress.ip_address(SERVER_IP)
	except ValueError:
		print(f"[ERRO] IP do servidor invalido: {SERVER_IP}")
		return 1

	try:
		ensure_chain()
	except subprocess.CalledProcessError as exc:
		print("[ERRO] nao foi possivel configurar o firewall do roteador.")
		if exc.stdout:
			print(exc.stdout.strip())
		if exc.stderr:
			print(exc.stderr.strip())
		return 1

	print("[INFO] defesa do roteador ativa")
	print(f"[INFO] servidor protegido: {SERVER_IP}")
	print(f"[INFO] interfaces monitoradas: {sniff_interfaces()}")
	print("[INFO] assinatura de payload ativa e regras de drop carregadas")

	syn_history: Deque[float] = deque()
	alert_state: Dict[str, bool] = {"syn_burst_reported": False}

	def callback(packet) -> None:
		handle_packet(packet, syn_history, alert_state)

	try:
		sniff(iface=sniff_interfaces(), filter="tcp", prn=callback, store=False)
	except KeyboardInterrupt:
		print("\n[INFO] encerrando defesa do roteador")
	except Exception as exc:  # pragma: no cover - caminho de erro operacional
		print(f"[ERRO] falha durante o sniffer: {exc}")
		return 1

	return 0


if __name__ == "__main__":
	sys.exit(main())
