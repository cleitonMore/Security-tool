import psutil
import time
import os

# lista todas as tarefas
def list_processes():
    print("Listando processos em execução:")
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        print(proc.info)

# lista todos os processos de monitoramento
def monitor_process(target_process):
    print(f"Monitorando o processo: {target_process}")
    while True:
        found = False
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == target_process:
                print(f"Processo {target_process} (PID: {proc.info['pid']}) está em execução.")
                found = True
        if not found:
            print(f"Processo {target_process} não está em execução.")
        time.sleep(5)

# Função para dtectar todos os processos suspeitos
def detect_malware(suspicious_processes):
    print("Verificando a presença de malwares...")
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in suspicious_processes:
            print(f"Atenção! Processo suspeito detectado: {proc.info['name']} (PID: {proc.info['pid']})")


def list_connections():
    print("Listando conexões de rede ativas:")
    for conn in psutil.net_connections(kind='inet'):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status
        print(f"Local: {laddr}, Remoto: {raddr}, Status: {status}")


def list_firewall_rules():
    print("Listando regras do firewall:")
    os.system("netsh advfirewall firewall show rule name=all")


def manage_firewall(action, rule_name, protocol=None, port=None, direction=None):
    if action == "add":
        if protocol and port and direction:
            os.system(f"netsh advfirewall firewall add rule name={rule_name} protocol={protocol} dir={direction} localport={port} action=allow")
            print(f"Regra adicionada: {rule_name}, Protocolo: {protocol}, Porta: {port}, Direção: {direction}")
        else:
            print("Faltam parâmetros para adicionar a regra.")
    elif action == "delete":
        os.system(f"netsh advfirewall firewall delete rule name={rule_name}")
        print(f"Regra deletada: {rule_name}")
    else:
        print("Ação inválida. Use 'add' ou 'delete'.")

if __name__ == "__main__":
    while True:
        print("\nMenu de Segurança:")
        print("1. Listar processos em execução")
        print("2. Monitorar processo específico")
        print("3. Detectar processos suspeitos (Malware)")
        print("4. Listar conexões de rede")
        print("5. Listar regras do firewall")
        print("6. Gerenciar firewall")
        print("7. Sair")

        choice = input("Escolha uma opção: ")

        if choice == '1':
            list_processes()
        elif choice == '2':
            target_process = input("Digite o nome do processo para monitorar: ")
            monitor_process(target_process)
        elif choice == '3':
            suspicious_processes = ['malware.exe', 'virus.exe']  # Exemplos de nomes de processos suspeitos
            detect_malware(suspicious_processes)
        elif choice == '4':
            list_connections()
        elif choice == '5':
            list_firewall_rules()
        elif choice == '6':
            action = input("Digite a ação (add/delete): ")
            rule_name = input("Digite o nome da regra: ")
            if action == "add":
                protocol = input("Digite o protocolo (TCP/UDP): ")
                port = input("Digite a porta: ")
                direction = input("Digite a direção (in/out): ")
                manage_firewall(action, rule_name, protocol, port, direction)
            else:
                manage_firewall(action, rule_name)
        elif choice == '7':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")