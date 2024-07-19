import tkinter as tk
from tkinter import messagebox, filedialog
import logging
import os
import csv
import json
from scapy.all import srp, Ether, ARP

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def save_changes(arquivo, resultados):
    """Salva as alterações no arquivo"""
    try:
        resposta = messagebox.askyesno("Salvar alterações", "Deseja salvar as alterações no arquivo?")
        if resposta:
            with open(arquivo, 'a') as f:
                for resultado in resultados:
                    f.write(f"{str(resultado['mac'])} {str(resultado['ip'])}\n")
            logging.info("Alterações salvas")
        else:
            logging.info("Alterações não foram salvas")
    except Exception as e:
        logging.error(f"Erro ao salvar alterações: {e}")
        messagebox.showerror("Erro", f"Ocorreu um erro ao salvar alterações: {e}")

def save_results_csv(arquivo, resultados):
    """Salva os resultados em um csv"""
    try:
        with open(arquivo, 'w', newline='') as csvfile:
            fieldnames = ['mac', 'ip']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for resultado in resultados:
                writer.writerow({'mac': str(resultado['mac']), 'ip': str(resultado['ip'])})
        logging.info(f"Resultados salvos em {arquivo}")
    except Exception as e:
        logging.error(f"Erro ao salvar resultados em CSV: {e}")
        messagebox.showerror("Erro", f"Ocorreu um erro ao salvar em CSV: {e}")

def save_results_json(arquivo, resultados):
    """Salva os resultados em um json"""
    try:
        with open(arquivo, 'w') as jsonfile:
            json.dump(resultados, jsonfile, indent=4)
        logging.info(f"Resultados salvos em {arquivo}")
    except Exception as e:
        logging.error(f"Erro ao salvar resultados em JSON: {e}")
        messagebox.showerror("Erro", f"Ocorreu um erro ao salvar em JSON: {e}")

def show_results(resultados):
    """Exibe os resultados na interface"""
    resultados_text.delete(1.0, tk.END)
    for resultado in resultados:
        resultados_text.insert(tk.END, f"MAC: {str(resultado['mac'])} - IP: {str(resultado['ip'])}\n")

def arp_ping(host, arquivo_saida, timeout):
    """Executa o ARP Ping"""
    try:
        # Limpa o arquivo temporário
        open("temporario2.txt", 'w').close()

        # Abre o arquivo de saída e lê as linhas existentes
        if not os.path.exists(arquivo_saida):
            open(arquivo_saida, 'w').close()  # Cria o arquivo se não existir

        with open(arquivo_saida, 'r') as f1:
            existing_lines = f1.readlines()

        resultados = []
        with open("temporario.txt", 'w') as f2:
            # Envia pacotes ARP
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=timeout, verbose=False)
            ans.summary(lambda s, r: f2.write(f"{str(r[Ether].src)} {str(r[ARP].psrc)}\n"))

        with open("temporario.txt", 'r') as f:
            with open("temporario2.txt", 'a') as f3:
                for linha2 in f:
                    if linha2 not in existing_lines:
                        f3.write(linha2)
                        mac, ip = linha2.strip().split()
                        resultados.append({'mac': mac, 'ip': ip})

        with open("temporario2.txt", 'r') as f3:
            total = sum(1 for _ in f3)

        if total > 0:
            save_changes(arquivo_saida, resultados)

        return resultados
    except Exception as e:
        logging.error(f"Erro durante o ARP Ping: {e}")
        messagebox.showerror("Erro", f"Ocorreu um erro durante o ARP Ping: {e}")
        return []

def start_arp_ping():
    """Inicia o ARP Ping na interface"""
    host = entrada_ip.get()
    arquivo_saida = entrada_arquivo.get()
    try:
        timeout = float(entrada_timeout.get())
    except ValueError:
        messagebox.showerror("Erro", "Timeout deve ser um número")
        return

    if not host or not arquivo_saida:
        messagebox.showerror("Erro", "Por favor, preencha todos os campos")
        return

    logging.info(f"Iniciando ARP Ping na faixa de IPs: {host}")
    try:
        resultados = arp_ping(host, arquivo_saida, timeout)
        show_results(resultados)
        logging.info("ARP Ping concluído")
        messagebox.showinfo("Concluído", "ARP Ping concluído com sucesso")
    except Exception as e:
        logging.error(f"Erro durante o ARP Ping: {e}")
        messagebox.showerror("Erro", f"Ocorreu um erro: {e}")

def save_as_csv():
    """Salva os resultados exibidos em um arquivo csv"""
    resultados = resultados_text.get(1.0, tk.END).strip().split('\n')
    if not resultados:
        messagebox.showerror("Erro", "Nenhum resultado para salvar")
        return

    resultados_formatados = []
    for resultado in resultados:
        if resultado.strip():  # Verifica se a linha não está vazia
            try:
                mac, ip = resultado.replace('MAC: ', '').replace(' - IP: ', '').split()
                resultados_formatados.append({'mac': mac, 'ip': ip})
            except ValueError as e:
                logging.error(f"Erro ao processar resultado: {resultado} - {e}")

    arquivo_csv = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if arquivo_csv:
        save_results_csv(arquivo_csv, resultados_formatados)

def save_as_json():
    """Salva os resultados exibidos em um arquivo json"""
    resultados = resultados_text.get(1.0, tk.END).strip().split('\n')
    if not resultados:
        messagebox.showerror("Erro", "Nenhum resultado para salvar")
        return

    resultados_formatados = []
    for resultado in resultados:
        if resultado.strip():  # Verifica se a linha não está vazia
            try:
                mac, ip = resultado.replace('MAC: ', '').replace(' - IP: ', '').split()
                resultados_formatados.append({'mac': mac, 'ip': ip})
            except ValueError as e:
                logging.error(f"Erro ao processar resultado: {resultado} - {e}")

    arquivo_json = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if arquivo_json:
        save_results_json(arquivo_json, resultados_formatados)

# Configuração da interface gráfica
janela = tk.Tk()
janela.title("ARP Ping")
janela.geometry("600x400")

# Frame principal
frame_principal = tk.Frame(janela)
frame_principal.pack(fill=tk.BOTH, expand=True)

# Campos de entrada
frame_entrada = tk.Frame(frame_principal)
frame_entrada.pack(fill=tk.X, padx=10, pady=10)

tk.Label(frame_entrada, text="Faixa de IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
entrada_ip = tk.Entry(frame_entrada)
entrada_ip.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

tk.Label(frame_entrada, text="Arquivo de Saída:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
entrada_arquivo = tk.Entry(frame_entrada)
entrada_arquivo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

tk.Label(frame_entrada, text="Timeout:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
entrada_timeout = tk.Entry(frame_entrada)
entrada_timeout.insert(0, "2")
entrada_timeout.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

# Expandir entradas horizontalmente
frame_entrada.grid_columnconfigure(1, weight=1)

# Botão para iniciar o ARP Ping
frame_botao = tk.Frame(frame_principal)
frame_botao.pack(fill=tk.X, padx=10, pady=10)

botao_iniciar = tk.Button(frame_botao, text="Iniciar ARP Ping", command=start_arp_ping)
botao_iniciar.pack(pady=5)

# Área de texto para exibir resultados
frame_resultados = tk.Frame(frame_principal)
frame_resultados.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

resultados_text = tk.Text(frame_resultados)
resultados_text.pack(fill=tk.BOTH, expand=True)

# Botões para salvar resultados em diferentes formatos
frame_salvar = tk.Frame(frame_principal)
frame_salvar.pack(fill=tk.X, padx=10, pady=10)

botao_salvar_csv = tk.Button(frame_salvar, text="Salvar como CSV", command=save_as_csv)
botao_salvar_csv.pack(side=tk.LEFT, padx=5)

botao_salvar_json = tk.Button(frame_salvar, text="Salvar como JSON", command=save_as_json)
botao_salvar_json.pack(side=tk.LEFT, padx=5)

# Iniciar o loop da interface gráfica
janela.mainloop()
