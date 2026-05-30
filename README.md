😈 NekotinaCat Frameworks v5.0.1 — CRIMSON WATCHER

🐱‍💻 Linux Rescue Toolkit · Dark Edition · by psyhusk
💜 Apoie o Desenvolvimento
O NekotinaCat é um projeto de código aberto, arquitetado e desenvolvido 100% em ambiente mobile. Meu objetivo é criar ferramentas de alta performance que facilitem o fluxo de trabalho de profissionais da área, mesmo com as limitações técnicas do meu setup atual.

Se esta ferramenta foi útil para você, considere apoiar o projeto:

👉 patreon.com/cw/Psyhusk/membership
Seu apoio é fundamental para que eu possa continuar dedicando tempo integral ao desenvolvimento, à correção de bugs e à implementação de novas funcionalidades.

Todo apoio é muito bem-vindo e me ajuda a manter este ecossistema vivo e em constante evolução. 🙏# NekotinaCat_Framework v5.0.1 — CRIMSON SENTINEL

> Ferramenta de monitoramento defensivo de segurança para sistemas Linux/Unix.

---

## Estrutura dos arquivos

```
nekotinacat/
├── nekotinacat.py            ← Aplicação principal (GUI)
├── nekotinacat_installer.py  ← Instalador gráfico
├── build_nekotinacat.py      ← Script de build (PyInstaller)
└── README.md
```

---

## Instalação rápida (sem build)

```bash
# Instalar dependências
pip install psutil

# Instalar tkinter (se necessário)
sudo apt install python3-tk    # Debian/Ubuntu
sudo dnf install python3-tkinter  # Fedora

# Rodar o instalador gráfico
python3 nekotinacat_installer.py

# Ou rodar direto
python3 nekotinacat.py
```

---

## Gerar executável standalone

```bash
pip install pyinstaller psutil Pillow

python3 build_nekotinacat.py
# Saída: dist/NekotinaCat_Framework  (Linux/macOS)
# Saída: dist/NekotinaCat_Framework.exe  (Windows)
```

---

## Funcionalidades

### ◈ Dashboard
- CPU, RAM, rede em tempo real
- Informações de firmware/BIOS/UEFI
- Produto, placa-mãe, Secure Boot

### ⚡ Vulnerability Scanner
- CVEs de CPU (Spectre, Meltdown, Retbleed, MDS, L1TF…)
- Configuração SSH insegura (root login, senha vazia, etc.)
- Usuários com UID 0 indevido / senhas vazias
- Status do firewall (ufw/iptables)
- Binários SUID suspeitos
- Crontabs com comandos maliciosos

### 🦠 Malware & Rootkit Scanner
- Processos suspeitos (netcat, miners, metasploit…)
- Entradas de autorun suspeitas (systemd, ~/.config/autostart)
- Arquivos ocultos em /tmp e /var/tmp
- Indicadores de rootkits (chkrootkit, arquivos em /dev)

### 🌐 Network Analyzer
- Lista de interfaces e endereços
- Conexões ativas (TCP/UDP) com PIDs
- Detecção de modo promíscuo (sniffers)

### 🔧 System Inspector
- Info completa de OS, kernel, distro
- BIOS/UEFI, fabricante, produto, placa
- Configurações sysctl de segurança (ASLR, SYN cookies…)
- Lista de discos/partições

### 📋 Log de Eventos
- Histórico completo de scans e alertas

---

## Ferramentas do sistema recomendadas

```bash
sudo apt install \
  chkrootkit rkhunter \
  smartmontools ufw \
  iproute2 procps util-linux
```

---

## Design da interface

- Janela frameless com fundo transparente/escuro
- Gato com **olhos vermelhos brilhantes** desenhado em canvas Tk
- **Pentagrama** pulsante com glow vermelho animado
- Borda com animação de glow crimson
- Paleta CRIMSON SENTINEL — `#cc1a1a` / `#ff3333` / `#060404`
