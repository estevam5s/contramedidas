import streamlit as st
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Configuração da página
st.set_page_config(
    page_title="Enciclopédia de Segurança Cibernética e Roadmap",
    page_icon="💻",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estruturas de Dados para Casos Reais de Ataques
CYBER_ATTACKS = {
    "Ransomware": {
        "WannaCry": {
            "data": "Maio 2017",
            "impacto": "Afetou mais de 200.000 computadores em 150 países",
            "prejuizo": "US$ 4 bilhões",
            "metodo": "Exploração da vulnerabilidade EternalBlue",
            "setores_afetados": ["Saúde", "Manufatura", "Governo"],
            "contramedidas": [
                "Atualização de sistemas",
                "Backup regular",
                "Segmentação de rede"
            ],
            "timeline": {
                "Dia 1": "Início do ataque na Ásia",
                "Dia 2": "Propagação para Europa",
                "Dia 3": "Alcance global",
                "Dia 7": "Desenvolvimento do kill-switch",
                "Dia 14": "Contenção principal do ataque"
            }
        },
        "NotPetya": {
            "data": "Junho 2017",
            "impacto": "Afetou grandes empresas globalmente",
            "prejuizo": "US$ 10 bilhões",
            "metodo": "Malware disfarçado de atualização de software",
            "setores_afetados": ["Logística", "Farmacêutico", "Energia"],
            "contramedidas": [
                "Verificação de assinatura digital",
                "Isolamento de sistemas críticos",
                "Políticas de atualização rigorosas"
            ],
            "timeline": {
                "Dia 1": "Início na Ucrânia",
                "Dia 2": "Propagação global",
                "Dia 5": "Impacto em operações portuárias",
                "Dia 10": "Prejuízos estimados divulgados"
            }
        }
    },
    "Vazamento de Dados": {
        "Equifax": {
            "data": "Setembro 2017",
            "impacto": "147 milhões de pessoas afetadas",
            "prejuizo": "US$ 1.7 bilhões",
            "metodo": "Exploração de vulnerabilidade Apache Struts",
            "dados_vazados": ["CPFs", "Cartões de crédito", "Endereços"],
            "contramedidas": [
                "Patch management",
                "Monitoramento contínuo",
                "Criptografia de dados sensíveis"
            ],
            "timeline": {
                "Março": "Início da invasão",
                "Julho": "Descoberta do vazamento",
                "Setembro": "Anúncio público",
                "Outubro": "Início das investigações"
            }
        },
        "Facebook/Cambridge Analytica": {
            "data": "Março 2018",
            "impacto": "87 milhões de usuários afetados",
            "prejuizo": "US$ 5 bilhões (multa)",
            "metodo": "Coleta indevida via API",
            "dados_vazados": ["Perfis", "Preferências", "Conexões sociais"],
            "contramedidas": [
                "Restrição de API",
                "Auditoria de aplicativos",
                "Transparência no uso de dados"
            ],
            "timeline": {
                "2014": "Início da coleta de dados",
                "2015": "Primeira denúncia",
                "2018": "Escândalo público",
                "2019": "Aplicação da multa"
            }
        }
    },
    "APT (Advanced Persistent Threat)": {
        "APT41": {
            "data": "2012-2021",
            "impacto": "Múltiplos setores globalmente",
            "prejuizo": "Bilhões estimados",
            "metodo": "Spear-phishing, supply chain attacks",
            "setores_afetados": ["Tecnologia", "Governo", "Educação"],
            "contramedidas": [
                "Threat hunting",
                "EDR avançado",
                "Inteligência de ameaças"
            ],
            "timeline": {
                "2012": "Primeiras atividades detectadas",
                "2019": "Intensificação de ataques",
                "2020": "Indiciamento público",
                "2021": "Novas campanhas identificadas"
            }
        }
    }
}

# Estruturas de Dados para Ferramentas
TOOLS = {
    "Escaneamento de Rede": {
        "Nmap": {
            "descricao": "Exploração de rede e auditoria de segurança",
            "instalacao": "sudo apt install nmap",
            "exemplos_codigo": {
                "Scan Básico": "nmap -sV 192.168.1.1",
                "Auditoria Completa": "nmap -A -T4 -p- target.com",
                "Scan Silencioso": "nmap -sS -sC -T2 target.com"
            },
            "caso_real": "Utilizado na Operação Aurora para mapear redes internas",
            "documentacao": "https://nmap.org",
            "risco": "Médio",
            "ano": 1997,
            "contramedidas": [
                "IDS/IPS",
                "Firewall configurado",
                "Monitoramento de rede"
            ]
        },
        "Wireshark": {
            "descricao": "Analisador de protocolos de rede",
            "instalacao": "sudo apt install wireshark",
            "exemplos_codigo": {
                "Captura Básica": "wireshark -i eth0",
                "Filtro HTTP": "wireshark -i eth0 -f 'tcp port 80'",
                "Análise de Pacotes": "wireshark -r capture.pcap"
            },
            "caso_real": "Análise forense em incidentes de segurança",
            "documentacao": "https://www.wireshark.org",
            "risco": "Baixo",
            "ano": 1998,
            "contramedidas": [
                "Criptografia de tráfego",
                "Segmentação de rede",
                "Monitoramento de endpoints"
            ]
        },
        "Zenmap": {
            "descricao": "Interface gráfica para Nmap",
            "instalacao": "sudo apt install zenmap",
            "exemplos_codigo": {
                "Scan Básico": "zenmap -sV 192.168.1.1",
            },
            "caso_real": "Utilizado para visualização de redes complexas",
            "documentacao": "https://nmap.org/zenmap/",
            "risco": "Médio",
            "ano": 2006,
            "contramedidas": [
                "IDS/IPS",
                "Firewall configurado",
                "Monitoramento de rede"
            ]
        },
        
        "Hydra": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install hydra",
            "exemplos_codigo": {
                "SSH": "hydra -l admin -P wordlist.txt ssh://192.168.1.1",
                "FTP": "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
                "Web Form": "hydra -l admin -P pass.txt http-post-form://site.com/login"
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://github.com/vanhauser-thc/thc-hydra",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "Metasploit": {
            "descricao": "Framework para desenvolvimento e execução de exploits",
            "instalacao": "curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | bash",
            "exemplos_codigo": {
                "Iniciar Metasploit": "msfconsole",
                "Buscar Exploits": "search type:exploit",
            },
            "caso_real": "Utilizado em testes de penetração em diversas organizações",
            "documentacao": "https://docs.metasploit.com/",
            "risco": "Alto",
            "ano": 2003,
            "contramedidas": [
                "Atualizações regulares",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "SQLMap": {
            "descricao": "Ferramenta de teste de injeção SQL",
            "instalacao": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev",
            "exemplos_codigo": {
                "Scan Básico": "python sqlmap.py -u 'http://target.com/page.php?id=1'",
            },
            "caso_real": "Utilizado para encontrar e explorar vulnerabilidades de injeção SQL",
            "documentacao": "http://sqlmap.org/",
            "risco": "Alto",
            "ano": 2006,
            "contramedidas": [
                "Validação de entrada",
                "Uso de ORM",
                "Escapamento de dados"
            ]
        },
        "Aircrack-ng": {
            "descricao": "Conjunto de ferramentas para auditoria de redes Wi-Fi",
            "instalacao": "sudo apt install aircrack-ng",
            "exemplos_codigo": {
                "Captura de Pacotes": "airodump-ng wlan0",
                "Quebra de Senha": "aircrack-ng -w wordlist.txt capture.cap",
            },
            "caso_real": "Utilizado para testar a segurança de redes sem fio",
            "documentacao": "https://www.aircrack-ng.org/",
            "risco": "Alto",
            "ano": 2006,
            "contramedidas": [
                "WPA3",
                "Desativar WPS",
                "Monitoramento de rede"
            ]
        },
        "Kismet": {
            "descricao": "Detector de rede sem fio e sniffer",
            "instalacao": "sudo apt install kismet",
            "exemplos_codigo": {
                "Iniciar Kismet": "kismet",
            },
            "caso_real": "Utilizado para monitorar redes sem fio em ambientes de teste",
            "documentacao": "https://kismetwireless.net/",
            "risco": "Médio",
            "ano": 2003,
            "contramedidas": [
                "Criptografia de tráfego",
                "Desativar SSID Broadcasting",
                "Monitoramento de rede"
            ]
        },
        "Netcat": {
            "descricao": "Ferramenta de rede para leitura e gravação de dados através de conexões de rede",
            "instalacao": "sudo apt install netcat",
            "exemplos_codigo": {
                "Escutar em uma Porta": "nc -l -p 1234",
                "Conectar a um Servidor": "nc target.com 1234",
            },
            "caso_real": "Utilizado para testes de conectividade e transferência de arquivos",
            "documentacao": "https://netcat.sourceforge.net/",
            "risco": "Médio",
            "ano": 1996,
            "contramedidas": [
                "Firewall configurado",
                "Monitoramento de rede",
                "Desativar serviços não utilizados"
            ]
        },
        "TCPDump": {
            "descricao": "Ferramenta de captura de pacotes de rede",
            "instalacao": "sudo apt install tcpdump",
            "exemplos_codigo": {
                "Captura de Pacotes": "tcpdump -i eth0",
            },
            "caso_real": "Utilizado para análise de tráfego em redes",
            "documentacao": "https://www.tcpdump.org/",
            "risco": "Médio",
            "ano": 1988,
            "contramedidas": [
                "Criptografia de tráfego",
                "Monitoramento de rede",
                "Segmentação de rede"
            ]
        },
        "Burp Suite": {
            "descricao": "Plataforma de teste de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Proxy": "Configure o navegador para localhost:8080",
                "Scanner": "Configurar scope e iniciar scanning",
                "Intruder": "Selecionar payload e iniciar ataque"
            },
            "caso_real": "Identificação de vulnerabilidades em aplicações web",
            "documentacao": "https://portswigger.net/burp",
            "risco": "Alto",
            "ano": 2003,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Nikto": {
            "descricao": "Scanner de vulnerabilidades em servidores web",
            "instalacao": "sudo apt install nikto",
            "exemplos_codigo": {
                "Scan Básico": "nikto -h http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em servidores web",
            "documentacao": "https://cirt.net/Nikto2",
            "risco": "Médio",
            "ano": 2001,
            "contramedidas": [
                "Atualizações regulares",
                "Configuração segura do servidor",
                "Monitoramento de logs"
            ]
        },
        "John the Ripper": {
            "descricao": "Quebrador de senhas avançado",
            "instalacao": "sudo apt install john",
            "exemplos_codigo": {
                "Hash Básico": "john --format=raw-md5 hashes.txt",
                "Modo Incremental": "john --incremental passwords.txt",
                "Wordlist": "john --wordlist=dictionary.txt hashes.txt"
            },
            "caso_real": "Análise forense de credenciais vazadas",
            "documentacao": "https://www.openwall.com/john/",
            "risco": "Alto",
            "ano": 1996,
            "contramedidas": [
                "Hashing seguro",
                "Salt único",
                "Rotação de senhas"
            ]
        },
        "Hashcat": {
            "descricao": "Ferramenta de recuperação de senhas",
            "instalacao": "sudo apt install hashcat",
            "exemplos_codigo": {
                "Quebra de Hash": "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
            },
            "caso_real": "Utilizado em testes de penetração para recuperação de senhas",
            "documentacao": "https://hashcat.net/hashcat/",
            "risco": "Alto",
            "ano": 2010,
            "contramedidas": [
                "Hashing seguro",
                "Políticas de senha forte",
                "Monitoramento de logs"
            ]
        },
        "SET (Social-Engineer Toolkit)": {
            "descricao": "Ferramenta para testes de engenharia social",
            "instalacao": "git clone https://github.com/trustedsec/social-engineer-toolkit/ setoolkit",
            "exemplos_codigo": {
                "Iniciar SET": "setoolkit",
            },
            "caso_real": "Utilizado para simular ataques de engenharia social",
            "documentacao": "https://github.com/trustedsec/social-engineer-toolkit",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Treinamento de conscientização",
                "Simulações de phishing",
                "Monitoramento de comportamento"
            ]
        },
        "BeEF": {
            "descricao": "Framework para exploração de navegadores",
            "instalacao": "git clone https://github.com/beefproject/beef.git",
            "exemplos_codigo": {
                "Iniciar BeEF": "ruby beef",
            },
            "caso_real": "Utilizado para demonstrar vulnerabilidades em navegadores",
            "documentacao": "https://github.com/beefproject/beef",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Atualizações regulares",
                "Treinamento de equipe",
                "Monitoramento de logs"
            ]
        },
        "Maltego": {
            "descricao": "Ferramenta de análise de link e coleta de informações",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Maltego": "maltego",
            },
            "caso_real": "Utilizado para análise de redes sociais e coleta de informações",
            "documentacao": "https://www.paterva.com/web7/",
            "risco": "Médio",
            "ano": 2010,
            "contramedidas": [
                "Políticas de privacidade",
                "Monitoramento de informações",
                "Treinamento de equipe"
            ]
        },
        "Gobuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "go get -u github.com/OJ/gobuster",
            "exemplos_codigo": {
                "Scan de Diretórios": "gobuster dir -u http://target.com -w wordlist.txt",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://github.com/OJ/gobuster",
            "risco": "Médio",
            "ano": 2017,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "DirBuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan de Diretórios": "java -jar dirbuster.jar",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "Ettercap": {
            "descricao": "Ferramenta de ataque Man-in-the-Middle",
            "instalacao": "sudo apt install ettercap-gtk",
            "exemplos_codigo": {
                "Iniciar Ettercap": "ettercap -G",
            },
            "caso_real": "Utilizado para interceptar e modificar tráfego em redes",
            "documentacao": "https://www.ettercap.com/",
            "risco": "Alto",
            "ano": 2001,
            "contramedidas": [
                "Criptografia de tráfego",
                "Monitoramento de rede",
                "Segmentação de rede"
            ]
        },
        "Cain & Abel": {
            "descricao": "Ferramenta de recuperação de senhas para Windows",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Quebra de Senha": "Utilizar a interface gráfica",
            },
            "caso_real": "Utilizado para recuperação de senhas em ambientes Windows",
            "documentacao": "http://www.oxid.it/cain.html",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "Políticas de senha forte",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Mimikatz": {
            "descricao": "Ferramenta para extração de credenciais do Windows",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Extrair Senhas": "mimikatz # sekurlsa::minidump",
            },
            "caso_real": "Utilizado em testes de penetração para extração de credenciais",
            "documentacao": "https://github.com/gentilkiwi/mimikatz",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "PowerSploit": {
            "descricao": "Framework de exploração para PowerShell",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar PowerSploit": "Import-Module PowerSploit",
            },
            "caso_real": "Utilizado em testes de penetração em ambientes Windows",
            "documentacao": "https://github.com/PowerShellMafia/PowerSploit",
            "risco": "Alto",
            "ano": 2015,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "Empire": {
            "descricao": "Framework de pós-exploração para PowerShell",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar Empire": "python empire",
            },
            "caso_real": "Utilizado em testes de penetração para pós-exploração",
            "documentacao": "https://github.com/EmpireProject/Empire",
            "risco": "Alto",
            "ano": 2016,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "Responder": {
            "descricao": "Ferramenta para ataques de envenenamento de cache DNS",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar Responder": "python Responder.py -I eth0",
            },
            "caso_real": "Utilizado para capturar credenciais em redes Windows",
            "documentacao": "https://github.com/SpiderLabs/Responder",
            "risco": "Alto",
            "ano": 2014,
            "contramedidas": [
                "Desativar NetBIOS",
                "Monitoramento de rede",
                "Treinamento de equipe"
            ]
        },
        "Ophcrack": {
            "descricao": "Ferramenta de recuperação de senhas do Windows",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Ophcrack": "ophcrack",
            },
            "caso_real": "Utilizado para recuperação de senhas em ambientes Windows",
            "documentacao": "http://ophcrack.sourceforge.net/",
            "risco": "Alto",
            "ano": 2005,
            "contramedidas": [
                "Políticas de senha forte",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Fierce": {
            "descricao": "Ferramenta de escaneamento de DNS",
            "instalacao": "git clone https://github.com/mschwager/fierce.git",
            "exemplos_codigo": {
                "Iniciar Fierce": "perl fierce.pl -domain target.com",
            },
            "caso_real": "Utilizado para descobrir subdomínios e informações de DNS",
            "documentacao": "https://github.com/mschwager/fierce",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Configuração segura de DNS",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Skipfish": {
            "descricao": "Scanner de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan Básico": "./skipfish -o /output -W /path/to/wordlist http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://skipfish.googlecode.com/",
            "risco": "Médio",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "w3af": {
            "descricao": "Framework de teste de segurança web",
            "instalacao": "git clone https://github.com/andresriancho/w3af.git",
            "exemplos_codigo": {
                "Iniciar w3af": "python w3af_console.py",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "http://w3af.org/",
            "risco": "Alto",
            "ano": 2009,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Slowloris": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "git clone https://github.com/gkbrk/slowloris.git",
            "exemplos_codigo": {
                "Iniciar Slowloris": "python slowloris.py target.com",
            },
            "caso_real": "Utilizado para testar a resistência de servidores web",
            "documentacao": "https://github.com/gkbrk/slowloris",
            "risco": "Alto",
            "ano": 2009,
            "contramedidas": [
                "Limitar conexões simultâneas",
                "Monitoramento de tráfego",
                "Firewall configurado"
            ]
        },
        "LOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar LOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/loic/",
            "risco": "Alto",
            "ano": 2006,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "HOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar HOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/hoic/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "Fern WiFi Cracker": {
            "descricao": "Ferramenta para auditoria de redes Wi-Fi",
            "instalacao": "git clone https://github.com/savio-code/Fern-WiFi-Cracker.git",
            "exemplos_codigo": {
                "Iniciar Fern": "python fern-wifi-cracker.py",
            },
            "caso_real": "Utilizado para testar a segurança de redes sem fio",
            "documentacao": "https://github.com/savio-code/Fern-WiFi-Cracker",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "WPA3",
                "Desativar WPS",
                "Monitoramento de rede"
            ]
        },
        "Reaver": {
            "descricao": "Ferramenta para quebrar WPS de redes Wi-Fi",
            "instalacao": "sudo apt install reaver",
            "exemplos_codigo": {
                "Quebra de WPS": "reaver -i wlan0 -b <BSSID> -vv",
            },
            "caso_real": "Utilizado para explorar vulnerabilidades em redes sem fio",
            "documentacao": "https://code.google.com/p/reaver-wps/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Desativar WPS",
                "Monitoramento de rede",
                "Treinamento de equipe"
            ]
        },
        "WPScan": {
            "descricao": "Scanner de vulnerabilidades para WordPress",
            "instalacao": "gem install wpscan",
            "exemplos_codigo": {
                "Scan Básico": "wpscan --url http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em sites WordPress",
            "documentacao": "https://wpscan.com/",
            "risco": "Alto",
            "ano": 2012,
            "contramedidas": [
                "Atualizações regulares",
                "Monitoramento de logs",
                "Segurança de plugins"
            ]
        },
        "Armitage": {
            "descricao": "Interface gráfica para Metasploit",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Armitage": "armitage",
            },
            "caso_real": "Utilizado para facilitar o uso do Metasploit",
            "documentacao": "http://www.fastandeasyhacking.com/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Atualizações regulares",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Medusa": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install medusa",
            "exemplos_codigo": {
                "SSH": "medusa -h 192.168.1.1 -u admin -P wordlist.txt -M ssh",
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://www.foofus.net/?q=medusa",
            "risco": "Alto",
            "ano": 2008,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "Gobuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "go get -u github.com/OJ/gobuster",
            "exemplos_codigo": {
                "Scan de Diretórios": "gobuster dir -u http://target.com -w wordlist.txt",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://github.com/OJ/gobuster",
            "risco": "Médio",
            "ano": 2017,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "DirBuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan de Diretórios": "java -jar dirbuster.jar",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "Autopsy": {
            "descricao": "Ferramenta de análise forense digital",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Autopsy": "autopsy",
            },
            "caso_real": "Utilizado em investigações forenses digitais",
            "documentacao": "https://www.sleuthkit.org/autopsy/",
            "risco": "Médio",
            "ano": 2009,
            "contramedidas": [
                "Treinamento de equipe",
                "Políticas de segurança",
                "Monitoramento de logs"
            ]
        },
        "Responder": {
            "descricao": "Ferramenta para ataques de envenenamento de cache DNS",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar Responder": "python Responder.py -I eth0",
            },
            "caso_real": "Utilizado para capturar credenciais em redes Windows",
            "documentacao": "https://github.com/SpiderLabs/Responder",
            "risco": "Alto",
            "ano": 2014,
            "contramedidas": [
                "Desativar NetBIOS",
                "Monitoramento de rede",
                "Treinamento de equipe"
            ]
        },
        "DNSEnum": {
            "descricao": "Ferramenta para enumeração de DNS",
            "instalacao": "sudo apt install dnsenum",
            "exemplos_codigo": {
                "Iniciar DNSEnum": "dnsenum target.com",
            },
            "caso_real": "Utilizado para coletar informações sobre domínios",
            "documentacao": "https://github.com/fwaeytens/dnsenum",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "Configuração segura de DNS",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "nbtscan": {
            "descricao": "Ferramenta para escanear redes Windows",
            "instalacao": "sudo apt install nbtscan",
            "exemplos_codigo": {
                "Scan de Rede": "nbtscan 192.168.1.0/24",
            },
            "caso_real": "Utilizado para descobrir informações sobre dispositivos em redes Windows",
            "documentacao": "https://www.unixwiz.net/tools/nbtscan.html",
            "risco": "Médio",
            "ano": 2000,
            "contramedidas": [
                "Monitoramento de rede",
                "Desativar serviços não utilizados",
                "Treinamento de equipe"
            ]
        },
        "Enum4linux": {
            "descricao": "Ferramenta para enumeração de informações de sistemas Windows",
            "instalacao": "git clone https://github.com/PowerShellMafia/PowerSploit.git",
            "exemplos_codigo": {
                "Iniciar Enum4linux": "enum4linux -a target.com",
            },
            "caso_real": "Utilizado para coletar informações sobre sistemas Windows",
            "documentacao": "https://github.com/PowerShellMafia/PowerSploit",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "THC-Hydra": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install hydra",
            "exemplos_codigo": {
                "SSH": "hydra -l admin -P wordlist.txt ssh://192.168.1.1",
                "FTP": "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
                "Web Form": "hydra -l admin -P pass.txt http-post-form://site.com/login"
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://github.com/vanhauser-thc/thc-hydra",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "Dirbuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan de Diretórios": "java -jar dirbuster.jar",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "davtest": {
            "descricao": "Ferramenta para testar servidores WebDAV",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar davtest": "python davtest.py http://target.com",
            },
            "caso_real": "Utilizado para testar a segurança de servidores WebDAV",
            "documentacao": "https://github.com/jesusprubio/davtest",
            "risco": "Médio",
            "ano": 2007,
                        "contramedidas": [
                "Desativar WebDAV se não necessário",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "CeWL": {
            "descricao": "Ferramenta para gerar listas de palavras a partir de sites",
            "instalacao": "sudo apt install cewl",
            "exemplos_codigo": {
                "Gerar Lista de Palavras": "cewl http://target.com -w wordlist.txt",
            },
            "caso_real": "Utilizado para coletar palavras para ataques de força bruta",
            "documentacao": "https://digininja.org/projects/cewl.php",
            "risco": "Médio",
            "ano": 2013,
            "contramedidas": [
                "Monitoramento de informações públicas",
                "Treinamento de equipe",
                "Políticas de segurança"
            ]
        },
        "Arachni": {
            "descricao": "Scanner de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan Básico": "arachni http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://www.arachni-scanner.com/",
            "risco": "Alto",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Unicornscan": {
            "descricao": "Ferramenta de escaneamento de rede",
            "instalacao": "sudo apt install unicornscan",
            "exemplos_codigo": {
                "Scan de Rede": "unicornscan -I a -p 80,443 target.com",
            },
            "caso_real": "Utilizado para escanear redes em busca de serviços ativos",
            "documentacao": "http://unicornscan.org/",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "IDS/IPS",
                "Firewall configurado",
                "Monitoramento de rede"
            ]
        },
        "Fierce": {
            "descricao": "Ferramenta de escaneamento de DNS",
            "instalacao": "git clone https://github.com/mschwager/fierce.git",
            "exemplos_codigo": {
                "Iniciar Fierce": "perl fierce.pl -domain target.com",
            },
            "caso_real": "Utilizado para descobrir subdomínios e informações de DNS",
            "documentacao": "https://github.com/mschwager/fierce",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Configuração segura de DNS",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Skipfish": {
            "descricao": "Scanner de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan Básico": "./skipfish -o /output -W /path/to/wordlist http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://skipfish.googlecode.com/",
            "risco": "Médio",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Slowloris": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "git clone https://github.com/gkbrk/slowloris.git",
            "exemplos_codigo": {
                "Iniciar Slowloris": "python slowloris.py target.com",
            },
            "caso_real": "Utilizado para testar a resistência de servidores web",
            "documentacao": "https://github.com/gkbrk/slowloris",
            "risco": "Alto",
            "ano": 2009,
            "contramedidas": [
                "Limitar conexões simultâneas",
                "Monitoramento de tráfego",
                "Firewall configurado"
            ]
        },
        "LOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar LOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/loic/",
            "risco": "Alto",
            "ano": 2006,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "HOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar HOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/hoic/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "Fern WiFi Cracker": {
            "descricao": "Ferramenta para auditoria de redes Wi-Fi",
            "instalacao": "git clone https://github.com/savio-code/Fern-WiFi-Cracker.git",
            "exemplos_codigo": {
                "Iniciar Fern": "python fern-wifi-cracker.py",
            },
            "caso_real": "Utilizado para testar a segurança de redes sem fio",
            "documentacao": "https://github.com/savio-code/Fern-WiFi-Cracker",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "WPA3",
                "Desativar WPS",
                "Monitoramento de rede"
            ]
        },
        "Reaver": {
            "descricao": "Ferramenta para quebrar WPS de redes Wi-Fi",
            "instalacao": "sudo apt install reaver",
            "exemplos_codigo": {
                "Quebra de WPS": "reaver -i wlan0 -b <BSSID> -vv",
            },
            "caso_real": "Utilizado para explorar vulnerabilidades em redes sem fio",
            "documentacao": "https://code.google.com/p/reaver-wps/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Desativar WPS",
                "Monitoramento de rede",
                "Treinamento de equipe"
            ]
        },
        "WPScan": {
            "descricao": "Scanner de vulnerabilidades para WordPress",
            "instalacao": "gem install wpscan",
            "exemplos_codigo": {
                "Scan Básico": "wpscan --url http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em sites WordPress",
            "documentacao": "https://wpscan.com/",
            "risco": "Alto",
            "ano": 2012,
            "contramedidas": [
                "Atualizações regulares",
                "Monitoramento de logs",
                "Segurança de plugins"
            ]
        },
        "Armitage": {
            "descricao": "Interface gráfica para Metasploit",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Armitage": "armitage",
            },
            "caso_real": "Utilizado para facilitar o uso do Metasploit",
            "documentacao": "http://www.fastandeasyhacking.com/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Atualizações regulares",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Medusa": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install medusa",
            "exemplos_codigo": {
                "SSH": "medusa -h 192.168.1.1 -u admin -P wordlist.txt -M ssh",
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://www.foofus.net/?q=medusa",
            "risco": "Alto",
            "ano": 2008,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "Gobuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "go get -u github.com/OJ/gobuster",
            "exemplos_codigo": {
                "Scan de Diretórios": "gobuster dir -u http://target.com -w wordlist.txt",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://github.com/OJ/gobuster",
            "risco": "Médio",
            "ano": 2017,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "DirBuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan de Diretórios": "java -jar dirbuster.jar",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "Autopsy": {
            "descricao": "Ferramenta de análise forense digital",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Autopsy": "autopsy",
            },
            "caso_real": "Utilizado em investigações forenses digitais",
            "documentacao": "https://www.sleuthkit.org/autopsy/",
            "risco": "Médio",
            "ano": 2009,
            "contramedidas": [
                "Treinamento de equipe",
                "Políticas de segurança",
                "Monitoramento de logs"
            ]
        },
        "TCPDump": {
            "descricao": "Ferramenta de captura de pacotes de rede",
            "instalacao": "sudo apt install tcpdump",
            "exemplos_codigo": {
                "Captura de Pacotes": "tcpdump -i eth0",
            },
            "caso_real": "Utilizado para análise de tráfego em redes",
            "documentacao": "https://www.tcpdump.org/",
            "risco": "Médio",
            "ano": 1988,
            "contramedidas": [
                "Criptografia de tráfego",
                "Monitoramento de rede",
                "Segmentação de rede"
            ]
        },
        "Cain & Abel": {
            "descricao": "Ferramenta de recuperação de senhas para Windows",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Quebra de Senha": "Utilizar a interface gráfica",
            },
            "caso_real": "Utilizado para recuperação de senhas em ambientes Windows",
            "documentacao": "http://www.oxid.it/cain.html",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "Políticas de senha forte",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Mimikatz": {
            "descricao": "Ferramenta para extração de credenciais do Windows",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Extrair Senhas": "mimikatz # sekurlsa::minidump",
            },
            "caso_real": "Utilizado em testes de penetração para extração de credenciais",
            "documentacao": "https://github.com/gentilkiwi/mimikatz",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "PowerSploit": {
            "descricao": "Framework de exploração para PowerShell",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar PowerSploit": "Import-Module PowerSploit",
            },
            "caso_real": "Utilizado em testes de penetração em ambientes Windows",
            "documentacao": "https://github.com/PowerShellMafia/PowerSploit",
            "risco": "Alto",
            "ano": 2015,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "Empire": {
            "descricao": "Framework de pós-exploração para PowerShell",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar Empire": "python empire",
            },
            "caso_real": "Utilizado em testes de penetração para pós-exploração",
            "documentacao": "https://github.com/EmpireProject/Empire",
            "risco": "Alto",
            "ano": 2016,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "Responder": {
            "descricao": "Ferramenta para ataques de envenenamento de cache DNS",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar Responder": "python Responder.py -I eth0",
            },
            "caso_real": "Utilizado para capturar credenciais em redes Windows",
            "documentacao": "https://github.com/SpiderLabs/Responder",
            "risco": "Alto",
            "ano": 2014,
            "contramedidas": [
                "Desativar NetBIOS",
                "Monitoramento de rede",
                "Treinamento de equipe"
            ]
        },
        "Ophcrack": {
            "descricao": "Ferramenta de recuperação de senhas do Windows",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar Ophcrack": "ophcrack",
            },
            "caso_real": "Utilizado para recuperação de senhas em ambientes Windows",
            "documentacao": "http://ophcrack.sourceforge.net/",
            "risco": "Alto",
            "ano": 2005,
            "contramedidas": [
                "Políticas de senha forte",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Fierce": {
            "descricao": "Ferramenta de escaneamento de DNS",
            "instalacao": "git clone https://github.com/mschwager/fierce.git",
            "exemplos_codigo": {
                "Iniciar Fierce": "perl fierce.pl -domain target.com",
            },
            "caso_real": "Utilizado para descobrir subdomínios e informações de DNS",
            "documentacao": "https://github.com/mschwager/fierce",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Configuração segura de DNS",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "Skipfish": {
            "descricao": "Scanner de segurança web",
            "instalacao": "Download do site oficial",
                        "exemplos_codigo": {
                "Scan Básico": "./skipfish -o /output -W /path/to/wordlist http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://skipfish.googlecode.com/",
            "risco": "Médio",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "w3af": {
            "descricao": "Framework de teste de segurança web",
            "instalacao": "git clone https://github.com/andresriancho/w3af.git",
            "exemplos_codigo": {
                "Iniciar w3af": "python w3af_console.py",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "http://w3af.org/",
            "risco": "Alto",
            "ano": 2009,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Slowloris": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "git clone https://github.com/gkbrk/slowloris.git",
            "exemplos_codigo": {
                "Iniciar Slowloris": "python slowloris.py target.com",
            },
            "caso_real": "Utilizado para testar a resistência de servidores web",
            "documentacao": "https://github.com/gkbrk/slowloris",
            "risco": "Alto",
            "ano": 2009,
            "contramedidas": [
                "Limitar conexões simultâneas",
                "Monitoramento de tráfego",
                "Firewall configurado"
            ]
        },
        "LOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar LOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/loic/",
            "risco": "Alto",
            "ano": 2006,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "HOIC": {
            "descricao": "Ferramenta de ataque de negação de serviço",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar HOIC": "Executar a interface gráfica",
            },
            "caso_real": "Utilizado em ataques DDoS em várias operações",
            "documentacao": "http://sourceforge.net/projects/hoic/",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "Monitoramento de tráfego",
                "Firewall configurado",
                "Limitar conexões simultâneas"
            ]
        },
        "Fern WiFi Cracker": {
            "descricao": "Ferramenta para auditoria de redes Wi-Fi",
            "instalacao": "git clone https://github.com/savio-code/Fern-WiFi-Cracker.git",
            "exemplos_codigo": {
                "Iniciar Fern": "python fern-wifi-cracker.py",
            },
            "caso_real": "Utilizado para testar a segurança de redes sem fio",
            "documentacao": "https://github.com/savio-code/Fern-WiFi-Cracker",
            "risco": "Alto",
            "ano": 2011,
            "contramedidas": [
                "WPA3",
                "Desativar WPS",
                "Monitoramento de rede"
            ]
        },
        "Zenmap": {
            "descricao": "Interface gráfica para Nmap",
            "instalacao": "sudo apt install zenmap",
            "exemplos_codigo": {
                "Scan Básico": "zenmap -sV 192.168.1.1",
            },
            "caso_real": "Utilizado para visualização de redes complexas",
            "documentacao": "https://nmap.org/zenmap/",
            "risco": "Médio",
            "ano": 2006,
            "contramedidas": [
                "IDS/IPS",
                "Firewall configurado",
                "Monitoramento de rede"
            ]
        },
        "Zed Attack Proxy (ZAP)": {
            "descricao": "Ferramenta de teste de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar ZAP": "zap.sh",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://www.zaproxy.org/",
            "risco": "Alto",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "WebScarab": {
            "descricao": "Ferramenta de teste de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Iniciar WebScarab": "java -jar webscarab.jar",
            },
            "caso_real": "Utilizado para análise de segurança em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/WebScarab",
            "risco": "Médio",
            "ano": 2004,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "DNSEnum": {
            "descricao": "Ferramenta para enumeração de DNS",
            "instalacao": "sudo apt install dnsenum",
            "exemplos_codigo": {
                "Iniciar DNSEnum": "dnsenum target.com",
            },
            "caso_real": "Utilizado para coletar informações sobre domínios",
            "documentacao": "https://github.com/fwaeytens/dnsenum",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "Configuração segura de DNS",
                "Monitoramento de logs",
                "Treinamento de equipe"
            ]
        },
        "nbtscan": {
            "descricao": "Ferramenta para escanear redes Windows",
            "instalacao": "sudo apt install nbtscan",
            "exemplos_codigo": {
                "Scan de Rede": "nbtscan 192.168.1.0/24",
            },
            "caso_real": "Utilizado para descobrir informações sobre dispositivos em redes Windows",
            "documentacao": "https://www.unixwiz.net/tools/nbtscan.html",
            "risco": "Médio",
            "ano": 2000,
            "contramedidas": [
                "Monitoramento de rede",
                "Desativar serviços não utilizados",
                "Treinamento de equipe"
            ]
        },
        "Enum4linux": {
            "descricao": "Ferramenta para enumeração de informações de sistemas Windows",
            "instalacao": "git clone https://github.com/PowerShellMafia/PowerSploit.git",
            "exemplos_codigo": {
                "Iniciar Enum4linux": "enum4linux -a target.com",
            },
            "caso_real": "Utilizado para coletar informações sobre sistemas Windows",
            "documentacao": "https://github.com/PowerShellMafia/PowerSploit",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "Monitoramento de logs",
                "Políticas de segurança",
                "Treinamento de equipe"
            ]
        },
        "THC-Hydra": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install hydra",
            "exemplos_codigo": {
                "SSH": "hydra -l admin -P wordlist.txt ssh://192.168.1.1",
                "FTP": "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
                "Web Form": "hydra -l admin -P pass.txt http-post-form://site.com/login"
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://github.com/vanhauser-thc/thc-hydra",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "Dirbuster": {
            "descricao": "Ferramenta de força bruta para descobrir diretórios e arquivos",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan de Diretórios": "java -jar dirbuster.jar",
            },
            "caso_real": "Utilizado para descobrir diretórios ocultos em aplicações web",
            "documentacao": "https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Validação de entrada",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "davtest": {
            "descricao": "Ferramenta para testar servidores WebDAV",
            "instalacao": "Download do repositório GitHub",
            "exemplos_codigo": {
                "Iniciar davtest": "python davtest.py http://target.com",
            },
            "caso_real": "Utilizado para testar a segurança de servidores WebDAV",
            "documentacao": "https://github.com/jesusprubio/davtest",
            "risco": "Médio",
            "ano": 2007,
            "contramedidas": [
                "Desativar WebDAV se não necessário",
                "Monitoramento de logs",
                "Configuração segura do servidor"
            ]
        },
        "CeWL": {
            "descricao": "Ferramenta para gerar listas de palavras a partir de sites",
            "instalacao": "sudo apt install cewl",
            "exemplos_codigo": {
                "Gerar Lista de Palavras": "cewl http://target.com -w wordlist.txt",
            },
            "caso_real": "Utilizado para coletar palavras para ataques de força bruta",
            "documentacao": "https://digininja.org/projects/cewl.php",
            "risco": "Médio",
            "ano": 2013,
            "contramedidas": [
                "Monitoramento de informações públicas",
                "Treinamento de equipe",
                "Políticas de segurança"
            ]
        },
        "Arachni": {
            "descricao": "Scanner de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Scan Básico": "arachni http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em aplicações web",
            "documentacao": "https://www.arachni-scanner.com/",
            "risco": "Alto",
            "ano": 2010,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Unicornscan": {
            "descricao": "Ferramenta de escaneamento de rede",
            "instalacao": "sudo apt install unicornscan",
            "exemplos_codigo": {
                "Scan de Rede": "unicornscan -I a -p 80,443 target.com",
            },
            "caso_real": "Utilizado para escanear redes em busca de serviços ativos",
            "documentacao": "http://unicornscan.org/",
            "risco": "Médio",
            "ano": 2005,
            "contramedidas": [
                "IDS/IPS",
                "Firewall configurado",
                "Monitoramento de rede"
            ]
        }
    },
    "Ataques de Senha": {
        "Hydra": {
            "descricao": "Ferramenta de quebra de senhas paralela",
            "instalacao": "sudo apt install hydra",
            "exemplos_codigo": {
                "SSH": "hydra -l admin -P wordlist.txt ssh://192.168.1.1",
                "FTP": "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
                "Web Form": "hydra -l admin -P pass.txt http-post-form://site.com/login"
            },
            "caso_real": "Utilizado em testes de penetração autorizados",
            "documentacao": "https://github.com/vanhauser-thc/thc-hydra",
            "risco": "Alto",
            "ano": 2000,
            "contramedidas": [
                "2FA/MFA",
                "Rate limiting",
                "Políticas de senha forte"
            ]
        },
        "John the Ripper": {
            "descricao": "Quebrador de senhas avançado",
            "instalacao": "sudo apt install john",
            "exemplos_codigo": {
                "Hash Básico": "john --format=raw-md5 hashes.txt",
                "Modo Incremental": "john --incremental passwords.txt",
                "Wordlist": "john --wordlist=dictionary.txt hashes.txt"
            },
            "caso_real": "Análise forense de credenciais vazadas",
            "documentacao": "https://www.openwall.com/john/",
            "risco": "Alto",
            "ano": 1996,
            "contramedidas": [
                "Hashing seguro",
                "Salt único",
                "Rotação de senhas"
            ]
        }
    },
    "Exploração Web": {
        "Burp Suite": {
            "descricao": "Plataforma de teste de segurança web",
            "instalacao": "Download do site oficial",
            "exemplos_codigo": {
                "Proxy": "Configure o navegador para localhost:8080",
                "Scanner": "Configurar scope e iniciar scanning",
                "Intruder": "Selecionar payload e iniciar ataque"
            },
            "caso_real": "Identificação de vulnerabilidades em aplicações web",
            "documentacao": "https://portswigger.net/burp",
            "risco": "Alto",
            "ano": 2003,
            "contramedidas": [
                "WAF",
                "HTTPS",
                "Security Headers"
            ]
        },
        "Nikto": {
            "descricao": "Scanner de vulnerabilidades em servidores web",
            "instalacao": "sudo apt install nikto",
            "exemplos_codigo": {
                "Scan Básico": "nikto -h http://target.com",
            },
            "caso_real": "Utilizado para identificar vulnerabilidades em servidores web",
            "documentacao": "https://cirt.net/Nikto2",
            "risco": "Médio",
            "ano": 2001,
            "contramedidas": [
                "Atualizações regulares",
                "Configuração segura do servidor",
                "Monitoramento de logs"
            ]
        },
        "OWASP ZAP": {
            "descricao": "Proxy de segurança open source",
            "instalacao": "sudo apt install zaproxy",
            "exemplos_codigo": {
                "Scan Automático": "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target",
                "API Scan": "zap-api-scan.py -t http://target -f openapi",
                "Spider": "zap-cli spider http://target"
            },
            "caso_real": "Testes de segurança em desenvolvimento",
            "documentacao": "https://www.zaproxy.org",
            "risco": "Médio",
            "ano": 2010,
            "contramedidas": [
                "Input validation",
                "Output encoding",
                "CSP"
            ]
        }
    }
}

# Estruturas de Dados para o Roadmap
ROADMAP = {
    "0 - Computação Básica": {
        "icon": "💻",
        "items": {
            "Como o Computador Funciona?": {"fundamentos": "https://fundamentos.guiaanonima.com"},
            "O que é Binário?": {"fundamentos": "https://fundamentos.guiaanonima.com"},
            "Software VS Hardware": {"fundamentos": "https://fundamentos.guiaanonima.com"},
            "Como Funciona um Sistema Operacional?": {"fundamentos": "https://fundamentos.guiaanonima.com"},
            "Windows VS Linux": {
                "fundamentos": "https://fundamentos.guiaanonima.com",
                "youtube": "https://youtu.be/xlTW05ED8YM"
            },
            "x86 VS x64 VS ARM": {"fundamentos": "https://fundamentos.guiaanonima.com"}
        }
    },
    "1 - Redes de Computadores": {
        "icon": "🌐",
        "items": {
            "Como a Internet Funciona?": {"fundamentos": "https://fundamentos.guiaanonima.com"},
            "IP VS MAC": {
                "fundamentos": "https://fundamentos.guiaanonima.com",
                "youtube": "https://youtu.be/rOckjDLTuMc"
            },
            "Modelo OSI": {
                "fundamentos": "https://fundamentos.guiaanonima.com",
                "youtube": "https://youtu.be/FU58q40l_j8"
            },
            "Protocolos": {
                "TCP/UDP": {
                    "fundamentos": "https://fundamentos.guiaanonima.com",
                    "youtube": "https://youtu.be/J-Cb19qGZxw"
                },
                "HTTP/HTTPS": {"fundamentos": "https://fundamentos.guiaanonima.com"},
                "DNS": {"fundamentos": "https://fundamentos.guiaanonima.com"}
            }
        }
    },
    # [...] (Adicionar todas as seções seguintes seguindo o mesmo padrão)
}

ICON_MAP = {
    "fundamentos": {"icon": "📘", "color": "#4B8BBE"},
    "youtube": {"icon": "🎥", "color": "#FF0000"},
    "blog": {"icon": "📝", "color": "#00CC96"},
    "instagram": {"icon": "📱", "color": "#E1306C"},
    "TCP/UDP": {"icon": "🌐", "color": "#4B8BBE"},
    "HTTP/HTTPS": {"icon": "🌐", "color": "#4B8BBE"},
    "DNS": {"icon": "🌐", "color": "#4B8BBE"}  # Adicionando a chave DNS
}

def create_resource_badge(resource_type, url):
    badge = f"""
    <a href="{url}" target="_blank" style="text-decoration: none;">
        <span style="
            background-color: {ICON_MAP[resource_type]['color']}20;
            border: 1px solid {ICON_MAP[resource_type]['color']};
            border-radius: 5px;
            padding: 2px 8px;
            margin: 2px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        ">
            {ICON_MAP[resource_type]['icon']}
            <span style="color: {ICON_MAP[resource_type]['color']}; font-size: 0.8em;">
                {resource_type.capitalize()}
            </span>
        </span>
    </a>
    """
    return badge

def display_roadmap_section(section_title, section_data):
    with st.expander(f"{section_data['icon']} **{section_title}**", expanded=False):
        for item, resources in section_data["items"].items():
            cols = st.columns([3, 7])
            with cols[0]:
                st.markdown(f"**{item}**")
            with cols[1]:
                if isinstance(resources, dict):
                    badges_html = " ".join([create_resource_badge(rt, url) for rt, url in resources.items()])
                    st.markdown(badges_html, unsafe_allow_html=True)
                else:
                    st.write(resources)
            st.divider()

def display_roadmap_section(section_title, section_data):
    with st.expander(f"{section_data['icon']} **{section_title}**", expanded=False):
        for item, resources in section_data["items"].items():
            cols = st.columns([3, 7])
            with cols[0]:
                st.markdown(f"**{item}**")
            with cols[1]:
                if isinstance(resources, dict):
                    badges_html = " ".join([create_resource_badge(rt, url) for rt, url in resources.items()])
                    st.markdown(badges_html, unsafe_allow_html=True)
                else:
                    st.write(resources)
            st.divider()
            
def show_roadmap():
    st.title("🗺️ Roadmap Completo de CyberSecurity")
    st.markdown("""
    <div style="text-align: center; margin-bottom: 30px;">
        <h3 style="color: #4B8BBE;">Guia de Aprendizado para Segurança Ofensiva Web</h3>
        <p>Desenvolvido em parceria com a <a href="https://guiaanonima.com/" target="_blank">Guia Anônima</a></p>
    </div>
    """, unsafe_allow_html=True)
    
    progress = st.progress(0)
    sections = list(ROADMAP.keys())
    
    for i, section_title in enumerate(sections):
        progress.progress((i+1)/len(sections), text=f"Carregando: {section_title}")
        display_roadmap_section(section_title, ROADMAP[section_title])
    
    st.success("✅ Roadmap completo carregado!")

def criar_graficos_impacto(tipo_ataque):
    dados = CYBER_ATTACKS[tipo_ataque]
    
    # Prejuízos
    prejuizos = {}
    for k, v in dados.items():
        # Remover 'US$ ', ' bilhões', ' bilhão' e também lidar com '(multa)' se presente
        valor = v['prejuizo'].replace('US$ ', '').replace(' bilhões', '').replace(' bilhão', '').replace(' (multa)', '')
        try:
            prejuizos[k] = float(valor)
        except ValueError:
            st.warning(f"Valor inválido para {k}: {v['prejuizo']}")
            prejuizos[k] = 0  # Ou você pode decidir não incluir esse valor

    fig_prejuizos = go.Figure(data=[
        go.Bar(x=list(prejuizos.keys()), 
               y=list(prejuizos.values()),
               text=[f'US$ {v}B' for v in prejuizos.values()],
               textposition='auto')
    ])
    
    fig_prejuizos.update_layout(
        title=f'Prejuízos por Ataque ({tipo_ataque})',
        xaxis_title="Ataque",
        yaxis_title="Prejuízo (Bilhões US$)"
    )
    
    return fig_prejuizos

def mostrar_dashboard_ataques():
    st.title("📊 Dashboard de Ataques Cibernéticos")
    
    # Seletor de tipo de ataque
    tipo_ataque = st.selectbox("Selecione o Tipo de Ataque", list(CYBER_ATTACKS.keys()))
    
    # Visão geral
    st.header("Visão Geral")
    col1, col2 = st.columns(2)
    
    dados_tipo = CYBER_ATTACKS[tipo_ataque]
    
    with col1:
        # Métricas principais
        for caso, info in dados_tipo.items():
            st.metric(
                label=caso,
                value=info['prejuizo'],
                delta=info['impacto'].split()[0]
            )
    
    with col2:
        # Gráfico de prejuízos
        fig_prejuizos = criar_graficos_impacto(tipo_ataque)
        st.plotly_chart(fig_prejuizos, use_container_width=True)
    
    # Detalhes dos ataques
    st.header("Análise Detalhada")
    for caso, info in dados_tipo.items():
        with st.expander(f"📝 {caso}"):
            st.write(f"**Data:** {info['data']}")
            st.write(f"**Método:** {info['metodo']}")
            st.write(f"**Impacto:** {info['impacto']}")
            # Timeline do ataque
            st.subheader("Timeline")
            for data, evento in info['timeline'].items():
                st.write(f"**{data}:** {evento}")
            
            # Contramedidas
            st.subheader("Contramedidas")
            for medida in info['contramedidas']:
                st.write(f"- {medida}")

# Função para exibir documentação
def mostrar_documentacao():
    st.title("📚 Documentação Completa")
    
    st.header("Guia de Uso")
    st.write("""
    Esta aplicação serve como uma enciclopédia abrangente de segurança cibernética, 
    oferecendo informações detalhadas sobre ferramentas, casos reais e contramedidas de segurança.
    """)
    
    # Documentação de Ferramentas
    st.header("Catálogo de Ferramentas")
    for categoria, ferramentas in TOOLS.items():
        with st.expander(f"🔧 {categoria}"):
            for nome, dados in ferramentas.items():
                st.subheader(nome)
                st.write(f"**Descrição:** {dados['descricao']}")
                st.write(f"**Risco:** {dados['risco']}")
                st.write(f"**Ano:** {dados['ano']}")
                st.write("**Contramedidas Recomendadas:**")
                for medida in dados['contramedidas']:
                    st.write(f"- {medida}")
    
    # Documentação de Ataques
    st.header("Casos de Estudo")
    for tipo, ataques in CYBER_ATTACKS.items():
        with st.expander(f"🚨 {tipo}"):
            for nome, dados in ataques.items():
                st.subheader(nome)
                st.write(f"**Data:** {dados['data']}")
                st.write(f"**Impacto:** {dados['impacto']}")
                st.write(f"**Prejuízo:** {dados['prejuizo']}")
                st.write("**Linha do Tempo:**")
                for periodo, evento in dados['timeline'].items():
                    st.write(f"- {periodo}: {evento}")

    st.header("Políticas de Uso")
    st.write("""
    ### Diretrizes Éticas
    - Uso exclusivo para fins educacionais e defesa
    - Respeito às leis de segurança cibernética
    - Não utilização para atividades maliciosas
    
    ### Responsabilidade Legal
    O uso indevido das informações e ferramentas aqui contidas pode resultar em:
    - Processos criminais
    - Responsabilização civil
    - Penalidades administrativas
    """)

# Função para exibir detalhes da ferramenta
def mostrar_detalhes_ferramenta(category, selected_tool):
    tool_data = TOOLS[category][selected_tool]
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.title(f"⚡ {selected_tool}")
        st.caption(f"Lançamento: {tool_data['ano']} | Nível de Risco: {tool_data['risco']}")
        
        with st.expander("📄 Descrição", expanded=True):
            st.write(tool_data["descricao"])
        
        with st.expander("🛠️ Guia de Instalação"):
            st.code(tool_data["instalacao"], language="bash")
        
        with st.expander("💻 Exemplos de Uso"):
            for cenario, codigo in tool_data["exemplos_codigo"].items():
                st.subheader(cenario)
                st.code(codigo, language="bash")
        
        with st.expander("📜 Caso Real"):
            st.write(tool_data["caso_real"])
    
    with col2:
        st.markdown("### 🛡️ Contramedidas")
        for medida in tool_data["contramedidas"]:
            st.write(f"- {medida}")
        
        st.markdown("### 📚 Recursos")
        st.markdown(f"[Documentação Oficial]({tool_data['documentacao']})")
        
        # Botão para download do guia rápido
        guia_rapido = f"""
        {selected_tool} - Guia Rápido
        
        Descrição: {tool_data['descricao']}
        Instalação: {tool_data['instalacao']}
        
        Exemplos de Uso:
        {chr(10).join([f'{k}: {v}' for k,v in tool_data['exemplos_codigo'].items()])}
        
        Contramedidas Recomendadas:
        {chr(10).join([f'- {m}' for m in tool_data['contramedidas']])}
        
        Documentação: {tool_data['documentacao']}
        """
        
        st.download_button(
            "📥 Download Guia Rápido",
            guia_rapido,
            file_name=f"{selected_tool.lower()}_guia_rapido.txt",
            mime="text/plain"
        )

# Sistema de busca
def buscar_conteudo(termo_busca):
    resultados = []
    
    # Busca em ferramentas
    for categoria, ferramentas in TOOLS.items():
        for nome, dados in ferramentas.items():
            if termo_busca.lower() in nome.lower() or termo_busca.lower() in dados['descricao'].lower():
                resultados.append({
                    'tipo': 'Ferramenta',
                    'categoria': categoria,
                    'nome': nome,
                    'descricao': dados['descricao']
                })
    
    # Busca em ataques
    for tipo, ataques in CYBER_ATTACKS.items():
        for nome, dados in ataques.items():
            if termo_busca.lower() in nome.lower() or termo_busca.lower() in dados['metodo'].lower():
                resultados.append({
                    'tipo': 'Ataque',
                    'categoria': tipo,
                    'nome': nome,
                    'descricao': dados['metodo']
                })
    
    return resultados

# Função principal
def main():
    # Barra lateral com navegação
    st.sidebar.title("🔧 Navegador de Segurança")
    
    # Campo de busca
    termo_busca = st.sidebar.text_input("🔍 Buscar...")
    if termo_busca:
        st.sidebar.markdown("---")
        resultados = buscar_conteudo(termo_busca)
        if resultados:
            st.sidebar.write("Resultados encontrados:")
            for res in resultados:
                st.sidebar.write(f"**{res['tipo']}:** {res['nome']}")
    
    pagina = st.sidebar.radio(
        "Selecione a Página",
        ["Ferramentas", "Dashboard de Ataques", "Documentação", "Roadmap Completo"]
    )
    
    if pagina == "Ferramentas":
        st.sidebar.markdown("---")
        category = st.sidebar.selectbox("Selecione Categoria", list(TOOLS.keys()))
        tool_list = list(TOOLS[category].keys())
        selected_tool = st.sidebar.selectbox("Selecione Ferramenta", tool_list)
        
        mostrar_detalhes_ferramenta(category, selected_tool)
        
    elif pagina == "Dashboard de Ataques":
        mostrar_dashboard_ataques()
    
    elif pagina == "Documentação":
        mostrar_documentacao()
    
    elif pagina == "Roadmap Completo":
        show_roadmap()
    
    # Rodapé
    st.markdown("---")
    st.markdown("""
        <div style='text-align: center'>
            <p>Enciclopédia de Segurança Cibernética - Versão 1.0</p>
            <p>Use estas informações apenas para fins educacionais e de defesa</p>
        </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
