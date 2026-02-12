🛡️ ShieldPhish Ultra — Detector de Phishing

ShieldPhish Ultra é uma ferramenta de segurança voltada para a detecção de phishing e links maliciosos em tempo real. Utilizando a API do VirusTotal, o sistema realiza análises de reputação de domínios e verificação de arquivos via hash, garantindo uma proteção rápida e eficiente.

🚀 Funcionalidades

✔ Análise de Links
Verifica URLs em busca de padrões de fraude, histórico de malware e reputação do domínio.

✔ Scanner de Arquivos
Permite upload de anexos para análise via hash na base do VirusTotal.

✔ Interface Intuitiva
Construído com Streamlit, oferecendo uma experiência de usuário simples e ágil.

🔐 Selo de Metodologia — Privacidade Garantida

Este sistema não armazena e-mails, senhas ou conteúdos analisados.
Toda análise é processada em memória e descartada ao final da sessão, garantindo total privacidade e segurança dos dados do usuário.

🛠️ Tecnologias Utilizadas

Python

Streamlit

VirusTotal API

Git/GitHub

🔒 Segurança e Boas Práticas

O projeto segue padrões rigorosos de segurança:

✅ Gerenciamento de Segredos
A chave da API não é exposta no código e é gerenciada via Secrets do Streamlit.

✅ .gitignore configurado
Arquivos sensíveis como .streamlit/secrets.toml são ignorados no controle de versão.

📌 Como executar localmente

Siga os passos abaixo:

# 1. Clone o repositório
git clone <URL_DO_REPOSITORIO>

# 2. Entre na pasta do projeto
cd shieldphish-ultra

# 3. Crie um ambiente virtual
python -m venv venv

# 4. Ative o ambiente
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# 5. Instale as dependências
pip install -r requirements.txt

# 6. Crie o arquivo de secrets
mkdir -p .streamlit
touch .streamlit/secrets.toml


Adicione sua chave da API no arquivo .streamlit/secrets.toml:

[general]
VT_API_KEY = "SUA_VT_API_KEY_AQUI"

# 7. Execute o app
streamlit run app.py

⚙️ Roadmap (Futuras melhorias)

📊 Dashboard com estatísticas de detecções

🔍 Análise heurística avançada

🔗 Integração com outros serviços de threat intelligence

🔔 Alertas em tempo real via e-mail/Telegram
