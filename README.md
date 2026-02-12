# 🛡️ ShieldPhish Ultra — Inteligência Artificial Contra Phishing

O **ShieldPhish Ultra** é uma plataforma avançada de cibersegurança projetada para detectar tentativas de phishing, domínios maliciosos e anexos perigosos em tempo real. Diferente de ferramentas convencionais, o sistema combina **Inteligência Artificial (Machine Learning)** com múltiplas camadas de análise heurística para garantir um veredito de alta precisão.

## 🚀 Funcionalidades de Elite

O sistema utiliza um motor de análise híbrido que verifica:

* 🧠 **Motor de IA (Random Forest):** Classificação preditiva de URLs utilizando o modelo Random Forest Classifier.
* 🌍 **Geolocalização e Infraestrutura:** Rastreamento do IP do servidor, identificando o país de origem e o provedor (ASN).
* 🔡 **Detecção de Ataques Homográficos:** Identificação de caracteres visuais falsos (Punnycode).
* 📊 **Análise de Entropia de Shannon:** Medição matemática da aleatoriedade do domínio para detectar DGAs.
* 📏 **Distância de Levenshtein:** Verificação de similaridade com marcas famosas (Typosquatting).
* 📥 **Central de Auditoria:** Exportação de relatórios completos em formatos **CSV, Excel, JSON e HTML**.

## 🔐 Selo de Metodologia — Privacidade e Rigor

Este sistema foi construído sob o princípio de **Zero Trust**:
* **Privacidade:** Processamento em memória volátil, sem armazenamento de e-mails ou dados sensíveis.
* **Transparência:** Exibição clara do cálculo de score baseado em evidências técnicas.

## 🛠️ Stack Tecnológica

* 🐍 **Linguagem:** Python 3.10+
* 💻 **Interface:** Streamlit (Layout totalmente responsivo, otimizado para desktops, notebooks, tablets e smartphones)
* 🤖 **IA/ML:** Scikit-Learn (Random Forest), CountVectorizer
* 🛡️ **Segurança:** VirusTotal API v3 (vt-py)
* 📊 **Dados:** Pandas, Levenshtein, Tldextract

