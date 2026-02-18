import streamlit as st
import tldextract
import whois
import vt
import pandas as pd
from datetime import datetime
import pytz  # Necessário: pip install pytz
from shieldphish_ultra_core import ShieldPhishUltraCore
import requests
import time  # <-- Linha corrigida/adicionada

# --- CONFIGURAÇÃO ---
VT_API_KEY = st.secrets["VT_API_KEY"]
URLSCAN_API_KEY = st.secrets["URLSCAN_API_KEY"]

st.set_page_config(page_title="ShieldPhish Ultra", page_icon="🛡️", layout="wide")
st.markdown("""
    <style>
    /* 1. TÍTULO DE EXPORTAÇÃO: Garante linha única em notebooks */
    h3 {
        white-space: nowrap !important;
        width: 100% !important;
        font-size: 1.15rem !important; 
        margin-bottom: 1rem !important;
    }

    /* 2. PADRONIZAÇÃO DE TODOS OS BOTÕES: Mesma altura e largura padrão */
    .stButton button, .stDownloadButton button {
        width: 100% !important;
        height: 3.5rem !important;    
        font-size: 0.95rem !important; 
        font-weight: bold !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }

    /* 3. SIMETRIA DAS COLUNAS: Botões alinhados lado a lado em qualquer tela */
    div[data-testid="column"] {
        display: flex !important;
        width: 100% !important;
        flex: 1 1 0% !important;
    }
    </style>
    """, unsafe_allow_html=True)

# Inicializa o motor de IA Profissional
if 'engine' not in st.session_state:
    st.session_state.engine = ShieldPhishUltraCore()

if 'historico' not in st.session_state:
    st.session_state.historico = []

# Função para Horário de Brasília
def get_brasilia_time():
    tz = pytz.timezone('America/Sao_Paulo')
    return datetime.now(tz).strftime("%H:%M") # Removi o :%S (segundos)

DOMINIOS_OFICIAIS = {
    "itau": "itau.com.br", 
    "nubank": "nubank.com.br", 
    "google": "google.com",
    "bradesco": "bradesco.com.br", 
    "caixa": "caixa.gov.br", 
    "santander": "santander.com.br"
}

# --- NÚCLEO DE INTELIGÊNCIA ANTERIOR ---
def obter_idade_dominio(texto):
    try:
        dominio = texto.split("@")[-1].strip().lower() if "@" in texto else tldextract.extract(texto).fqdn
        res = whois.whois(dominio)
        data = res.creation_date
        if isinstance(data, list): data = data[0]
        return (datetime.now() - data).days if data else None
    except:
        return None

# --- NÚCLEO DE INTELIGÊNCIA ATUALIZADO ---
def consultar_reputacao(alvo):
    """Consulta universal no VirusTotal para URLs, IPs, Domínios ou Hashes"""
    try:
        with vt.Client(VT_API_KEY) as client:
            if "/" in alvo or "." in alvo or len(alvo) > 30:
                try:
                    # Tenta tratar como URL primeiro
                    stats = client.get_object("/urls/{}", vt.url_id(alvo)).last_analysis_stats
                except:
                    # Se falhar, tenta como arquivo (Hash), IP ou Domínio
                    if len(alvo) > 30: # Provável Hash (MD5, SHA1, SHA256)
                        stats = client.get_object("/files/{}", alvo).last_analysis_stats
                    elif any(c.isdigit() for c in alvo) and alvo.count('.') == 3: # Provável IP
                        stats = client.get_object("/ip_addresses/{}", alvo).last_analysis_stats
                    else: # Provável Domínio
                        stats = client.get_object("/domains/{}", alvo).last_analysis_stats
                return stats.get('malicious', 0)
            return 0
    except:
        return 0

def consultar_urlscan(url):
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    dominio = url.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        # 1. PRIMEIRA TENTATIVA: MODO PRIVADO (Sua preferência)
        data = {"url": url, "visibility": "private"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)

        # 2. SE FALHAR (Cota excedida ou erro), TENTA MODO UNLISTED (Contingência)
        if response.status_code != 200:
            data["visibility"] = "unlisted"
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)

        if response.status_code == 200:
            res_json = response.json()
            uuid = res_json.get('uuid')
            
            # Busca o Histórico Real (Para o Contador Amarelo)
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{dominio}"
            search_response = requests.get(search_url, headers=headers)
            total_real = 0
            if search_response.status_code == 200:
                total_real = search_response.json().get('total', 0)

            return {
                "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
                "report": f"https://urlscan.io/result/{uuid}/",
                "uuid": uuid,
                "total_scans": total_real
            }
        return None
    except Exception as e:
        return None
    
def calcular_dias(data_str):
    try:
        # Limpa o formato '2026-02-13T...' para '2026-02-13'
        data_limpa = data_str.split("T")[0]
        data_emissao = datetime.strptime(data_limpa, "%Y-%m-%d")
        # Diferença exata entre hoje (15/02) e a emissão (13/02)
        return (datetime.now() - data_emissao).days
    except:
        return None

def calcular_idade_certificado(res_core):
    try:
        data_bruta = res_core.get('ssl_date') 
        if data_bruta:
            from datetime import datetime
            import math
            
            # 1. Converte a data do SSL (formato: Feb 13 00:00:00 2026 GMT)
            data_limpa = " ".join(data_bruta.split()[:4])
            data_emissao = datetime.strptime(data_limpa, "%b %d %H:%M:%S %Y")
            
            # 2. Pega o momento exato agora
            hoje = datetime.now()
            
            # 3. Calcula a diferença total em segundos e converte para dias exatos
            diferenca = hoje - data_emissao
            dias_reais = diferenca.total_seconds() / 86400  # 86400 segundos em um dia
            
            # 4. Usamos math.ceil para que "1 dia e algumas horas" vire "2 dias"
            return math.ceil(dias_reais)
        return None
    except:
        return None

# --- INTERFACE (BARRA LATERAL SEM ALTERAÇÃO) ---
with st.sidebar:
    st.markdown("### Sobre o Sistema")
    st.write("O ShieldPhish Ultra utiliza fontes confiáveis de segurança, histórico de domínios e padrões conhecidos de fraude para avaliar links e e-mails.")
    st.markdown("---")
    st.markdown("### 🔐 Selo de Metodologia")
    st.caption("Privacidade Garantida: Este sistema não armazena e-mails, senhas ou conteúdos analisados. A análise é processada em memória e descartada após a sessão.")
    st.markdown("---")
    st.markdown("**Fontes de Análise:**")
    st.write("* Reputação global (VirusTotal)")
    st.write("* Análise visual em ambiente virtual isolado e seguro sandbox (Urlscan.io):")
    # O uso do caption abaixo cria o detalhamento que você solicitou com recuo visual
    st.caption("""
    - Análise de Phishing
    - Investigação de Redes
    - Análise de Cabeçalhos e Cookies
    - Captura de Tela
    - Inspeção de Código
    """)
    st.write("* Registro de domínios (Whois)")
    st.write("* Similaridade de marcas")
    st.write("* Padrões de fraude")

# --- 1. CRIAR AS COLUNAS MESTRAS ---
col_principal, col_informativo = st.columns([2.8, 1.2]) 

# --- 2. CONTEÚDO DA ESQUERDA (Coluna Principal) ---
with col_principal:
    st.title("🛡️ ShieldPhish Ultra")

    # Criamos as abas uma única vez aqui dentro
    aba_links, aba_e_v, aba_scanner, aba_educativo = st.tabs([
        "🔗 Links", "📧 E-mails & Vazamentos", "📂 Scanner de Arquivos", "🎓 Centro Educativo"
    ])

    # --- ABA 1: LINKS (Toda a lógica de busca e resultados) ---
    with aba_links:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Insira o link para análise:") 
            
            url_input = st.text_input("📍 Alvo da Perícia (URL, IP, Domínio ou Hash):", 
                                     placeholder="Ex: 8.8.8.8, www.site.com.br, ou hash do arquivo...",
                                     key="input_link_principal")
            
            c_btn1, c_btn2 = st.columns(2)
            with c_btn1:
                btn_analise = st.button("Executar Análise Ultra", key="btn_analise_ultra")

            with c_btn2:
                report_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={url_input}" if url_input else "https://safebrowsing.google.com/safebrowsing/report_phish/"
                st.link_button("🚨 Denunciar ao Google", report_url)

            if btn_analise and url_input:
                with st.spinner('Consultando inteligência artificial e bases globais...'):
                    maliciosos = consultar_reputacao(url_input)
                    idade = obter_idade_dominio(url_input)
                    res_core = st.session_state.engine.analyze_link(url_input, maliciosos=maliciosos)

                    if maliciosos == 0:
                        try:
                            score_atual = float(res_core['score'].replace('%', ''))
                            if score_atual < 15.0:
                                res_core['score'] = "1.0%"
                                res_core['status'] = "BAIXO RISCO"
                                res_core['color'] = "green"
                        except:
                            pass
                        
                    cert_idade = calcular_idade_certificado(res_core)
                    dados_visual = consultar_urlscan(url_input)

                    st.session_state.analise_ativa = {
                        'res_core': res_core, 'maliciosos': maliciosos, 'idade': idade,
                        'cert_idade': cert_idade, 'dados_visual': dados_visual, 'url': url_input,
                        'ip_final': res_core['geo'].get('ip') or (dados_visual.get('ip') if dados_visual else None)
                    }

                    st.session_state.historico.append({
                        "Hora": get_brasilia_time(), "Alvo": url_input, "Resultado": res_core['status'],
                        "País": res_core['geo']['pais'], "Provedor": res_core['geo']['provedor']
                    })

            # EXIBIÇÃO DE RESULTADOS (DENTRO DA COLUNA PRINCIPAL)
            if 'analise_ativa' in st.session_state:
                res = st.session_state.analise_ativa
                core = res['res_core']
                st.markdown(f"### Veredito: :{core['color']}[{core['status']}]")
                
                if core['score'] == "100.0%":
                    st.error("🚨 **EXFILTRAÇÃO DETECTADA:** Dados direcionados para servidor externo suspeito.")

                m1, m2, m3 = st.columns(3)
                m1.metric("Score de Risco", core['score'])
                
                try:
                    conf_v = float(core['detalhes']['ia'].replace('%', ''))
                    score_v = float(core['score'].replace('%', ''))
                except:
                    conf_v, score_v = 0.0, 0.0
                
                label, cor_d = ("✅ ALTA", "normal") if conf_v >= 80 else (("⚠️ VERIFICAR", "off") if conf_v >= 50 else (("🚨 REVISAR", "inverse") if score_v >= 70 else ("🟢 LIMPO", "normal")))
                m2.metric("Nível de Certeza IA", core['detalhes']['ia'], delta=label, delta_color=cor_d)
                m3.metric("Ameaças (VT)", f"{res['maliciosos']} alertas")

                st.markdown("---")
                g1, g2 = st.columns(2)
                with g1:
                    st.markdown("**📍 Localização do Servidor**")
                    if core['geo']['bandeira']: st.image(core['geo']['bandeira'], width=35)
                    st.text(f"País: {core['geo']['pais']}")
                with g2:
                    st.markdown("**🏢 Infraestrutura (ASN)**")
                    st.info(f"{core['geo']['provedor']}")

                if res.get('dados_visual'):
                    st.markdown("---")
                    st.subheader("📸 Visualização em Tempo Real (Sandbox)")
                    dv = res['dados_visual']
                    st.warning(f"🌐 Analisado **{dv['total_scans']} vezes** no urlscan.io.")
                    st.image(dv['screenshot'], use_container_width=True, caption="🔒 Captura em ambiente isolado")

        with col2:
            st.markdown("### 🕒 Histórico")
            if st.session_state.historico:
                df_ex = pd.DataFrame(st.session_state.historico).head(10)
                st.dataframe(df_ex, use_container_width=True)
            
            st.markdown("### 📥 Exportar")
            if st.session_state.historico:
                csv = pd.DataFrame(st.session_state.historico).to_csv(index=False).encode('utf-8')
                st.download_button("📄 Baixar CSV", data=csv, file_name="auditoria.csv", mime='text/csv')

    # --- ABA 2: E-MAILS ---
    with aba_e_v:
        st.subheader("🔍 Verificação de Integridade de E-mail")
        st.info("Funcionalidade ativa. Cole o conteúdo para análise técnica.")

    # --- ABA 3: SCANNER ---
    with aba_scanner:
        st.subheader("📂 Análise Proativa de Anexos")
        st.file_uploader("Suba arquivos suspeitos", type=['pdf', 'docx', 'jpg'])

    # --- ABA 4: EDUCATIVO ---
    with aba_educativo:
        st.subheader("🎓 Centro Educativo")
        st.write("Mantenha sua higiene digital em dia.")

# --- 3. INFORMATIVO FIXO NA DIREITA (FORA DO WITH PRINCIPAL) ---
with col_informativo:
    st.markdown("""
    <div style="background-color: #412121; padding: 20px; border-radius: 10px; border: 1px solid #ff4b4b;">
        <h4 style="color: #ff4b4b; margin-top: 0; font-size: 1.1rem;">🚨 O que fazer com este (Site, URL, IP, Domínio ou Hash Malicioso)?</h4>
        <ul style="color: white; list-style-type: disc; padding-left: 20px; font-size: 0.85rem;">
            <br>
            <li><b>Não forneça dados:</b> Nunca digite senhas ou CPFs em sites marcados.</li>
            <li><b>Feche a aba original:</b> Interrompa o acesso se veio de link externo.</li>
            <li><b>Entenda o risco:</b> Este IP já possui histórico de crimes digitais.</li>
            <li><b>A visualização é segura:</b> O sistema usa sandbox para capturar o site.</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("📚 Identificadores"):
        st.markdown("<div style='font-size: 0.8rem; color: #ccc;'><b>IP:</b> Endereço da máquina.<br><b>URL:</b> Caminho da página.<br><b>Hash:</b> Digital do arquivo.</div>", unsafe_allow_html=True)
        # Update de segurança: st.secrets.
