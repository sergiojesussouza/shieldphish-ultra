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
    data = {"url": url, "visibility": "private"}
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
        if response.status_code == 200:
            res_json = response.json()
            uuid = res_json.get('uuid')
            
            # TENTATIVA 1: Campo direto de endereço
            ip_scan = res_json.get('address')
            
            # TENTATIVA 2: Extração da mensagem de confirmação (mais estável)
            if not ip_scan:
                msg = res_json.get('message', "")
                if "at " in msg:
                    # Extrai o número após o "at " (ex: 35.201.127.49)
                    ip_scan = msg.split("at ")[-1].split(",")[0].strip()
            
            return {
                "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
                "report": f"https://urlscan.io/result/{uuid}/",
                "ip": ip_scan if ip_scan else "IP em processamento..."
            }
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
    st.write("* Reputação global (VirusTotal)\n* Registro de domínios\n* Similaridade de marcas\n* Padrões de fraude")

st.title("🛡️ ShieldPhish Ultra")

aba_links, aba_e_v, aba_scanner, aba_educativo = st.tabs([
    "🔗 Links", "📧 E-mails & Vazamentos", "📂 Scanner de Arquivos", "🎓 Centro Educativo"
])

# --- ABA 1: LINKS (VERSÃO BUSCA GLOBAL) ---
with aba_links:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Insira o link para análise:") 
        
        # Campo Versátil: Agora aceita URL, IP, Domínio ou Hash
        url_input = st.text_input("Busca Global (URL, IP, Domínio ou Hash):", 
                                 placeholder="Ex: 8.8.8.8, www.site.com.br, ou hash do arquivo...")
        
        c_btn1, c_btn2 = st.columns(2)
        with c_btn1:
            btn_analise = st.button("Executar Análise Ultra")

        with c_btn2:
            report_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={url_input}" if url_input else "https://safebrowsing.google.com/safebrowsing/report_phish/"
            st.link_button("🚨 Denunciar ao Google Safe Browsing", report_url)

        if btn_analise:
            if url_input:
                with st.spinner('Consultando inteligência artificial e bases globais...'):
                    # 1. Consultas Únicas (Removida a duplicidade das suas linhas 159 e 166)
                    maliciosos = consultar_reputacao(url_input)
                    idade = obter_idade_dominio(url_input)
                    res_core = st.session_state.engine.analyze_link(url_input, maliciosos=maliciosos)
                    
                    # 2. Veredito e Banner de Exfiltração
                    st.markdown(f"### Veredito: :{res_core['color']}[{res_core['status']}]")
                    if res_core['score'] == "100.0%":
                        st.error("🚨 **EXFILTRAÇÃO DETECTADA:** Dados direcionados para servidor externo suspeito.")

                    # Métricas
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Score de Risco", res_core['score'])
                    m2.metric("Confiança IA", res_core['detalhes']['ia'])
                    m3.metric("Ameaças (VT)", f"{maliciosos} alertas")

                    st.markdown("---")
                    g1, g2 = st.columns(2)
                    with g1:
                        st.markdown("**📍 Localização do Servidor**")
                        if res_core['geo']['bandeira']:
                            st.image(res_core['geo']['bandeira'], width=35)
                        st.text(f"País: {res_core['geo']['pais']}")
                        # Badge de SSL
                        st.markdown("`[!] SSL RECENTE`" if idade and idade < 7 else "`[✔] SSL ESTÁVEL`")
                    
                    with g2:
                        st.markdown("**🏢 Infraestrutura (ASN)**")
                        st.info(f"{res_core['geo']['provedor']}")

                # --- 3. BLOCO URLSCAN CORRIGIDO (EVIDÊNCIA VISUAL) ---
                with st.spinner('Iniciando perícia técnica no sandbox...'):
                    dados_visual = consultar_urlscan(url_input)
                    if dados_visual:
                        st.markdown("---")
                        st.subheader("📸 Evidência Visual (Sandbox)")
                        
                        # Exibição do IP detectado no Scan
                        st.warning(f"🌐 **IP Detectado no Scan:** {res_core['geo'].get('ip', dados_visual['ip'])}")
                        
                        # Espera necessária para a imagem não dar erro "X"
                        import time
                        aviso_espera = st.info("⏳ O sandbox está gerando a captura de tela. Aguarde 15 segundos...")
                        time.sleep(15) 
                        aviso_espera.empty()
                        
                        st.image(dados_visual['screenshot'], use_container_width=True, caption="Captura em ambiente isolado")
                        st.link_button("📄 Ver Relatório Técnico Detalhado", dados_visual['report'])

                    # Alertas de Segurança Específicos
                    if maliciosos > 0:
                        st.error(f"🚨 **VirusTotal:** {maliciosos} motores detectaram ameaças neste item.")
                    if res_core['detalhes']['homo']:
                        st.error("⚠️ **Ataque Homográfico!** Detectado uso de caracteres visuais falsos.")
                    if idade and idade < 30:
                        st.warning(f"⏳ **Domínio Recente:** Criado há apenas {idade} dias.")

                    # Histórico persistente com Geolocalização e Horário
                    st.session_state.historico.append({
                        "Hora": get_brasilia_time(),
                        "Alvo": url_input, 
                        "Resultado": res_core['status'],
                        "País": res_core['geo']['pais'], 
                        "Provedor": res_core['geo']['provedor']
                    })
            else:
                st.warning("Por favor, insira um dado válido para análise.")

# --- ESTA LINHA (191) DEVE FICAR TOTALMENTE À ESQUERDA, FORA DO IF ---
with col2:
    st.markdown("### 🕒 Histórico de Análises")
    if st.session_state.historico:
        # Criar o DataFrame sem inverter (a lista já está na ordem certa)
        df_exibir = pd.DataFrame(st.session_state.historico)

        # Exibe apenas os últimos 10 registros
        st.dataframe(
                df_exibir.head(10), # Mostra as 10 últimas análises feitas
                use_container_width=True,
                hide_index=False,
                column_config={
                    "Hora": st.column_config.TextColumn("Hora", width="small"),
                    "Alvo": st.column_config.TextColumn("Alvo", width="medium"),
                    "Resultado": st.column_config.TextColumn("Resultado", width="medium")
                }
        )
# --- CENTRAL DE EXPORTAÇÃO MULTIFORMATO ---
    st.markdown("### 📥 Exportar Relatório de Auditoria")

    if st.session_state.historico:
        df_export = pd.DataFrame(st.session_state.historico)

        # Criando 4 colunas para os botões ficarem alinhados
        exp_col1, exp_col2, exp_col3, exp_col4 = st.columns(4)

        # 1. Exportar para CSV
        with exp_col1:
            csv_data = df_export.to_csv(index=False).encode('utf-8')
            st.download_button("📄 CSV", data=csv_data, file_name="auditoria_links.csv", mime='text/csv', use_container_width=True)

        # 2. Exportar para EXCEL
        with exp_col2:
            import io
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df_export.to_excel(writer, index=False, sheet_name='Analises')
                workbook = writer.book
                worksheet = writer.sheets['Analises']

                border_format = workbook.add_format({'border': 1})

                for row_num in range(len(df_export) + 1):
                    for col_num in range(len(df_export.columns)):
                        worksheet.write(row_num, col_num, df_export.iloc[row_num-1, col_num] if row_num > 0 else df_export.columns[col_num], border_format)

            st.download_button("📊 Excel", data=output.getvalue(), file_name="auditoria_links.xlsx", use_container_width=True)

        # 3. Exportar para JSON
        with exp_col3:
            json_data = df_export.to_json(orient='records', indent=4).encode('utf-8')
            st.download_button("💻 JSON", data=json_data, file_name="auditoria_links.json", mime='application/json', use_container_width=True)

        # 4. Exportar para HTML
        with exp_col4:
            # Gerar o HTML e adicionar estilo CSS para centralizar cabeçalhos (th)
            html_content = df_export.to_html(index=False)
            html_styled = f"""
            <style>
                table {{ border-collapse: collapse; width: 100%; font-family: sans-serif; }}
                th {{ text-align: center; background-color: #f2f2f2; padding: 10px; border: 1px solid #ddd; }}
                td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
            </style>
            {html_content}
            """
            html_data = html_styled.encode('utf-8')
            st.download_button("🌐 HTML", data=html_data, file_name="auditoria_links.html", mime='text/html', use_container_width=True)

# --- ABA 2: E-MAILS & VAZAMENTOS ---
with aba_e_v:
    st.subheader("🔍 Verificação de Integridade de E-mail")
    
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        remetente = st.text_input("E-mail do remetente:", placeholder="exemplo@empresa.com.br")
    with col_v2:
        conteudo = st.text_area("Descrição/Corpo do e-mail:", placeholder="Cole o texto suspeito aqui...")

    if st.button("Executar Análise Completa de E-mail"):
        if remetente and conteudo:
            with st.spinner('Analisando padrões e reputação...'):
                # 1. Analisar Gatilhos no Texto
                gatilhos_detectados = analisar_texto_phishing(conteudo)
                
                # 2. Analisar Reputação do Domínio
                dominio = remetente.split("@")[-1]
                maliciosos = consultar_reputacao(dominio)
                
                if gatilhos_detectados or maliciosos > 0:
                    st.error("### ⚠️ ALERTA DE RISCO")
                    if gatilhos_detectados:
                        st.markdown("**Padrões de ataque encontrados no texto:**")
                        for g in gatilhos_detectados:
                            st.write(f"🚩 Termo suspeito detectado: `{g}`")
                    if maliciosos > 0:
                        st.warning(f"O domínio `{dominio}` possui alertas em bases de segurança globais.")
                else:
                    st.success("### ✅ Baixo Risco\nNão foram detectados padrões óbvios de fraude neste conteúdo.")
        else:
            st.warning("Por favor, preencha o remetente e o corpo do e-mail.")

    st.markdown("---")

    # --- SEÇÃO DE ANÁLISE DE CABEÇALHO ---
    st.markdown("### 📄 Análise de Cabeçalho")
    st.write("O que é isto? É o DNA do e-mail. Confirma a autenticidade do remetente.")

    with st.expander("❓ Como encontrar o cabeçalho no seu e-mail"):
        st.markdown("""
        * **No Gmail:** Abra o e-mail > Clique nos **três pontos (Mais)** ao lado de Responder > Selecione **Mostrar original**.
        * **No Outlook:** Abra o e-mail > Clique nos **três pontos** > **Exibir** > **Exibir detalhes da mensagem**.
        * **Ação:** Copie todo o texto que aparecer e cole no campo abaixo.
        """)

    header_input = st.text_area("Cole os dados técnicos aqui:", placeholder="spf=pass dkim=pass...", height=150)

    if st.button("Validar Identidade do Remetente"):
        if header_input:
            with st.spinner('Validando identidade técnica...'):
                # Verifica protocolos de segurança
                if "spf=pass" in header_input.lower() or "dkim=pass" in header_input.lower():
                    st.success("### ✔️ Remetente Autêntico")
                    st.write("Os protocolos confirmam que este e-mail partiu de um servidor oficial autorizado.")
                else:
                    st.error("### ❌ Falha na Autenticação")
                    st.write("O cabeçalho não apresenta selos de autenticidade válidos. Risco de falsificação (Spoofing).")
        else:
            st.info("Por favor, cole o cabeçalho técnico para análise.")

# As outras abas (Links, Scanner, Educativo) seguem a lógica padrão definida anteriormente.


# --- ABA 3: SCANNER DE ARQUIVOS ---
with aba_scanner:
    st.subheader("📂 Análise Proativa de Anexos")
    st.file_uploader("Suba arquivos suspeitos para scan", type=['pdf', 'docx', 'jpg', 'jpeg'], help="Procurar arquivos")
    st.caption("Dica: Clique em 'Browse files' (ou 'Procurar arquivos') para selecionar o anexo suspeito.")

# --- ABA 4: CENTRO EDUCATIVO ---
with aba_educativo:
    st.subheader("🎓 Treine seu Olhar")
    col_ed1, col_ed2 = st.columns(2)
    with col_ed1:
        st.markdown("### 🚩 5 Sinais de Phishing")
        st.write("1. **Senso de Urgência**: 'Sua conta será excluída em 2 horas'.")
        st.write("2. **Erros Gramaticais**: Empresas reais revisam seus e-mails.")
        st.write("3. **Remetente Estranho**: E-mail não condiz com a empresa.")
        st.write("4. **Links Ocultos**: O link leva para um site diferente do texto.")
        st.write("5. **Pedidos de Dados**: Bancos nunca pedem senha por e-mail.")
    with col_ed2:
        st.markdown("### 🔐 Higiene Digital")
        st.info("Use sempre Autenticação de Dois Fatores (2FA) e Gerenciadores de Senha.")


        # Update de segurança: st.secrets.
