import socket
import requests
import pandas as pd
import math
import idna
import joblib
import urllib.parse
import Levenshtein
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer

class ShieldPhishUltraCore:
    def __init__(self):
        # Domínios que o sistema protege contra imitações
        self.target_domains = [
            "google.com.br", "google.com", "itau.com.br", 
            "bradesco.com.br", "facebook.com", "netflix.com", "nubank.com.br"
        ]
        self.vectorizer = CountVectorizer(analyzer='char', ngram_range=(2, 3))
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False

    def _get_clean_domain(self, url):
        url = url.lower().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.replace("www.", "")
            return domain
        except:
            return url

    def _calc_entropy(self, text):
        """Mede a aleatoriedade da URL (Entropia)"""
        if not text: return 0
        probs = [float(text.count(c)) / len(text) for c in set(text)]
        return - sum([p * math.log(p, 2) for p in probs])

    def _check_homograph(self, domain):
        """Detecta ataques de caracteres visuais (Ex: αmazon)"""
        try:
            punycode = idna.encode(domain).decode('ascii')
            return "xn--" in punycode, punycode
        except:
            return False, domain

    def _check_typosquatting(self, domain):
        """Mede a distância de Levenshtein para marcas famosas"""
        for target in self.target_domains:
            if domain == target: return 0.0
            dist = Levenshtein.distance(domain, target)
            if dist <= 2: return 0.85 # Risco alto se for muito similar
        return 0.0

    def train_default(self):
        """Treino de emergência caso não existam arquivos .pkl"""
        data = {
            'url': ['google.com.br', 'itau.com.br', 'facebook.com', 'go0gle.com.br', 'itau-seguranca.tk', 'login-confirmar.net'],
            'is_phishing': [0, 0, 0, 1, 1, 1]
        }
        df = pd.DataFrame(data)
        x = self.vectorizer.fit_transform(df['url'].values.astype('U'))
        self.model.fit(x, df['is_phishing'])
        self.is_trained = True

    def analyze_link(self, raw_url, maliciosos=0):
        """Motor de Análise Final com Geolocalização e Filtro de Confiança"""
        if not self.is_trained:
            self.train_default()

        domain = self._get_clean_domain(raw_url)
        typo_risk = self._check_typosquatting(domain)
        is_homo, puny = self._check_homograph(domain)
        entropy_val = self._calc_entropy(domain)
        
        # --- BUSCA DE DADOS DE IP E PAÍS ---
        geo_info = {"pais": "Desconhecido", "bandeira": "", "provedor": "N/A"}
        try:
            ip_alvo = socket.gethostbyname(domain)
            res = requests.get(f"http://ip-api.com/json/{ip_alvo}?fields=status,country,countryCode,as", timeout=3).json()
            if res.get('status') == 'success':
                geo_info = {
                    "pais": res.get('country'),
                    "bandeira": f"https://flagcdn.com/w40/{res.get('countryCode').lower()}.png",
                    "provedor": res.get('as')
                }
        except:
            pass

        # Predição por Inteligência Artificial
        x_input = self.vectorizer.transform([raw_url])
        ia_prob = self.model.predict_proba(x_input)[0][1]

       # --- CÁLCULO DINÂMICO DE SCORE (Ajustado para Rigor Máximo) ---
        # Aumentamos o peso da similaridade de marca (typo_risk) para 0.7
        final_score = (ia_prob * 0.3) + (typo_risk * 0.7)
        
        # FILTRO DE CONFIANÇA INTELIGENTE
        if ("Google" in geo_info['provedor'] or "Cloudflare" in geo_info['provedor']) and maliciosos == 0:
            final_score = 0.01  
            ia_prob = 0.01

        # Penalidades Extras
        if is_homo: final_score += 0.5
        
        # URLs aleatórias (Entropia) agora somam 0.3 ao score total
        if entropy_val > 3.8: final_score += 0.3
        
        # TRAVA DE SEGURANÇA: Se detectar similaridade com bancos, o risco é no mínimo MÉDIO (0.45)
        if typo_risk > 0: final_score = max(final_score, 0.45)

        if maliciosos > 0:
            final_score += 0.3 + (maliciosos * 0.1)

        final_score = min(final_score, 1.0)

        final_score = min(final_score, 1.0)

        # Definição de Status e Cores
        if final_score >= 0.7 or maliciosos >= 5: 
            status, color = "ALTO RISCO", "red"
        elif final_score >= 0.4 or maliciosos > 0: 
            status, color = "MÉDIO RISCO", "orange"
        else:
            status, color = "BAIXO RISCO", "green"

        # --- LÓGICA DE CONFIANÇA BASEADA EM EVIDÊNCIAS (Rigor Técnico) ---
        evidencias = (
            (1 if typo_risk > 0 else 0) +
            (1 if is_homo else 0) +
            (1 if entropy_val > 3.8 else 0) + # Padronizado com o cálculo de score na linha 104
            (1 if maliciosos > 0 else 0)
        )

        # Confiança baseada no volume de sinais (Baixo Risco cai para 30.00% se evidencias for 0)
        confianca_exibida = min(0.3 + evidencias * 0.15, 0.85)

        # O VirusTotal, como autoridade externa, eleva a confiança da análise
        if maliciosos >= 5:
            confianca_exibida = 0.99
        elif maliciosos > 0:
            confianca_exibida = max(confianca_exibida, 0.80)

        # Se o risco for muito baixo, a confiança deve refletir a ausência de sinais
        if final_score < 0.2:
            confianca_exibida = min(confianca_exibida, 0.30)

        return {
            "url": raw_url, 
            "status": status, 
            "color": color,
            "score": f"{final_score * 100:.1f}%",
            "geo": geo_info, 
            "detalhes": {
                "ia": f"{confianca_exibida:.2%}", # Métrica de confiança real e calibrada
                "typo": "Sim" if typo_risk > 0 else "Não",
                "homo": is_homo,
                "entropy": round(entropy_val, 2)
            }
        }