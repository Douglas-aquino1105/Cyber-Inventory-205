
import requests
import re


class VulnerabilidadeAPI:

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    MITRE_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness"

    @staticmethod
    def buscar_cve(cve):

        # Verifica se o formato do CVE é válido
        cve = cve.strip().upper()

        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            print("[Erro] Formato de CVE inválido.")
            return None

        try:
            resposta = requests.get(
                VulnerabilidadeAPI.NVD_URL,
                params={"cveId": cve},
                timeout=15
            )

            resposta.raise_for_status()

            dados = resposta.json()

            if dados.get("totalResults", 0) == 0:
                print("[Erro] CVE não encontrado.")
                return None

            return dados["vulnerabilities"][0]["cve"]

        except requests.exceptions.RequestException as erro:
            print(f"[Erro] Falha na comunicação com a API: {erro}")
            return None

        except (ValueError, KeyError, IndexError, TypeError) as erro:
            print(f"[Erro] Não foi possível interpretar a resposta da API: {erro}")
            return None

    @staticmethod
    def extrair_cwes(cve_dados):

        weaknesses = cve_dados.get("weaknesses", [])

        cwes = []

        for weakness in weaknesses:

            for descricao in weakness.get("description", []):

                if descricao.get("lang") == "en":

                    cwe = descricao.get("value", "")

                    # Aceita somente identificadores CWE numéricos
                    if re.fullmatch(r"CWE-\d+", cwe):

                        if cwe not in cwes:
                            cwes.append(cwe)

        return cwes

    @staticmethod
    def buscar_descricoes_cwe(cwes):

        if not cwes:
            return []

        # Remove o prefixo CWE-
        numeros = [
            cwe.replace("CWE-", "")
            for cwe in cwes
        ]

        # Consulta todos os CWEs em uma única requisição
        identificadores = ",".join(numeros)

        url = f"{VulnerabilidadeAPI.MITRE_URL}/{identificadores}"

        resposta = requests.get(url, timeout=15)

        resposta.raise_for_status()

        dados = resposta.json()

        resultados = []

        for weakness in dados.get("Weaknesses", []):

            resultados.append({
                "cwe": f"CWE-{weakness['ID']}",
                "nome": weakness["Name"],
                "descricao": weakness["Description"]
            })

        return resultados

    @staticmethod
    def buscar_cvss(cve_dados):
        # Obtém as métricas CVSS
        metrics = cve_dados.get("metrics", {})

        # Procura a versão mais recente disponível
        versoes = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2"
        ]

        encontrado = False

        for versao in versoes:
            if versao in metrics:
                cvss = metrics[versao][0]["cvssData"]

                # print("Score CVSS:", cvss["baseScore"])
                # print("Severidade:", cvss.get("baseSeverity", "Não informada"))
                # print("Versão CVSS:", cvss["version"])

                encontrado = True
                return cvss

        if not encontrado:
            print("Score CVSS não disponível.")
