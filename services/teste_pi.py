
import requests

# Endereço da API
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Recebe o CVE
cve = input("Digite o CVE: ")

# Parâmetros da requisição
params = {
    "cveId": cve
}

try:
    # Realiza a requisição GET
    resposta = requests.get(url, params=params, timeout=15)

    # Verifica se ocorreu algum erro HTTP
    resposta.raise_for_status()

    # Converte o JSON recebido em dicionário Python
    dados = resposta.json()

    # Verifica se encontrou alguma vulnerabilidade
    if dados["totalResults"] == 0:
        print("Vulnerabilidade não encontrada.")

    else:
        # Acessa a primeira vulnerabilidade
        cve_dados = dados["vulnerabilities"][0]["cve"]
        print(dados)

        print("\n--- VULNERABILIDADE ---")

        print("CVE:", cve_dados["id"])

        # Obtém a descrição em inglês
        descricao = cve_dados["descriptions"][0]["value"]

        print("Descrição:", descricao)

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

                print("Score CVSS:", cvss["baseScore"])
                print("Severidade:", cvss.get("baseSeverity", "Não informada"))
                print("Versão CVSS:", cvss["version"])

                encontrado = True
                break

        if not encontrado:
            print("Score CVSS não disponível.")

except requests.exceptions.Timeout:
    print("A API demorou demais para responder.")

except requests.exceptions.HTTPError as erro:
    print("Erro HTTP:", erro)

except requests.exceptions.RequestException as erro:
    print("Erro de conexão:", erro)

except (KeyError, IndexError, TypeError) as erro:
    print("Erro ao interpretar os dados:", erro)
