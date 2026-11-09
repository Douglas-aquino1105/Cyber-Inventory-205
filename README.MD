# Gerenciador de Ativos

Sistema desenvolvido em Python para gerenciamento de ativos, utilizando programação orientada a objetos (POO).

## Funcionalidades

- Cadastro de ativos.
- Consulta de ativos.
- Edição de informações.
- Remoção de registros.
- Cadastro de vulnerabilidades associadas a cada ativo.
- Estabelecimento de relação de dependência entre ativos.
- Cálculo de risco individual e total de cada ativo.
- Armazenamento persistente em arquivos JSON.

## Tecnologias utilizadas

- Python
- Docker
- Docker Compose
- JSON

## Pré-requisitos

- Docker instalado.
- Docker Compose instalado.

## Como executar

Clone o repositório:

```bash
  git clone https://github.com/Douglas-aquino1105/Cyber-Inventory-205
```

Entre na pasta do projeto:

```bash
  cd Cyber-Inventory-205
```

Construa a imagem e inicie o container:

```bash
  docker compose up -d --build
```

## Gerenciamento do container

Visualizar o estado dos serviços:

```bash
  docker compose ps
```

Visualizar os logs:

```bash
  docker compose logs -f
```

Parar e remover os containers:

```bash
  docker compose down
```
Interagir com o container:

```bash
  docker attach --detach-keys="ctrl-x" trab02_2026_2_12621CBS205
```
Para cancelar a interação com o container pressione `ctrl+x`

## Persistência de dados

Os dados são armazenados em arquivos JSON dentro da pasta `/app/data` no container.

O Docker utiliza um volume nomeado chamado `dados_trab02_2026_2_12621CBS205:` para garantir que os dados sejam preservados mesmo quando o container é removido.

**Atenção:** para remover também o volume e seus dados, utilize:

```bash
  docker compose down -v
```

## Autor

Desenvolvido por [Douglas Oliveira de Aquino].
