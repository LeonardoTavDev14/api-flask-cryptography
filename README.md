---


## **app/: Contém o código da aplicação Flask.**

### ***__init__.py: Inicializa a aplicação Flask.***
### ***database.py: Gerencia a conexão com o banco de dados.***
### ***models.py: Define os modelos de dados.***
### ***routes.py: Define as rotas da API.***
### ***utils.py: Contém funções utilitárias para criptografia e outras operações.***
### ***.gitignore: Arquivo para ignorar arquivos no Git.***
### ***config.py: Configurações da aplicação.***
### ***README.md: Documentação do projeto.***
### ***run.py: Script para iniciar a aplicação.***


---


## **Tecnologias Utilizadas**
### ***Flask: Framework web Python para criar a API.***
### ***bcrypt: Biblioteca para criptografia de senhas.***
### ***Cryptography: Biblioteca para criptografia de mensagens.***
### ***Python: Linguagem de programação principal.***
### ***dotenv: Para gerenciar variáveis de ambiente.***


---

## **Configuração**

*   **Clone do Repositório:**
```
git clone <URL_DO_REPOSITÓRIO>
cd <NOME_DO_REPOSITÓRIO>
```
*   **Crie um ambiente virtual (opcional, mas recomendado):**
```
python3 -m venv venv
source venv/bin/activate  # No Linux/macOS
venv\Scripts\activate  # No Windows
```
*   **Instale as dependências:**
```
pip install -r requirements.txt
```
*   Configure as variáveis de ambiente:
*   Crie um arquivo .env na raiz do projeto e adicione as seguintes variáveis:
```
SECRET_KEY=<SUA_CHAVE_SECRETA_DO_FLASK>
DATABASE_URL=<URL_DO_SEU_BANCO_DE_DADOS>
```
*   Substitua <SUA_CHAVE_SECRETA_DO_FLASK> por uma chave secreta segura para o Flask e <URL_DO_SEU_BANCO_DE_DADOS> pela URL de conexão do seu banco de dados.


---
# **Executando a Aplicação**
Para iniciar a aplicação, execute o seguinte comando:
```
python run.py
```
A API estará disponível em http://127.0.0.1:5000/.


---
## **Endpoints da API**
**Criptografia de Mensagens**
*   POST /encrypt: Criptografa uma mensagem.
  *   Corpo da requisição:
```
{
    "message": "mensagem a ser criptografada"
}
```
  *  Resposta:
```
{
  "encrypted_message": "mensagem criptografada"
}
```
*   POST /decrypt: Descriptografa uma mensagem.
  *   Corpo da requisição:
```
{
  "encrypted_message": "mensagem criptografada"
}
```
  *  Resposta:
```
{
  "message": "mensagem descriptografada"
}
```


**Criptografia de Senhas**
*   POST /hash_password: Criptografa uma senha.
  *   Corpo da requisição:
```
{
  "password": "senha a ser criptografada"
}
```
  *  Resposta:
```
{
  "hashed_password": "senha criptografada"
}
```
*   POST /verify_password: Verifica se uma senha corresponde a um hash.
  *   Corpo da requisição:
```
{
  "password": "senha a ser verificada",
  "hashed_password": "senha criptografada"
}
```
  *  Resposta:
```
{
  "result": true/false
}
```


---

## **Contribuições**
*   Professor Fabiano Menegidio
