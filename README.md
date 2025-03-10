---


## **app/: Contains the Flask application code.

### ***__init__.py: Initializes the Flask application.***
### ***database.py: Manages the connection to the database.***
### ***models.py: Defines the data models.***
### ***routes.py: Defines the API routes.***
### ***utils.py: Contains utility functions for encryption and other operations.***
### ***.gitignore: File for ignoring files in Git.***
### ***config.py: Application settings.***
### ***README.md: Project documentation.***
### ***run.py: Script to start the application.***


---


## **Technologies Used**
### ***Flask: Python web framework to create the API.***
### ***bcrypt: Password encryption library.***
### ***Cryptography: Library for encrypting messages.***
### ***Python: Main programming language.***
### ***dotenv: To manage environment variables.***



---

## **Configuration**

* Repository clone:**
```
git clone <REPOSITORY_URL>
cd <REPOSITORY_NAME>
```
* Create a virtual environment (optional, but recommended):**
```
python3 -m venv venv
source venv/bin/activate # On Linux/macOS
venv\Scripts\activate # On Windows
```
**Install the dependencies:**
```
pip install -r requirements.txt
```
* Set the environment variables:
* Create an .env file in the root of the project and add the following variables:
```
SECRET_KEY=<YOUR_FLASK_SECRET_KEY>
DATABASE_URL=<YOUR_DATABASE_URL>
```
* Replace <YOUR_FLASK_SECRET_KEY> with a secure secret key for Flask and <URL_YOUR_DATABASE> with your database connection URL.


---
# Running the application
To start the application, run the following command:
```
python run.py
```
The API will be available at http://127.0.0.1:5000/.


---
## **API Endpoints**
**Message Encryption
* POST /encrypt: Encrypts a message.
  * Request body:
```
{
    “message": ”message to be encrypted”
}
```
  * Response:
```
{
  “encrypted_message": ”encrypted message”
}
```
* POST /decrypt: Decrypts a message.
  * Request body:
```
{
  “encrypted_message": ”encrypted message”
}
```
  * Response:
```
{
  “message": ”decrypted message”
}
```


**Password encryption
* POST /hash_password: Encrypts a password.
  * Request body:
```
{
  “password": ”password to be encrypted”
}
```
  * Response:
```
{
  “hashed_password": ”encrypted password”
}
```
* POST /verify_password: Checks if a password matches a hash.
  * Request body:
```
{
  “password": ‘password to be verified’,
  “hashed_password": ”encrypted password”
}
```
  * Response:
```
{
  “result": true/false
}
```


---

## **Contributions**
* Professor Fabiano Menegidio
