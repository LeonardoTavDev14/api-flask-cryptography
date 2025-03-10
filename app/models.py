from app.database import get_db_connection
from app.utils import hash_password, verify_password, generate_rsa_keys

class User:
    def __init__(self, username, password, public_key=None, private_key=None, id=None, password_hash=None):
        self.id = id
        self.username = username
        self.password = password
        self.public_key = public_key
        self.private_key = private_key
        self.password_hash = password_hash

    def save(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        if self.id:
            cursor.execute(
                "UPDATE users SET username = %s, password_hash = %s, public_key = %s, private_key = %s WHERE id = %s",
                (self.username, hash_password(self.password), self.public_key, self.private_key, self.id),
            )
        else:
            public_key, private_key = generate_rsa_keys()
            cursor.execute(
                "INSERT INTO users (username, password_hash, public_key, private_key) VALUES (%s, %s, %s, %s)",
                (self.username, hash_password(self.password), public_key, private_key),
            )
            self.id = cursor.lastrowid
            self.public_key = public_key
            self.private_key = private_key
        conn.commit()
        cursor.close()
        conn.close()
        return self

    @staticmethod
    def find_by_username(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, public_key, private_key FROM users WHERE username = %s",
            (username,),
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            print(f"Type of public_key from DB: {type(result[3])}")
            print(f"Content of public_key from DB: {result[3][:50]}...")
            return User(
                username=result[1],
                password=None,
                public_key=result[3],
                private_key=result[4],
                id=result[0],
                password_hash=result[2],
            )
        return None

    @staticmethod
    def find_by_id(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, public_key, private_key FROM users WHERE id = %s",
            (user_id,),
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return User(
                username=result[1],
                password=None,
                public_key=result[3],
                private_key=result[4],
                id=result[0],
                password_hash=result[2],
            )
        return None

    @staticmethod
    def verify_password(password, hashed_password):
        return verify_password(password, hashed_password)