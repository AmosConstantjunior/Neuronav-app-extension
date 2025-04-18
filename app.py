from flask import Flask, render_template, request, redirect, url_for,jsonify,flash
import sqlite3
import os
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime



app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(app.config['DATABASE']):
        with get_db_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("Base de données initialisée")

# Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token mal formaté'}), 401
        
        if not token:
            return jsonify({'message': 'Token manquant'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            with get_db_connection() as conn:
                current_user = conn.execute(
                    'SELECT * FROM users WHERE email = ?', 
                    (data['email'],)
                ).fetchone()
            
            if not current_user:
                return jsonify({'message': 'Utilisateur introuvable'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token invalide'}), 401
        except Exception as e:
            return jsonify({'message': f'Erreur d\'authentification: {str(e)}'}), 500
            
        return f(current_user, *args, **kwargs)
        
    return decorated


# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

# Page d'inscription
@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        
        if not all([username, email, password, confirmation]):
            flash('Tous les champs sont obligatoires', 'error')
            return redirect(url_for('inscription'))
        
        if password != confirmation:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('inscription'))
        
        if len(password) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères', 'error')
            return redirect(url_for('inscription'))
        
        try:
            password_hash = generate_password_hash(password)
            with get_db_connection() as conn:
                conn.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                conn.commit()
            
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Cet email ou nom d\'utilisateur est déjà utilisé', 'error')
            return redirect(url_for('inscription'))
        except Exception as e:
            flash(f'Erreur lors de l\'inscription: {str(e)}', 'error')
    
    return render_template('inscriptions.html')


@app.route('/v1/auth/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Pré-vol CORS accepté'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', '*')
        response.headers.add('Access-Control-Allow-Methods', '*')
        return response

    data = request.get_json()

    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email et mot de passe requis'}), 400
    
    try:
        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE email = ?', 
                (data['email'],)
            ).fetchone()
        
        if user and check_password_hash(user['password_hash'], data['password']):
            token = jwt.encode({
                'email': user['email'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            response = jsonify({
                'token': token,
                'user': {
                    'email': user['email'],
                    'username': user['username']
                }
            })
            response.status_code = 200
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
        
    except Exception as e:
        return jsonify({'error': f'Erreur de connexion: {str(e)}'}), 500

@app.route('/v1/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({
        'user': {
            'email': current_user['email'],
            'username': current_user['username']
        }
    }), 200


if __name__ == '__main__':
    app.run(debug=True)
