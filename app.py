from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import sqlite3
import os
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from utils.groq_client import call_groq  # Assurez-vous que le fichier groq_client.py existe avec la fonction call_groq

from io import BytesIO


app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete_tres_securisee'
app.config['DATABASE'] = 'users.db'
hf_token = os.getenv('HF_USER_ACCESS_TOKEN')
api_key = os.getenv('GROQ_API_KEY')

# Supprimer le chargement du modèle PyTorch
# model_name = "distilgpt2"  # Ce n'est plus utilisé
# tokenizer = AutoTokenizer.from_pretrained(model_name)
# model = None


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


@app.route("/chat/completions", methods=["POST"])
def chat():
    if not request.is_json:
        return jsonify({"error": "Requête non valide"}), 400
    
    # Récupérer les données de la requête
    data = request.get_json()
    messages = data.get('messages', [])
    model_params = data.get("model_params", {})  # <-- ici on récupère les params

    if not messages:
        return jsonify({"error": "Aucun message reçu"}), 400
    
    user_message = messages[0].get("content", "")
    
    # Utilisation de l'API Groq pour obtenir la réponse
    result = call_groq(messages,api_key)
    bot_response = result["choices"][0]["message"]["content"]

    return jsonify({"choices": [{
            "message": {
                "role": "bot",
                "content": messages,
                # "content": bot_response

            }
        }]}), 200


# Nouveau endpoint pour utiliser Groq pour différentes fonctionnalités
@app.route("/summarize", methods=["POST"])
def summarize():
    text = request.json.get("text", "")
    messages = [
        {"role": "system", "content": "Tu es un assistant expert en résumés. Résume le texte donné de manière concise."},
        {"role": "user", "content": text}
    ]
    result = call_groq(messages,api_key)
    summary = result["choices"][0]["message"]["content"]

    return jsonify({
        "result": summary,
        "original_length": len(text),
        "summary_length": len(summary)
    })


@app.route("/correct-text", methods=["POST"])
def correct_text():
    text = request.json.get("text", "")
    messages = [
        {"role": "system", "content": "Tu es un assistant qui corrige le texte avec suggestions grammaticales et orthographiques."},
        {"role": "user", "content": text}
    ]
    result = call_groq(messages,api_key)
    corrected = result["choices"][0]["message"]["content"]

    return jsonify({
        "corrected_text": corrected,
        "suggestions": []  # tu peux extraire des suggestions via parsing si besoin
    })


@app.route("/translate", methods=["POST"])
def translate():
    text = request.json.get("text", "")
    target_lang = request.json.get("lang", "en")
    
    messages = [
        {"role": "system", "content": f"Traduis le texte en {target_lang}."},
        {"role": "user", "content": text}
    ]
    
    result = call_groq(messages,api_key)
    translated = result["choices"][0]["message"]["content"]
    
    return jsonify({ "translated_text": translated })


# Pour la détection d'objets YOLOv8 via ONNX
# @app.route("/detect-objects", methods=["POST"])
# def detect_objects_api():
#     data = request.json
#     image_data = data.get("image")

#     image_bytes = base64.b64decode(image_data.split(",")[1])
#     image = Image.open(BytesIO(image_bytes)).convert("RGB")

#     # Transformations de l'image
#     img = np.array(image)
#     img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

#     # Detection des objets via le modèle YOLOv8
#     objects = detect_objects(img)

#     return jsonify({"objects": objects})

# Initialize DB
init_db()

# if __name__ == '__main__':
#     app.run(debug=True)
