from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

# Page d'inscription
@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    if request.method == 'POST':
        nom = request.form.get('nom')
        email = request.form.get('email')
        # Ici tu pourrais ajouter le traitement (BD, validation, etc.)
        return f"Merci {nom}, vous êtes inscrit avec l'email {email} !"
    return render_template('inscriptions.html')

if __name__ == '__main__':
    app.run(debug=True)
