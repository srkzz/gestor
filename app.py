import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # Pode manter ou remover, não será usado ativamente
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do ficheiro .env
load_dotenv()

app = Flask(__name__)

# Configuração da base de dados
# Prioriza a DATABASE_URL do Render (para PostgreSQL), senão usa SQLite local
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///instance/site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db) # Pode manter ou remover, não será usado ativamente nesta abordagem

# Definição do modelo de Utilizador
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Exemplo de Modelo de Tarefa (se já tiver um, pode manter o seu)
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.Integer)
    due_date = db.Column(db.Date)
    category = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tasks', lazy=True))

    def __repr__(self):
        return f'<Task {self.title}>'

# Rotas da aplicação
@app.route('/')
def home():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists. Please use a different one.')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.password = password
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.')
        return redirect(url_for('home'))
    return render_template('register.html')

with app.app_context():
    db.create_all()
# O bloco if __name__ == '__main__': é para quando o ficheiro é executado diretamente.
# Em produção (com Gunicorn), este bloco não é executado.
# A criação das tabelas será feita no Build Command do Render.
if __name__ == '__main__':
    # A linha db.create_all() foi removida ou comentada daqui para o deploy no Render
    app.run(debug=True)