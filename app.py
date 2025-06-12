# app.py (Para usar com MongoDB e Flask-MongoEngine)

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine # Importação para MongoDB
from dotenv import load_dotenv
from datetime import datetime, date

# Carrega as variáveis de ambiente do ficheiro .env para desenvolvimento local
load_dotenv()

# Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração da Aplicação ---

# SECRET_KEY para segurança de sessões e CSRF.
# Em produção (Render), esta deve ser uma variável de ambiente no Dashboard.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua_chave_secreta_muito_segura_aqui_e_aleatoria')

# Configuração da URL de conexão do MongoDB
# No Render, 'MONGO_URI' será a sua Connection String do MongoDB Atlas.
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGO_URI', 'mongodb://localhost:27017/gestor_tarefas_db')
}

# Inicializa as extensões Flask
db = MongoEngine(app)      # Inicializa o Flask-MongoEngine
bcrypt = Bcrypt(app)       # Para hashing de senhas
csrf = CSRFProtect(app)    # Para proteção contra CSRF

# --- Definição dos Modelos de Documentos (MongoDB) ---
# Os modelos agora herdam de db.Document do Flask-MongoEngine

class User(db.Document):
    # Não há __tablename__ em MongoDB, pois é schemaless
    username = db.StringField(required=True, unique=True, max_length=80)
    email = db.StringField(required=True, unique=True, max_length=120)
    password_hash = db.StringField(required=True, max_length=255) # Armazena o hash da senha

    # Propriedade para definir a senha (hashing automático)
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Método para verificar a senha
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Relacionamento com Tarefas: Referência (não embutida) para as tarefas do utilizador.
    # Em MongoDB, relacionamentos são muitas vezes feitos por referência a IDs.
    # A lista de tarefas será obtida consultando o campo user_id na coleção Task.
    # Não usamos 'db.relationship' como no SQLAlchemy aqui.

    def __repr__(self):
        return f'<User {self.username}>'

class Task(db.Document):
    # Não há __tablename__
    title = db.StringField(required=True, max_length=100)
    description = db.StringField(required=False) # StringField é equivalente a Text
    priority = db.StringField(required=True, default='media', choices=['baixa', 'media', 'alta'])
    due_date = db.DateField(required=True)
    category = db.StringField(required=True, max_length=50)
    is_completed = db.BooleanField(default=False)
    date_created = db.DateTimeField(default=datetime.utcnow)

    # Foreign Key substituída por ReferenceField para o modelo User
    # 'dbref=True' para armazenar como DBRef, '_id' para o ID interno do Mongo
    user = db.ReferenceField(User, required=True, reverse_delete_rule=2) # 2 = CASCADE

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', user={self.user.username})>"

# --- Funções de Autenticação/Autorização (Decoradores) ---
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para aceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rotas da Aplicação ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if not username or not email or not password:
            flash('Username, email e senha não podem estar vazios.', 'error')
            return render_template('register.html')

        # Verifica se o username ou email já existem
        # Usamos .first() para obter o primeiro documento correspondente
        existing_user_by_username = User.objects(username=username).first()
        existing_user_by_email = User.objects(email=email).first()

        if existing_user_by_username or existing_user_by_email:
            flash(f"O utilizador '{username}' ou email '{email}' já existe. Por favor, escolha outro.", 'error')
            return render_template('register.html')

        new_user = User(username=username, email=email)
        new_user.password = password # Setter faz o hashing
        
        try:
            new_user.save() # Salva o novo documento (utilizador) no MongoDB
            flash(f"Utilizador '{username}' registado com sucesso! Faça login para continuar.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Ocorreu um erro ao registar: {e}', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password = request.form['password'].strip()

        # Busca o utilizador por username ou email
        user = User.objects(username=identifier).first()
        if not user:
            user = User.objects(email=identifier).first()

        if user and user.check_password(password):
            session['user_id'] = str(user.id) # IDs do MongoDB são ObjectId, converter para string
            session['username'] = user.username
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Username/Email ou senha inválidos.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você fez logout com sucesso.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    # Converta o user_id da sessão para o tipo correto de ID do MongoEngine
    from mongoengine.fields import ObjectId
    user_id_obj = ObjectId(session['user_id'])
    
    user = User.objects(id=user_id_obj).first_or_404() # Busca o utilizador pelo ID

    # Busca as tarefas associadas a este utilizador pelo campo 'user' (ReferenceField)
    tasks = Task.objects(user=user).order_by('is_completed', 'due_date').all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)

@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    from mongoengine.fields import ObjectId
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form['priority']
        due_date_str = request.form['due_date']
        category = request.form['category'].strip()

        if not all([title, priority, due_date_str, category]):
            flash("Todos os campos obrigatórios devem ser preenchidos.", 'error')
            return render_template('add_task.html', user=user)

        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Formato de data inválido. Use AAAA-MM-DD.", 'error')
            return render_template('add_task.html', user=user)

        new_task = Task(
            title=title,
            description=description,
            priority=priority,
            due_date=due_date,
            category=category,
            user=user # Associa o objeto User ao campo ReferenceField 'user'
        )
        new_task.save() # Salva a nova tarefa
        flash(f"Tarefa '{title}' adicionada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('add_task.html', user=user)

@app.route('/task/<string:task_id>/edit', methods=['GET', 'POST']) # ID é string em MongoDB
@login_required
def edit_task(task_id):
    task = Task.objects(id=task_id).first_or_404() # Busca a tarefa pelo ID

    # Autorização: Apenas o proprietário da tarefa pode editá-la
    # O ID do user no MongoEngine é um ObjectId, e o da sessão é string.
    # Converter ambos para string para comparação simples.
    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para editar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        task.title = request.form['title'].strip()
        task.description = request.form['description'].strip()
        task.priority = request.form['priority']
        task.category = request.form['category'].strip()
        due_date_str = request.form['due_date']

        if not all([task.title, task.priority, due_date_str, task.category]):
            flash("Todos os campos obrigatórios devem ser preenchidos.", 'error')
            return render_template('edit_task.html', task=task)

        try:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Formato de data inválido. Use AAAA-MM-DD.", 'error')
            return render_template('edit_task.html', task=task)

        task.save() # Salva as alterações na tarefa
        flash(f"Tarefa '{task.title}' atualizada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('edit_task.html', task=task)

@app.route('/task/<string:task_id>/mark_done') # ID é string em MongoDB
@login_required
def mark_task_done(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para alterar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.is_completed = True
    task.save() # Salva a alteração
    flash(f"Tarefa '{task.title}' marcada como concluída!", 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/task/<string:task_id>/mark_undone') # ID é string em MongoDB
@login_required
def mark_task_undone(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para alterar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.is_completed = False
    task.save()
    flash(f"Tarefa '{task.title}' marcada como pendente!", 'info')
    return redirect(url_for('user_dashboard'))

@app.route('/task/<string:task_id>/delete') # ID é string em MongoDB
@login_required
def delete_task(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para apagar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.delete() # Apaga o documento
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard'))

# Ponto de entrada da aplicação
if __name__ == '__main__':
    # Nota: Não há db.create_all() para MongoDB. O schemaless significa
    # que as coleções são criadas dinamicamente quando os primeiros documentos são inseridos.
    app.run(debug=True)
