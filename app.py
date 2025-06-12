# app.py (Versão para MongoDB com Novas Funcionalidades)

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from dotenv import load_dotenv
from datetime import datetime, date
from mongoengine.fields import ObjectId # Importa ObjectId para usar na conversão de IDs

# Carrega as variáveis de ambiente do ficheiro .env para desenvolvimento local
load_dotenv()

# Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração da Aplicação ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua_chave_secreta_muito_segura_aqui_e_aleatoria')
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGO_URI', 'mongodb://localhost:27017/gestor_tarefas_db')
}

# Inicializa as extensões Flask
db = MongoEngine(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# --- Definição dos Modelos de Documentos (MongoDB) ---

class User(db.Document):
    username = db.StringField(required=True, unique=True, max_length=80)
    email = db.StringField(required=True, unique=True, max_length=120)
    password_hash = db.StringField(required=True, max_length=255)
    # NOVO: Campo para o URL do avatar
    avatar_url = db.StringField(default='https://www.gravatar.com/avatar/?d=mp') # Default: imagem de pessoa genérica

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Task(db.Document):
    title = db.StringField(required=True, max_length=100)
    description = db.StringField(required=False)
    priority = db.StringField(required=True, default='media', choices=['baixa', 'media', 'alta'])
    due_date = db.DateField(required=True)
    category = db.StringField(required=True, max_length=50)
    is_completed = db.BooleanField(default=False)
    date_created = db.DateTimeField(default=datetime.utcnow)
    # NOVO: Campo para definir se a tarefa é pública
    is_public = db.BooleanField(default=False) 

    user = db.ReferenceField(User, required=True, reverse_delete_rule=2) # 2 = CASCADE

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', user={self.user.username})>"

# NOVO MODELO: Para comentários em tarefas públicas
class Comment(db.Document):
    content = db.StringField(required=True)
    date_created = db.DateTimeField(default=datetime.utcnow)
    user = db.ReferenceField(User, required=True, reverse_delete_rule=1) # 1 = DENY (não apagar user se tiver comments)
    task = db.ReferenceField(Task, required=True, reverse_delete_rule=2) # 2 = CASCADE (apagar comments se apagar task)

    def __repr__(self):
        return f"<Comment(id={self.id}, user={self.user.username}, task={self.task.title})>"


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
    # NOVO: Para mostrar uma lista de tarefas públicas recentes na home page
    # Limita a 5 tarefas mais recentes, que são públicas
    recent_public_tasks = Task.objects(is_public=True).order_by('-date_created').limit(5)
    return render_template('index.html', recent_public_tasks=recent_public_tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if not username or not email or not password:
            flash('Username, email e senha não podem estar vazios.', 'error')
            return render_template('register.html')

        existing_user_by_username = User.objects(username=username).first()
        existing_user_by_email = User.objects(email=email).first()

        if existing_user_by_username or existing_user_by_email:
            flash(f"O utilizador '{username}' ou email '{email}' já existe. Por favor, escolha outro.", 'error')
            return render_template('register.html')

        new_user = User(username=username, email=email)
        new_user.password = password
        
        try:
            new_user.save()
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

        user = User.objects(username=identifier).first()
        if not user:
            user = User.objects(email=identifier).first()

        if user and user.check_password(password):
            session['user_id'] = str(user.id)
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
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()
    
    tasks = Task.objects(user=user).order_by('is_completed', 'due_date').all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)

@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form['priority']
        due_date_str = request.form['due_date']
        category = request.form['category'].strip()
        # NOVO: Obtém o valor do checkbox 'is_public'
        is_public = 'is_public' in request.form # Checkbox envia 'on' se marcado, senão não envia nada

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
            is_public=is_public, # Guarda o estado público/privado
            user=user
        )
        new_task.save()
        flash(f"Tarefa '{title}' adicionada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('add_task.html', user=user)

@app.route('/task/<string:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para editar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        task.title = request.form['title'].strip()
        task.description = request.form['description'].strip()
        task.priority = request.form['priority']
        task.category = request.form['category'].strip()
        due_date_str = request.form['due_date']
        # NOVO: Obtém o valor do checkbox 'is_public' para edição
        task.is_public = 'is_public' in request.form 

        if not all([task.title, task.priority, due_date_str, task.category]):
            flash("Todos os campos obrigatórios devem ser preenchidos.", 'error')
            return render_template('edit_task.html', task=task)

        try:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Formato de data inválido. Use AAAA-MM-DD.", 'error')
            return render_template('edit_task.html', task=task)

        task.save()
        flash(f"Tarefa '{task.title}' atualizada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('edit_task.html', task=task)

@app.route('/task/<string:task_id>/mark_done')
@login_required
def mark_task_done(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para alterar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.is_completed = True
    task.save()
    flash(f"Tarefa '{task.title}' marcada como concluída!", 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/task/<string:task_id>/mark_undone')
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

@app.route('/task/<string:task_id>/delete')
@login_required
def delete_task(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para apagar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.delete()
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard'))

# NOVO: Rota para a página de perfil (avatar)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        new_avatar_url = request.form['avatar_url'].strip()
        user.avatar_url = new_avatar_url
        user.save()
        flash('URL do avatar atualizado com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# NOVO: Rota para a página de tarefas públicas (o "fórum")
# NOVO: Rota para a página de tarefas públicas (o "fórum")
@app.route('/public_tasks')
def public_tasks():
    # Busca todas as tarefas que são marcadas como públicas
    public_tasks = Task.objects(is_public=True).order_by('-date_created').all()
    
    # NOVO: Anexa os comentários a cada tarefa
    for task in public_tasks:
        task.comments = Comment.objects(task=task).order_by('date_created').all()

    current_user_obj = None
    if 'user_id' in session:
        current_user_obj = User.objects(id=ObjectId(session['user_id'])).first()

    return render_template('public_tasks.html', public_tasks=public_tasks, current_user=current_user_obj)

# NOVO: Rota para adicionar um comentário a uma tarefa pública
@app.route('/task/<string:task_id>/add_comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.objects(id=task_id).first_or_404()

    # Verifica se a tarefa é pública antes de permitir comentários
    if not task.is_public:
        flash('Não é possível comentar em tarefas privadas.', 'error')
        return redirect(url_for('public_tasks'))

    comment_content = request.form['comment_content'].strip()
    if not comment_content:
        flash('O comentário não pode estar vazio.', 'error')
        return redirect(url_for('public_tasks')) # Ou redireciona para a própria tarefa se tivermos página para ela

    user_id_obj = ObjectId(session['user_id'])
    current_user = User.objects(id=user_id_obj).first_or_404()

    new_comment = Comment(
        content=comment_content,
        user=current_user,
        task=task
    )
    new_comment.save()
    flash('Comentário adicionado com sucesso!', 'success')
    return redirect(url_for('public_tasks')) # Redireciona de volta para a lista de tarefas públicas


# Ponto de entrada da aplicação
if __name__ == '__main__':
    app.run(debug=True)
