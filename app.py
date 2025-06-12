# app.py (Versão Corrigida 'now' undefined E Prints de Debug para Login)

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from dotenv import load_dotenv
from datetime import datetime, date
from mongoengine.fields import ObjectId

# Carrega as variáveis de ambiente do ficheiro .env para desenvolvimento local
load_dotenv()

# Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração da Aplicação ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '000d88cd9d44446ebdd237eb6b0db000')
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGO_URI', 'mongodb://localhost:27017/gestor_tarefas_db')
}

# Constante para o número de itens por página
PER_PAGE = 10 # Define 10 tarefas por página

# Inicializa as extensões Flask
db = MongoEngine(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# --- Context Processor para Variáveis Globais na Template ---
@app.context_processor
def inject_global_variables():
    return {
        'now': datetime.utcnow()
    }

# --- Definição dos Modelos de Documentos (MongoDB) ---

class User(db.Document):
    username = db.StringField(required=True, unique=True, max_length=80)
    email = db.StringField(required=True, unique=True, max_length=120)
    password_hash = db.StringField(required=True, max_length=255)
    avatar_url = db.StringField(default='https://www.gravatar.com/avatar/?d=mp')

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
    is_public = db.BooleanField(default=False)
    tags = db.ListField(db.StringField())

    user = db.ReferenceField(User, required=True, reverse_delete_rule=2)

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', user={self.user.username})>"

class Comment(db.Document):
    content = db.StringField(required=True)
    date_created = db.DateTimeField(default=datetime.utcnow)
    user = db.ReferenceField(User, required=True, reverse_delete_rule=1)
    task = db.ReferenceField(Task, required=True, reverse_delete_rule=2)

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
    
    recent_public_tasks_query = Task.objects(is_public=True).order_by('-date_created')
    recent_public_tasks = recent_public_tasks_query.limit(5).all()

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
            # NOVO: Print para debug de registo
            print(f"DEBUG: Utilizador '{username}' registado com sucesso! Hash: {new_user.password_hash}")
            flash(f"Utilizador '{username}' registado com sucesso! Faça login para continuar.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            # NOVO: Print para debug de erro de registo
            print(f"DEBUG: Erro ao registar utilizador '{username}': {e}")
            flash(f'Ocorreu um erro ao registar: {e}', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        print(f"DEBUG: Já existe user_id na sessão: {session['user_id']}") # NOVO: Print
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password = request.form['password'].strip()

        print(f"DEBUG: Tentativa de login para identifier: '{identifier}', password (não hasheada): '{password}'") # NOVO: Print

        user = User.objects(username=identifier).first()
        if not user:
            user = User.objects(email=identifier).first()
        
        if user:
            print(f"DEBUG: Utilizador encontrado: {user.username}, Hash armazenado: {user.password_hash}") # NOVO: Print
            if user.check_password(password):
                session['user_id'] = str(user.id)
                session['username'] = user.username
                session['avatar_url'] = user.avatar_url
                print(f"DEBUG: Login bem-sucedido! user_id na sessão: {session['user_id']}") # NOVO: Print
                flash(f'Bem-vindo, {user.username}!', 'success')
                return redirect(url_for('user_dashboard'))
            else:
                print("DEBUG: Falha no login: Senha incorreta.") # NOVO: Print
                flash('Username/Email ou senha inválidos.', 'error')
                return render_template('login.html')
        else:
            print("DEBUG: Falha no login: Utilizador não encontrado.") # NOVO: Print
            flash('Username/Email ou senha inválidos.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    print(f"DEBUG: Logout do utilizador: {session.get('username')}") # NOVO: Print
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('avatar_url', None)
    flash('Você fez logout com sucesso.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    # NOVO: Print para verificar a sessão ao entrar no dashboard
    print(f"DEBUG: Acesso ao dashboard. user_id na sessão: {session.get('user_id')}")
    
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()
    
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    category_filter = request.args.get('category', 'all')
    tag_filter = request.args.get('tag', 'all')
    sort_by = request.args.get('sort_by', 'due_date')
    sort_order = request.args.get('sort_order', 'asc')
    search_query = request.args.get('search', '').strip()

    page = request.args.get('page', 1, type=int)
    
    tasks_query = Task.objects(user=user)

    if status_filter == 'completed':
        tasks_query = tasks_query(is_completed=True)
    elif status_filter == 'pending':
        tasks_query = tasks_query(is_completed=False)
    
    if priority_filter != 'all':
        tasks_query = tasks_query(priority=priority_filter)

    if category_filter != 'all':
        tasks_query = tasks_query(category=category_filter)
    
    if tag_filter != 'all':
        tasks_query = tasks_query(tags__in=[tag_filter]) 
    
    if search_query:
        tasks_query = tasks_query(__raw__={'$or': [
            {'title': {'$regex': search_query, '$options': 'i'}},
            {'description': {'$regex': search_query, '$options': 'i'}},
            {'category': {'$regex': search_query, '$options': 'i'}},
            {'tags': {'$regex': search_query, '$options': 'i'}}
        ]})

    total_tasks = tasks_query.count()
    total_pages = (total_tasks + PER_PAGE - 1) // PER_PAGE

    if sort_order == 'desc':
        sort_by_mongo = '-' + sort_by
    else:
        sort_by_mongo = sort_by
    
    tasks = tasks_query.order_by(sort_by_mongo).skip((page - 1) * PER_PAGE).limit(PER_PAGE).all()

    all_categories = sorted(list(set(task.category for task in Task.objects(user=user) if task.category)))
    all_tags = sorted(list(set(tag for task in Task.objects(user=user) for tag in task.tags)))

    total_tasks_count = Task.objects(user=user).count()
    pending_tasks_count = Task.objects(user=user, is_completed=False).count()
    completed_tasks_count = Task.objects(user=user, is_completed=True).count()
    public_tasks_count = Task.objects(user=user, is_public=True).count()


    return render_template('user_dashboard.html', user=user, tasks=tasks,
                           status_filter=status_filter,
                           priority_filter=priority_filter,
                           category_filter=category_filter,
                           tag_filter=tag_filter,
                           sort_by=sort_by,
                           sort_order=sort_order,
                           search_query=search_query,
                           all_categories=all_categories,
                           all_tags=all_tags,
                           page=page,
                           total_pages=total_pages,
                           per_page=PER_PAGE,
                           total_tasks_count=total_tasks_count,
                           pending_tasks_count=pending_tasks_count,
                           completed_tasks_count=completed_tasks_count,
                           public_tasks_count=public_tasks_count)


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
        is_public = 'is_public' in request.form
        tags_str = request.form['tags'].strip()

        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []

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
            is_public=is_public,
            tags=tags,
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
        task.is_public = 'is_public' in request.form 
        tags_str = request.form['tags'].strip()

        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []
        task.tags = tags

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

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_email = request.form['email'].strip()
        new_avatar_url = request.form['avatar_url'].strip()

        if new_username != user.username and User.objects(username=new_username).first():
            flash(f"O username '{new_username}' já está em uso.", 'error')
            return render_template('profile.html', user=user)
        
        if new_email != user.email and User.objects(email=new_email).first():
            flash(f"O email '{new_email}' já está em uso.", 'error')
            return render_template('profile.html', user=user)

        user.username = new_username
        user.email = new_email
        user.avatar_url = new_avatar_url
        user.save()

        session['username'] = user.username
        session['avatar_url'] = user.avatar_url
        
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        current_password = request.form['current_password'].strip()
        new_password = request.form['new_password'].strip()
        confirm_new_password = request.form['confirm_new_password'].strip()

        if not user.check_password(current_password):
            flash('A sua palavra-passe atual está incorreta.', 'error')
            return render_template('change_password.html')

        if new_password != confirm_new_password:
            flash('A nova palavra-passe e a confirmação não correspondem.', 'error')
            return render_template('change_password.html')

        if len(new_password) < 6:
            flash('A nova palavra-passe deve ter pelo menos 6 caracteres.', 'error')
            return render_template('change_password.html')
        
        user.password = new_password
        user.save()

        flash('Palavra-passe alterada com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')


@app.route('/public_tasks')
def public_tasks():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    
    public_tasks_query = Task.objects(is_public=True)
    
    if search_query:
        public_tasks_query = public_tasks_query(__raw__={'$or': [
            {'title': {'$regex': search_query, '$options': 'i'}},
            {'description': {'$regex': search_query, '$options': 'i'}},
            {'category': {'$regex': search_query, '$options': 'i'}},
            {'tags': {'$regex': search_query, '$options': 'i'}}
        ]})

    total_public_tasks = public_tasks_query.count()
    total_public_pages = (total_public_tasks + PER_PAGE - 1) // PER_PAGE

    public_tasks = public_tasks_query.order_by('-date_created').skip((page - 1) * PER_PAGE).limit(PER_PAGE).all()
    
    for task in public_tasks:
        task.comments = Comment.objects(task=task).order_by('date_created').all()

    current_user_obj = None
    if 'user_id' in session:
        current_user_obj = User.objects(id=ObjectId(session['user_id'])).first()

    return render_template('public_tasks.html', public_tasks=public_tasks, 
                           current_user=current_user_obj, search_query=search_query,
                           page=page,
                           total_pages=total_public_pages)

@app.route('/task/<string:task_id>/add_comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.objects(id=task_id).first_or_404()

    if not task.is_public:
        flash('Não é possível comentar em tarefas privadas.', 'error')
        return redirect(url_for('public_tasks'))

    comment_content = request.form['comment_content'].strip()
    if not comment_content:
        flash('O comentário não pode estar vazio.', 'error')
        return redirect(url_for('public_tasks'))

    user_id_obj = ObjectId(session['user_id'])
    current_user = User.objects(id=user_id_obj).first_or_404()

    new_comment = Comment(
        content=comment_content,
        user=current_user,
        task=task
    )
    new_comment.save()
    flash('Comentário adicionado com sucesso!', 'success')
    return redirect(url_for('public_tasks'))

if __name__ == '__main__':
    app.run(debug=True)
