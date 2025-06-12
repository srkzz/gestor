import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate # IMPORTANTE: Adicione esta linha

# 1. Carrega as variáveis de ambiente do ficheiro .env (apenas para desenvolvimento local)
load_dotenv()

# 2. Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração do Banco de Dados ---
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
database_path = os.path.join(instance_path, 'site.db')

if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# 3. Configuração do Flask:
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma_chave_secreta_padrao_muito_segura_para_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    f'sqlite:///{database_path}' # Fallback para SQLite em desenvolvimento local
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 4. Inicializa a extensão Flask-SQLAlchemy
db = SQLAlchemy(app)

# 5. Inicializa Flask-Migrate
migrate = Migrate(app, db) # IMPORTANTE: Adicione esta linha

# 6. Define os modelos de banco de dados (User e Task)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128)) # Campo para armazenar o hash da senha

    tasks = db.relationship('Task', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(10), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"<Task {self.title}>"

# 7. REMOVIDO: `with app.app_context(): db.create_all()`
# As migrações irão gerir o esquema da base de dados.

# --- Funções de Autenticação/Autorização ---
# ... (o resto das suas funções e rotas permanecem as mesmas) ...
def login_required(f):
    """Decorador para proteger rotas que exigem login."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para aceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS DA APLICAÇÃO ---

@app.route('/')
def home():
    """Página inicial que lista os utilizadores registados."""
    users = User.query.all()
    # Se o utilizador estiver logado, redireciona para o dashboard dele.
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Rota para registar um novo utilizador."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash('Username e senha não podem estar vazios.', 'error')
            return render_template('register_user.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f"O utilizador '{username}' já existe. Por favor, escolha outro.", 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password) # Cifra a senha
            db.session.add(new_user)
            db.session.commit()
            flash(f"Utilizador '{username}' registado com sucesso! Faça login para continuar.", 'success')
            return redirect(url_for('login')) # Redireciona para login após o registo
    return render_template('register_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota para login de utilizadores."""
    if 'user_id' in session: # Se já estiver logado, redireciona para o dashboard
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username # Armazena o username também para facilitar
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Username ou senha inválidos.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Rota para fazer logout."""
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você fez logout com sucesso.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required # Protege esta rota
def user_dashboard():
    """Página de dashboard do utilizador logado, listando as suas tarefas."""
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)

    # Busca as tarefas do utilizador logado, ordenadas por estado (pendente primeiro) e depois por data limite
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.is_completed, Task.due_date).all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)


@app.route('/add_task', methods=['GET', 'POST'])
@login_required # Protege esta rota
def add_task():
    """Adiciona uma nova tarefa para o utilizador logado."""
    user_id = session['user_id']
    user = User.query.get_or_404(user_id) # Garante que o utilizador existe

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form['priority']
        due_date_str = request.form['due_date']
        category = request.form['category'].strip()

        if not all([title, priority, due_date_str, category]):
            flash("Todos os campos obrigatórios (Título, Prioridade, Data Limite, Categoria) devem ser preenchidos.", 'error')
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
            user_id=user.id # Liga a tarefa ao utilizador logado
        )
        db.session.add(new_task)
        db.session.commit()
        flash(f"Tarefa '{title}' adicionada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('add_task.html', user=user)

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required # Protege esta rota
def edit_task(task_id):
    """Edita uma tarefa existente, verificando se pertence ao utilizador logado."""
    task = Task.query.get_or_404(task_id)

    # Autorização: Só o criador da tarefa pode editá-la
    if task.user_id != session['user_id']:
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

        db.session.commit()
        flash(f"Tarefa '{task.title}' atualizada com sucesso!", 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('edit_task.html', task=task)


@app.route('/task/<int:task_id>/mark_done')
@login_required # Protege esta rota
def mark_task_done(task_id):
    """Marca uma tarefa como concluída, verificando se pertence ao utilizador logado."""
    task = Task.query.get_or_404(task_id)

    # Autorização: Só o criador da tarefa pode marcá-la como concluída
    if task.user_id != session['user_id']:
        flash('Você não tem permissão para alterar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.is_completed = True
    db.session.commit()
    flash(f"Tarefa '{task.title}' marcada como concluída!", 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/task/<int:task_id>/mark_undone')
@login_required # Protege esta rota
def mark_task_undone(task_id):
    """Desmarca uma tarefa como concluída, verificando se pertence ao utilizador logado."""
    task = Task.query.get_or_404(task_id)

    # Autorização: Só o criador da tarefa pode alterá-la
    if task.user_id != session['user_id']:
        flash('Você não tem permissão para alterar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    task.is_completed = False
    db.session.commit()
    flash(f"Tarefa '{task.title}' marcada como pendente!", 'info')
    return redirect(url_for('user_dashboard'))


@app.route('/task/<int:task_id>/delete')
@login_required # Protege esta rota
def delete_task(task_id):
    """Apaga uma tarefa, verificando se pertence ao utilizador logado."""
    task = Task.query.get_or_404(task_id)

    # Autorização: Só o criador da tarefa pode apagá-la
    if task.user_id != session['user_id']:
        flash('Você não tem permissão para apagar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    db.session.delete(task)
    db.session.commit()
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard'))

# --- Ponto de Entrada da Aplicação ---
if __name__ == '__main__':
    app.run(debug=True)