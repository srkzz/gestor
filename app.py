import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv # Importa para carregar .env localmente
from datetime import datetime, date

# 1. Carrega as variáveis de ambiente do ficheiro .env
# Isto é crucial para o desenvolvimento local. No Render, as variáveis são definidas no Dashboard.
load_dotenv()

# 2. Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração do Banco de Dados ---
# Para SQLite local em desenvolvimento
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
database_path = os.path.join(instance_path, 'site.db')

# Garante que a pasta 'instance' existe para SQLite local
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# 3. Configuração do Flask:
# SECRET_KEY é essencial para sessões e mensagens flash seguras.
# No Render, defina esta variável de ambiente no Dashboard.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua_chave_secreta_muito_segura_aqui')

# Configuração da URL da base de dados.
# No Render, 'DATABASE_URL' será a URL da sua base de dados PostgreSQL.
# Localmente, usa SQLite como fallback se DATABASE_URL não estiver definida.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    f'sqlite:///{database_path}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recomendado para evitar avisos

# 4. Inicializa a extensão Flask-SQLAlchemy
db = SQLAlchemy(app)

# 5. Define os modelos de banco de dados (User e Task) - AGORA DENTRO DE app.py
class User(db.Model):
    __tablename__ = 'users' # Nome da tabela no banco de dados, importante para ForeignKey
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Armazena o hash da senha

    # Propriedade para definir a senha, que automaticamente faz o hash
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        # Utiliza generate_password_hash do Werkzeug para criar o hash da senha
        self.password_hash = generate_password_hash(password)

    # Método para verificar a senha fornecida com o hash armazenado
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Relacionamento com Tarefas: um utilizador pode ter muitas tarefas
    # 'cascade="all, delete-orphan"' significa que se o utilizador for apagado, as suas tarefas também o serão.
    tasks = db.relationship('Task', backref='owner', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'

class Task(db.Model):
    __tablename__ = 'tasks' # Nome da tabela no banco de dados
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(10), nullable=False) # 'alta', 'média', 'baixa'
    due_date = db.Column(db.Date, nullable=False) # Armazena apenas a data (YYYY-MM-DD)
    category = db.Column(db.String(50), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow) # Data e hora de criação da tarefa

    # Foreign Key para a tabela 'users', ligando a tarefa ao seu criador
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', user_id={self.user_id})>"


# --- Funções de Autenticação/Autorização ---
def login_required(f):
    """
    Decorador para proteger rotas que exigem que o utilizador esteja logado.
    Redireciona para a página de login se o utilizador não estiver autenticado.
    """
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
    """Página inicial da aplicação."""
    # Se o utilizador já estiver logado, redireciona para o dashboard dele.
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    # Caso contrário, exibe a página inicial padrão.
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Rota para registar um novo utilizador."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        # Validação básica de entrada
        if not username or not email or not password:
            flash('Username, email e senha não podem estar vazios.', 'error')
            return render_template('register.html')

        # Verifica se o username ou email já existem na base de dados
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash(f"O utilizador '{username}' ou email '{email}' já existe. Por favor, escolha outro.", 'error')
            return render_template('register.html')

        # Cria um novo utilizador. A senha é automaticamente hashed pelo setter no modelo User.
        new_user = User(username=username, email=email)
        new_user.password = password # Isso chama o setter 'password' que faz o hashing
        db.session.add(new_user)
        db.session.commit() # Salva o novo utilizador na base de dados

        flash(f"Utilizador '{username}' registado com sucesso! Faça login para continuar.", 'success')
        return redirect(url_for('login')) # Redireciona para a página de login

    # Se for um GET request, apenas renderiza o formulário de registo
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota para login de utilizadores."""
    # Se o utilizador já estiver logado, redireciona para o dashboard para evitar login duplicado
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        identifier = request.form['identifier'].strip() # Pode ser username ou email
        password = request.form['password'].strip()

        # Tenta encontrar o utilizador primeiro por username, depois por email
        user = User.query.filter_by(username=identifier).first()
        if not user:
            user = User.query.filter_by(email=identifier).first()

        # Se o utilizador for encontrado e a senha estiver correta
        if user and user.check_password(password): # Usa o método check_password do modelo User
            session['user_id'] = user.id # Armazena o ID do utilizador na sessão
            session['username'] = user.username # Armazena o username para exibição ou uso futuro
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Username/Email ou senha inválidos.', 'error')
            # Permanece na página de login para que o utilizador possa tentar novamente
            return render_template('login.html') # Renderiza o template para mostrar a mensagem de erro
    
    # Se for um GET request, apenas renderiza o formulário de login
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Rota para fazer logout."""
    # Remove as informações do utilizador da sessão
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você fez logout com sucesso.', 'info')
    return redirect(url_for('home')) # Redireciona para a página inicial


@app.route('/dashboard')
@login_required # Esta rota requer que o utilizador esteja logado
def user_dashboard():
    """Página de dashboard do utilizador logado, listando as suas tarefas."""
    user_id = session['user_id']
    user = User.query.get_or_404(user_id) # Busca o utilizador pelo ID da sessão

    # Busca todas as tarefas associadas a este utilizador.
    # Ordena: tarefas não concluídas primeiro, depois por data limite.
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.is_completed, Task.due_date).all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)


@app.route('/add_task', methods=['GET', 'POST'])
@login_required # Protege esta rota
def add_task():
    """Rota para adicionar uma nova tarefa para o utilizador logado."""
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form['priority']
        due_date_str = request.form['due_date']
        category = request.form['category'].strip()

        # Validação básica
        if not all([title, priority, due_date_str, category]):
            flash("Todos os campos obrigatórios (Título, Prioridade, Data Limite, Categoria) devem ser preenchidos.", 'error')
            return render_template('add_task.html', user=user)

        try:
            # Converte a string da data para um objeto date
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
            user_id=user.id # Associa a tarefa ao utilizador atualmente logado
        )
        db.session.add(new_task)
        db.session.commit()
        flash(f"Tarefa '{title}' adicionada com sucesso!", 'success')
        return redirect(url_for('user_dashboard')) # Redireciona para o dashboard após adicionar

    return render_template('add_task.html', user=user)

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required # Protege esta rota
def edit_task(task_id):
    """
    Rota para editar uma tarefa existente.
    Verifica se a tarefa pertence ao utilizador logado antes de permitir a edição.
    """
    task = Task.query.get_or_404(task_id)

    # Autorização: Apenas o proprietário da tarefa pode editá-la
    if task.user_id != session['user_id']:
        flash('Você não tem permissão para editar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        task.title = request.form['title'].strip()
        task.description = request.form['description'].strip()
        task.priority = request.form['priority']
        task.category = request.form['category'].strip()
        due_date_str = request.form['due_date']

        # Validação básica
        if not all([task.title, task.priority, due_date_str, task.category]):
            flash("Todos os campos obrigatórios devem ser preenchidos.", 'error')
            return render_template('edit_task.html', task=task) # Renderiza o form novamente com a tarefa atual

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
    """
    Marca uma tarefa como concluída.
    Verifica se a tarefa pertence ao utilizador logado.
    """
    task = Task.query.get_or_404(task_id)

    # Autorização: Apenas o proprietário da tarefa pode alterá-la
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
    """
    Desmarca uma tarefa como concluída (marca como pendente).
    Verifica se a tarefa pertence ao utilizador logado.
    """
    task = Task.query.get_or_404(task_id)

    # Autorização: Apenas o proprietário da tarefa pode alterá-la
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
    """
    Apaga uma tarefa.
    Verifica se a tarefa pertence ao utilizador logado.
    """
    task = Task.query.get_or_404(task_id)

    # Autorização: Apenas o proprietário da tarefa pode apagá-la
    if task.user_id != session['user_id']:
        flash('Você não tem permissão para apagar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    db.session.delete(task)
    db.session.commit()
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard'))


# --- Ponto de Entrada da Aplicação ---
# Isso garante que a aplicação só é executada quando o script é diretamente invocado
if __name__ == '__main__':
    # Em produção (no Render), o 'Build Command' cuidará do db.create_all()
    # Em desenvolvimento local, você pode executar db.create_all() manualmente ou via shell.
    # Exemplo: with app.app_context(): db.create_all()
    app.run(debug=True) # debug=True é para desenvolvimento, desative em produção