import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, date

# 1. Carrega as variáveis de ambiente do ficheiro .env (apenas para desenvolvimento local)
# Em produção no Render, estas variáveis de ambiente serão definidas diretamente no serviço.
load_dotenv()

# 2. Inicializa a aplicação Flask
app = Flask(__name__)

# --- Configuração do Banco de Dados ---

# Define o caminho para a pasta da base de dados local (SQLite) - Usado APENAS se DATABASE_URL não estiver definida
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
database_path = os.path.join(instance_path, 'site.db') # Caminho completo para o ficheiro da DB local

# Garante que a pasta 'instance' existe para desenvolvimento local
# Esta pasta será usada apenas se o SQLite for o banco de dados ativo.
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# 3. Configuração do Flask:
# - SECRET_KEY: Essencial para segurança (sessões, mensagens flash). Pega da variável de ambiente.
# - SQLALCHEMY_DATABASE_URI: String de conexão com o banco de dados.
#   Esta é a chave! Prioriza a 'DATABASE_URL' (que o Render injeta do seu PostgreSQL).
#   Se 'DATABASE_URL' não estiver definida (ex: desenvolvimento local),
#   usa o caminho local para o SQLite.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma_chave_secreta_padrao_muito_segura_para_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    f'sqlite:///{database_path}' # Fallback para SQLite em desenvolvimento local
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 4. Inicializa a extensão Flask-SQLAlchemy
db = SQLAlchemy(app)

# 5. Define os modelos de banco de dados (User e Task)
class User(db.Model):
    __tablename__ = 'users' # Nome da tabela no BD
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # password_hash = db.Column(db.String(128)) # Para autenticação real, adicione um campo para hash de senha

    # Uma relação para que, ao aceder a user.tasks, obtenha a lista de tarefas desse utilizador
    tasks = db.relationship('Task', backref='owner', lazy=True, cascade="all, delete-orphan") # cascade para apagar tarefas se o user for apagado

    def __repr__(self):
        return f"<User {self.username}>"

class Task(db.Model):
    __tablename__ = 'tasks' # Nome da tabela no BD
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(10), nullable=False) # 'alta', 'média', 'baixa'
    due_date = db.Column(db.Date, nullable=False) # Armazena apenas a data (YYYY-MM-DD)
    category = db.Column(db.String(50), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow) # Data de criação automática em UTC

    # Chave estrangeira: relaciona a tarefa com o utilizador
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"<Task {self.title}>"

# --- 6. ROTAS DA APLICAÇÃO (CRUD Básico) ---

@app.route('/')
def home():
    """Página inicial que lista os utilizadores registados."""
    users = User.query.all() # Busca todos os utilizadores do BD
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Rota para registar um novo utilizador."""
    if request.method == 'POST':
        username = request.form['username'].strip() # remove espaços em branco
        if not username:
            flash('Username não pode estar vazio.', 'error')
            return render_template('register_user.html')

        # Verifica se o username já existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f"O utilizador '{username}' já existe. Por favor, escolha outro.", 'error')
        else:
            new_user = User(username=username)
            db.session.add(new_user)
            db.session.commit() # Salva o novo utilizador no BD
            flash(f"Utilizador '{username}' registado com sucesso!", 'success')
            return redirect(url_for('home'))
    return render_template('register_user.html')


@app.route('/user/<username>')
def user_dashboard(username):
    """Página de dashboard de um utilizador, listando as suas tarefas."""
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f"Utilizador '{username}' não encontrado.", 'error')
        return redirect(url_for('home'))

    # Busca as tarefas do utilizador, ordenadas por estado (pendente primeiro) e depois por data limite
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.is_completed, Task.due_date).all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)


@app.route('/user/<username>/add_task', methods=['GET', 'POST'])
def add_task(username):
    """Adiciona uma nova tarefa para um utilizador."""
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f"Utilizador '{username}' não encontrado.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form['priority']
        due_date_str = request.form['due_date']
        category = request.form['category'].strip()

        # Validação básica dos campos
        if not all([title, priority, due_date_str, category]):
            flash("Todos os campos obrigatórios (Título, Prioridade, Data Limite, Categoria) devem ser preenchidos.", 'error')
            return render_template('add_task.html', user=user)

        try:
            # Converte a string de data (YYYY-MM-DD) para um objeto date do Python
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Formato de data inválido. Use AAAA-MM-DD.", 'error')
            return render_template('add_task.html', user=user)

        # Cria uma nova instância da tarefa e adiciona ao banco de dados
        new_task = Task(
            title=title,
            description=description,
            priority=priority,
            due_date=due_date,
            category=category,
            user_id=user.id # Liga a tarefa ao utilizador atual
        )
        db.session.add(new_task)
        db.session.commit() # Salva a nova tarefa
        flash(f"Tarefa '{title}' adicionada com sucesso para {username}!", 'success')
        return redirect(url_for('user_dashboard', username=username))

    return render_template('add_task.html', user=user)


@app.route('/task/<int:task_id>/mark_done')
def mark_task_done(task_id):
    """Marca uma tarefa como concluída."""
    task = Task.query.get_or_404(task_id) # Busca a tarefa pelo ID, ou retorna 404 se não encontrar
    task.is_completed = True # Atualiza o status
    db.session.commit() # Salva a alteração
    flash(f"Tarefa '{task.title}' marcada como concluída!", 'success')
    # Redireciona de volta para o dashboard do utilizador dono da tarefa
    return redirect(url_for('user_dashboard', username=task.owner.username))

@app.route('/task/<int:task_id>/delete')
def delete_task(task_id):
    """Apaga uma tarefa."""
    task = Task.query.get_or_404(task_id)
    username = task.owner.username # Guarda o username antes de apagar a tarefa
    db.session.delete(task) # Marca a tarefa para ser apagada
    db.session.commit() # Executa a remoção
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard', username=username))

# Cria as tabelas no banco de dados, se elas ainda não existirem.
# Esta parte será executada durante o deploy no Render via Build Command,
# e também ao rodar o ficheiro diretamente em desenvolvimento.
with app.app_context():
    db.create_all()

# --- 7. Ponto de Entrada da Aplicação ---
if __name__ == '__main__':
    # Esta parte só é executada quando você roda 'python app.py' diretamente.
    # Em produção (no Render), o Gunicorn é que vai iniciar a aplicação,
    # e o 'db.create_all()' é acionado via Build Command.
    # A linha abaixo é redundante se já estiver fora do 'if __name__', mas não causa problemas.
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True é para desenvolvimento (recarrega ao salvar, mostra erros)