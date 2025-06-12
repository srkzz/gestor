import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, date

# 1. Carrega as variáveis de ambiente do ficheiro .env (apenas para desenvolvimento local)
load_dotenv()

# 2. Inicializa a aplicação Flask
app = Flask(__name__)

# --- INÍCIO DA CORREÇÃO ---

# Define o caminho para a pasta da base de dados local (SQLite)
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
database_path = os.path.join(instance_path, 'site.db') # Caminho completo para o ficheiro da DB

# Garante que a pasta 'instance' existe. Isso deve ser feito ANTES de configurar a URI da DB.
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# 3. Configuração do Flask:
# - SECRET_KEY: Essencial para segurança (sessões, mensagens flash). Pega da variável de ambiente.
# - SQLALCHEMY_DATABASE_URI: String de conexão com o banco de dados.
#   Se a variável de ambiente 'DATABASE_URL' estiver definida (para PostgreSQL, por exemplo, no Render), use-a.
#   Caso contrário, use o caminho local para o SQLite.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma_chave_secreta_padrao_muito_segura_para_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{database_path}') # <-- CORREÇÃO AQUI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FIM DA CORREÇÃO ---

# 4. Inicializa a extensão Flask-SQLAlchemy
db = SQLAlchemy(app)

# 5. Define os modelos de banco de dados (User e Task)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True, cascade="all, delete-orphan")

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

# --- 6. ROTAS DA APLICAÇÃO (CRUD Básico) ---

@app.route('/')
def home():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        if not username:
            flash('Username não pode estar vazio.', 'error')
            return render_template('register_user.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f"O utilizador '{username}' já existe. Por favor, escolha outro.", 'error')
        else:
            new_user = User(username=username)
            db.session.add(new_user)
            db.session.commit()
            flash(f"Utilizador '{username}' registado com sucesso!", 'success')
            return redirect(url_for('home'))
    return render_template('register_user.html')


@app.route('/user/<username>')
def user_dashboard(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f"Utilizador '{username}' não encontrado.", 'error')
        return redirect(url_for('home'))

    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.is_completed, Task.due_date).all()
    return render_template('user_dashboard.html', user=user, tasks=tasks)


@app.route('/user/<username>/add_task', methods=['GET', 'POST'])
def add_task(username):
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
            user_id=user.id
        )
        db.session.add(new_task)
        db.session.commit()
        flash(f"Tarefa '{title}' adicionada com sucesso para {username}!", 'success')
        return redirect(url_for('user_dashboard', username=username))

    return render_template('add_task.html', user=user)


@app.route('/task/<int:task_id>/mark_done')
def mark_task_done(task_id):
    task = Task.query.get_or_404(task_id)
    task.is_completed = True
    db.session.commit()
    flash(f"Tarefa '{task.title}' marcada como concluída!", 'success')
    return redirect(url_for('user_dashboard', username=task.owner.username))

@app.route('/task/<int:task_id>/delete')
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    username = task.owner.username
    db.session.delete(task)
    db.session.commit()
    flash(f"Tarefa '{task.title}' apagada com sucesso!", 'success')
    return redirect(url_for('user_dashboard', username=username))

# Cria as tabelas da base de dados se não existirem
with app.app_context():
    db.create_all()

# --- 7. Ponto de Entrada da Aplicação ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Esta linha duplicada é redundante se já estiver fora do 'if __name__', mas não causa problemas
    app.run(debug=True)