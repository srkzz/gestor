# app.py (Versão com Aprovação de Admin, Criação em Lote, Assinaturas e Exportação PDF)
import os
import math
import base64
import tempfile
import re
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    Response
)
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from dotenv import load_dotenv
from mongoengine.fields import ObjectId
from mongoengine import EmbeddedDocument
from fpdf import FPDF


# Carrega o .env apenas quando estiver disponível
load_dotenv()


# Inicializa as extensões sem associá-las imediatamente à aplicação
# Extensões
db = MongoEngine()
bcrypt = Bcrypt()
csrf = CSRFProtect()


def create_app():
    flask_app = Flask(__name__)

    mongo_uri = os.getenv("MONGO_URI")
    secret_key = os.getenv("SECRET_KEY")

    if not mongo_uri:
        raise RuntimeError(
            "A variável MONGO_URI não está configurada."
        )

    if not mongo_uri.startswith(
        ("mongodb://", "mongodb+srv://")
    ):
        raise RuntimeError(
            "MONGO_URI inválida. Deve começar por "
            "mongodb:// ou mongodb+srv://"
        )

    if not secret_key:
        raise RuntimeError(
            "A variável SECRET_KEY não está configurada."
        )

    flask_app.config["SECRET_KEY"] = secret_key
    flask_app.config["MONGODB_SETTINGS"] = {
        "host": mongo_uri,
        "serverSelectionTimeoutMS": 5000,
        "connectTimeoutMS": 5000
    }

    db.init_app(flask_app)
    bcrypt.init_app(flask_app)
    csrf.init_app(flask_app)

    return flask_app


app = create_app()

PER_PAGE = 10

@app.context_processor
def inject_global_variables():
    current_user_is_admin = False

    if session.get("user_id"):
        try:
            current_user = User.objects(
                id=ObjectId(session["user_id"])
            ).first()

            if current_user:
                current_user_is_admin = bool(
                    current_user.is_admin
                )

                session["is_admin"] = current_user_is_admin
        except Exception:
            current_user_is_admin = False

    return {
        "now": datetime.utcnow(),
        "current_user_is_admin": current_user_is_admin
    }


# --- Modelos ---

class User(db.Document):
    username = db.StringField(required=True, unique=True, max_length=80)
    email = db.StringField(required=True, unique=True, max_length=120)
    password_hash = db.StringField(required=True, max_length=255)
    avatar_url = db.StringField(default='https://www.gravatar.com/avatar/?d=mp')
    is_admin = db.BooleanField(default=False)

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

class RequisitionItem(db.EmbeddedDocument):
    part_code = db.StringField(
        required=True,
        max_length=100
    )

    part_description = db.StringField(
        required=True,
        max_length=250
    )

    quantity = db.IntField(
        required=True,
        min_value=1,
        default=1
    )

    unit = db.StringField(
        required=True,
        max_length=20,
        default="UN"
    )

class RequisitionItem(db.EmbeddedDocument):
    part_code = db.StringField(
        required=True,
        max_length=100
    )

    part_description = db.StringField(
        required=True,
        max_length=250
    )

    quantity = db.IntField(
        required=True,
        min_value=1,
        default=1
    )

    unit = db.StringField(
        required=True,
        max_length=20,
        default="UN"
    )

class Requisition(db.Document):
    machine_reference = db.StringField(
        required=True,
        max_length=100
    )

    brand = db.StringField(
        required=True,
        max_length=100
    )

    model = db.StringField(
        required=True,
        max_length=100
    )

    serial_number = db.StringField(
        required=False,
        max_length=150
    )

    items = db.EmbeddedDocumentListField(
        RequisitionItem,
        required=True
    )

    priority = db.StringField(
        required=True,
        default="media",
        choices=["baixa", "media", "alta"]
    )

    due_date = db.DateField(required=True)

    description = db.StringField(required=False)

    user = db.ReferenceField(
        User,
        required=True,
        reverse_delete_rule=2
    )

    date_created = db.DateTimeField(
        default=datetime.utcnow
    )

    status = db.StringField(
        required=True,
        default="rascunho",
        choices=[
            "rascunho",
            "submetida",
            "aprovada",
            "rejeitada"
        ]
    )

    requester_signature = db.StringField()
    requester_signed_at = db.DateTimeField()

    approved_by = db.ReferenceField(User)
    approver_signature = db.StringField()
    approved_at = db.DateTimeField()

    rejection_reason = db.StringField()

    meta = {
        "indexes": [
            "status",
            "user",
            "brand",
            "model",
            "machine_reference",
            "-date_created"
        ]
    }

    @property
    def requisition_number(self):
        created = self.date_created or datetime.utcnow()

        return (
            f"REQ-{created.strftime('%Y%m%d')}-"
            f"{str(self.id)[-6:].upper()}"
        )

    @property
    def can_be_edited(self):
        return self.status in ["rascunho", "rejeitada"]

    def __repr__(self):
        return (
            f"<Requisition "
            f"id={self.id}, "
            f"machine={self.machine_reference}, "
            f"status={self.status}>"
        )


class Suggestion(db.Document):
    field_name = db.StringField(
        required=True,
        choices=[
            "machine_reference",
            "brand",
            "model",
            "part_code",
            "part_description",
            "unit"
        ]
    )

    value = db.StringField(
        required=True,
        max_length=250
    )

    normalized_value = db.StringField(
        required=True,
        max_length=250
    )

    created_by = db.ReferenceField(
        User,
        required=False
    )

    date_created = db.DateTimeField(
        default=datetime.utcnow
    )

    meta = {
        "indexes": [
            {
                "fields": [
                    "field_name",
                    "normalized_value"
                ],
                "unique": True
            }
        ]
    }

    @staticmethod
    def normalize(value):
        value = value.strip()
        value = re.sub(r"\s+", " ", value)
        return value.casefold()

    @classmethod
    def save_suggestion(cls, field_name, value, user=None):
        value = value.strip()

        if not value:
            return None

        normalized = cls.normalize(value)

        existing = cls.objects(
            field_name=field_name,
            normalized_value=normalized
        ).first()

        if existing:
            return existing

        try:
            return cls(
                field_name=field_name,
                value=value,
                normalized_value=normalized,
                created_by=user
            ).save()
        except Exception:
            return cls.objects(
                field_name=field_name,
                normalized_value=normalized
            ).first()

class Task(db.Document):
    title = db.StringField(required=True, max_length=100)
    description = db.StringField(required=False)
    priority = db.StringField(required=True, default='media', choices=['baixa', 'media', 'alta'])
    due_date = db.DateField(required=True)
    category = db.StringField(required=True, max_length=50)
    is_completed = db.BooleanField(default=False)
    date_created = db.DateTimeField(default=datetime.utcnow)
    tags = db.ListField(db.StringField())
    user = db.ReferenceField(User, required=True, reverse_delete_rule=2)

    # --- Fluxo de aprovação ---
    status = db.StringField(required=True, default='pendente',
                             choices=['pendente', 'aprovada', 'rejeitada'])
    approved_by = db.ReferenceField(User, required=False)
    approved_at = db.DateTimeField(required=False)

    @property
    def is_public(self):
        # Mantido só para compatibilidade com templates antigos que leem task.is_public
        return self.status == 'aprovada'

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', status={self.status})>"


class Comment(db.Document):
    content = db.StringField(required=True)
    date_created = db.DateTimeField(default=datetime.utcnow)
    user = db.ReferenceField(User, required=True, reverse_delete_rule=1)
    task = db.ReferenceField(Task, required=True, reverse_delete_rule=2)

    def __repr__(self):
        return f"<Comment(id={self.id}, user={self.user.username}, task={self.task.title})>"


# --- Decoradores ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para aceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para aceder a esta área de administração.', 'warning')
            return redirect(url_for('login'))
        user = User.objects(id=ObjectId(session['user_id'])).first()
        if not user or not user.is_admin:
            flash('Você não tem permissão para aceder a esta área.', 'error')
            return redirect(url_for('user_dashboard') if 'user_id' in session else url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# --- Rotas principais ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    recent_public_tasks = Task.objects(status='aprovada').order_by('-date_created').limit(5).all()
    return render_template('index.html', recent_public_tasks=recent_public_tasks)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            flash('Username, email e senha não podem estar vazios.', 'error')
            return render_template('register.html')

        if User.objects(username=username).first() or User.objects(email=email).first():
            flash(f"O utilizador '{username}' ou email '{email}' já existe. Por favor, escolha outro.", 'error')
            return render_template('register.html')

        new_user = User(username=username, email=email)
        new_user.password = password
        new_user.is_admin = False
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
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()

        user = User.objects(username=identifier).first() or User.objects(email=identifier).first()

        if user and user.check_password(password):
            session['user_id'] = str(user.id)
            session['username'] = user.username
            session['avatar_url'] = user.avatar_url
            session['is_admin'] = user.is_admin
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Credenciais inválidas.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('avatar_url', None)
    session.pop('is_admin', None)
    flash('Você fez logout com sucesso.', 'info')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def user_dashboard():
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
    total_pages = math.ceil(total_tasks / PER_PAGE)

    sort_by_mongo = ('-' + sort_by) if sort_order == 'desc' else sort_by
    tasks = tasks_query.order_by(sort_by_mongo).skip((page - 1) * PER_PAGE).limit(PER_PAGE).all()

    all_categories = sorted(list(set(task.category for task in Task.objects(user=user) if task.category)))
    all_tags = sorted(list(set(tag for task in Task.objects(user=user) for tag in task.tags)))

    total_tasks_count = Task.objects(user=user).count()
    pending_tasks_count = Task.objects(user=user, is_completed=False).count()
    completed_tasks_count = Task.objects(user=user, is_completed=True).count()
    approved_tasks_count = Task.objects(user=user, status='aprovada').count()
    awaiting_approval_count = Task.objects(user=user, status='pendente').count()
    requisitions = Requisition.objects(user=user).order_by("-date_created").all()
    total_requisitions_count = Requisition.objects(user=user).count()
    draft_requisitions_count = Requisition.objects(user=user,status="rascunho").count()
    submitted_requisitions_count = Requisition.objects(user=user,status="submetida").count()
    approved_requisitions_count = Requisition.objects(user=user,status="aprovada").count()
    rejected_requisitions_count = Requisition.objects(user=user,status="rejeitada").count()
    return render_template('user_dashboard.html', user=user, tasks=tasks,
                            status_filter=status_filter,
                            priority_filter=priority_filter,
                            category_filter=category_filter,
                            tag_filter=tag_filter,
                            sort_by=sort_by.lstrip('-'),
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
                            approved_tasks_count=approved_tasks_count,
                            awaiting_approval_count=awaiting_approval_count,
                            requisitions=requisitions,
                            total_requisitions_count=total_requisitions_count,
                            draft_requisitions_count=draft_requisitions_count,
                            submitted_requisitions_count=submitted_requisitions_count,
                            approved_requisitions_count=approved_requisitions_count,
                            rejected_requisitions_count=rejected_requisitions_count,
                           )


@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    user_id_obj = ObjectId(session['user_id'])
    user = User.objects(id=user_id_obj).first_or_404()

    if request.method == 'POST':
        titles = request.form.getlist('title[]')
        descriptions = request.form.getlist('description[]')
        priorities = request.form.getlist('priority[]')
        due_dates = request.form.getlist('due_date[]')
        categories = request.form.getlist('category[]')
        tags_raw = request.form.getlist('tags[]')

        created_count = 0
        errors = []

        for i in range(len(titles)):
            title = titles[i].strip()
            description = descriptions[i].strip() if i < len(descriptions) else ''
            priority = priorities[i] if i < len(priorities) else 'media'
            due_date_str = due_dates[i] if i < len(due_dates) else ''
            category = categories[i].strip() if i < len(categories) else ''
            tags_str = tags_raw[i].strip() if i < len(tags_raw) else ''
            tags = [t.strip() for t in tags_str.split(',') if t.strip()] if tags_str else []

            if not all([title, priority, due_date_str, category]):
                errors.append(f"Tarefa {i + 1}: campos obrigatórios em falta — foi ignorada.")
                continue

            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            except ValueError:
                errors.append(f"Tarefa {i + 1}: formato de data inválido — foi ignorada.")
                continue

            new_task = Task(
                title=title, description=description, priority=priority,
                due_date=due_date, category=category, tags=tags,
                status='pendente', user=user
            )
            try:
                new_task.save()
                created_count += 1
            except Exception as e:
                errors.append(f"Tarefa {i + 1}: erro ao guardar ({e}).")

        if created_count:
            flash(f"{created_count} tarefa(s) criada(s) e enviada(s) para aprovação de um administrador.", 'success')
        for err in errors:
            flash(err, 'error')

        if created_count:
            return redirect(url_for('user_dashboard'))
        return render_template('add_task.html', user=user)

    return render_template('add_task.html', user=user)


@app.route('/task/<string:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.objects(id=task_id).first_or_404()
    if str(task.user.id) != session['user_id']:
        flash('Você não tem permissão para editar esta tarefa.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        task.title = request.form.get('title', '').strip()
        task.description = request.form.get('description', '').strip()
        task.priority = request.form.get('priority', '')
        task.category = request.form.get('category', '').strip()
        due_date_str = request.form.get('due_date', '')
        tags_str = request.form.get('tags', '').strip()
        task.tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []

        if not all([task.title, task.priority, due_date_str, task.category]):
            flash("Todos os campos obrigatórios devem ser preenchidos.", 'error')
            return render_template('edit_task.html', task=task)

        try:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Formato de data inválido. Use AAAA-MM-DD.", 'error')
            return render_template('edit_task.html', task=task)

        try:
            task.save()
            flash(f"Tarefa '{task.title}' atualizada com sucesso!", 'success')
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            flash(f"Ocorreu um erro ao atualizar a tarefa: {e}", 'error')
            return render_template('edit_task.html', task=task)

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
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        new_avatar_url = request.form.get('avatar_url', '').strip()

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
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_new_password = request.form.get('confirm_new_password', '').strip()

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


# --- Dashboard global (só tarefas aprovadas) ---

@app.route('/public_tasks')
def public_tasks():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    public_tasks_query = Task.objects(status='aprovada')
    if search_query:
        public_tasks_query = public_tasks_query(__raw__={'$or': [
            {'title': {'$regex': search_query, '$options': 'i'}},
            {'description': {'$regex': search_query, '$options': 'i'}},
            {'category': {'$regex': search_query, '$options': 'i'}},
            {'tags': {'$regex': search_query, '$options': 'i'}}
        ]})

    total_public_tasks = public_tasks_query.count()
    total_public_pages = math.ceil(total_public_tasks / PER_PAGE)
    public_tasks_list = public_tasks_query.order_by('-date_created').skip((page - 1) * PER_PAGE).limit(PER_PAGE).all()

    current_user_obj = None
    if 'user_id' in session:
        current_user_obj = User.objects(id=ObjectId(session['user_id'])).first()

    return render_template('public_tasks.html', public_tasks=public_tasks_list,
                            current_user=current_user_obj, search_query=search_query,
                            page=page, total_pages=total_public_pages)


@app.route('/public_task/<string:task_id>')
def public_task_detail(task_id):
    task = Task.objects(id=task_id).first_or_404()
    if task.status != 'aprovada':
        flash('Esta tarefa ainda não foi aprovada e não pode ser visualizada.', 'error')
        return redirect(url_for('public_tasks'))

    task_comments = Comment.objects(task=task).order_by('date_created').all()
    current_user_obj = None
    if 'user_id' in session:
        current_user_obj = User.objects(id=ObjectId(session['user_id'])).first()

    return render_template('public_task_detail.html', task=task,
                            comments=task_comments, current_user=current_user_obj)


@app.route('/task/<string:task_id>/add_comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.objects(id=task_id).first_or_404()
    if task.status != 'aprovada':
        flash('Não é possível comentar em tarefas ainda não aprovadas.', 'error')
        return redirect(url_for('public_tasks'))

    comment_content = request.form.get('comment_content', '').strip()
    if not comment_content:
        flash('O comentário não pode estar vazio.', 'error')
        return redirect(url_for('public_task_detail', task_id=task_id))

    user_id_obj = ObjectId(session['user_id'])
    current_user = User.objects(id=user_id_obj).first_or_404()

    new_comment = Comment(content=comment_content, user=current_user, task=task)
    new_comment.save()
    flash('Comentário adicionado com sucesso!', 'success')
    return redirect(url_for('public_task_detail', task_id=task_id))


@app.route('/comment/<string:comment_id>/delete')
@login_required
def delete_comment(comment_id):
    comment = Comment.objects(id=comment_id).first_or_404()
    task_id = str(comment.task.id)

    if str(comment.user.id) != session['user_id']:
        flash('Você não tem permissão para apagar este comentário.', 'error')
        return redirect(url_for('public_task_detail', task_id=task_id))

    comment.delete()
    flash('Comentário apagado com sucesso!', 'success')
    return redirect(url_for('public_task_detail', task_id=task_id))


# --- Exportação para PDF (tarefas aprovadas, agregadas) ---

def _pdf_safe(text):
    if text is None:
        return ''
    return str(text).encode('latin-1', 'replace').decode('latin-1')


@app.route('/public_tasks/export_pdf')
@login_required
def export_tasks_pdf():
    search_query = request.args.get('search', '').strip()
    tasks_query = Task.objects(status='aprovada')
    if search_query:
        tasks_query = tasks_query(__raw__={'$or': [
            {'title': {'$regex': search_query, '$options': 'i'}},
            {'description': {'$regex': search_query, '$options': 'i'}},
            {'category': {'$regex': search_query, '$options': 'i'}},
            {'tags': {'$regex': search_query, '$options': 'i'}}
        ]})
    tasks = tasks_query.order_by('-date_created').all()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, _pdf_safe('Tarefas Aprovadas - Relatório'), ln=True, align='C')
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 8, _pdf_safe(f"Gerado em: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"), ln=True, align='C')
    pdf.cell(0, 8, _pdf_safe(f"Total de tarefas: {len(tasks)}"), ln=True, align='C')
    pdf.ln(6)

    if not tasks:
        pdf.set_font('Helvetica', 'I', 11)
        pdf.multi_cell(0, 8, _pdf_safe('Ainda não existem tarefas aprovadas.'))

    for task in tasks:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.multi_cell(0, 8, _pdf_safe(task.title))

        pdf.set_font('Helvetica', '', 10)
        pdf.multi_cell(0, 6, _pdf_safe(
            f"Categoria: {task.category}   |   Prioridade: {task.priority}   |   Prazo: {task.due_date}"
        ))

        if task.description:
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 6, _pdf_safe(task.description))

        if task.tags:
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 6, _pdf_safe(f"Tags: {', '.join(task.tags)}"))

        approved_by_name = task.approved_by.username if task.approved_by else '-'
        approved_at_str = task.approved_at.strftime('%Y-%m-%d %H:%M') if task.approved_at else '-'

        pdf.set_font('Helvetica', 'I', 9)
        pdf.multi_cell(0, 6, _pdf_safe(
            f"Assinado pelo criador: {task.user.username}   |   Aprovado por: {approved_by_name} em {approved_at_str}"
        ))

        pdf.ln(3)
        y = pdf.get_y()
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, y, 200, y)
        pdf.ln(4)

    pdf_output = pdf.output(dest='S')
    if isinstance(pdf_output, str):
        pdf_output = pdf_output.encode('latin-1')

    return Response(
        pdf_output,
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=tarefas_aprovadas.pdf'}
    )

@app.route("/requisitions/new", methods=["GET", "POST"])
@login_required
def add_requisition():
    user = User.objects(
        id=ObjectId(session["user_id"])
    ).first_or_404()

    suggestion_fields = [
        "machine_reference",
        "brand",
        "model",
        "part_code",
        "part_description",
        "unit"
    ]

    suggestions = {
        field: Suggestion.objects(
            field_name=field
        ).order_by("value")
        for field in suggestion_fields
    }

    if request.method == "POST":
        machine_reference = request.form.get(
            "machine_reference",
            ""
        ).strip()

        brand = request.form.get(
            "brand",
            ""
        ).strip()

        model = request.form.get(
            "model",
            ""
        ).strip()

        serial_number = request.form.get(
            "serial_number",
            ""
        ).strip()

        priority = request.form.get(
            "priority",
            "media"
        ).strip()

        due_date_raw = request.form.get(
            "due_date",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        signature = request.form.get(
            "requester_signature",
            ""
        ).strip()

        submit_action = request.form.get(
            "submit_action",
            "draft"
        )

        part_codes = request.form.getlist("part_code[]")
        part_descriptions = request.form.getlist(
            "part_description[]"
        )
        quantities = request.form.getlist("quantity[]")
        units = request.form.getlist("unit[]")

        if not all([
            machine_reference,
            brand,
            model,
            due_date_raw
        ]):
            flash(
                "Preencha a referência da máquina, marca, "
                "modelo e data necessária.",
                "error"
            )

            return render_template(
                "add_requisition.html",
                user=user,
                suggestions=suggestions
            )

        try:
            due_date = datetime.strptime(
                due_date_raw,
                "%Y-%m-%d"
            ).date()
        except ValueError:
            flash(
                "A data necessária não é válida.",
                "error"
            )

            return render_template(
                "add_requisition.html",
                user=user,
                suggestions=suggestions
            )

        items = []

        for index, part_code in enumerate(part_codes):
            part_code = part_code.strip()

            part_description = (
                part_descriptions[index].strip()
                if index < len(part_descriptions)
                else ""
            )

            quantity_raw = (
                quantities[index].strip()
                if index < len(quantities)
                else "1"
            )

            unit = (
                units[index].strip().upper()
                if index < len(units)
                else "UN"
            )

            if not part_code and not part_description:
                continue

            if not part_code or not part_description:
                flash(
                    f"Material {index + 1}: indique o código "
                    "e a descrição da peça.",
                    "error"
                )

                return render_template(
                    "add_requisition.html",
                    user=user,
                    suggestions=suggestions
                )

            try:
                quantity = int(quantity_raw)

                if quantity < 1:
                    raise ValueError
            except ValueError:
                flash(
                    f"Material {index + 1}: quantidade inválida.",
                    "error"
                )

                return render_template(
                    "add_requisition.html",
                    user=user,
                    suggestions=suggestions
                )

            items.append(
                RequisitionItem(
                    part_code=part_code,
                    part_description=part_description,
                    quantity=quantity,
                    unit=unit or "UN"
                )
            )

        if not items:
            flash(
                "Adicione pelo menos uma peça ou material.",
                "error"
            )

            return render_template(
                "add_requisition.html",
                user=user,
                suggestions=suggestions
            )

        if submit_action == "submit" and not signature:
            flash(
                "Assine a requisição antes de a submeter.",
                "error"
            )

            return render_template(
                "add_requisition.html",
                user=user,
                suggestions=suggestions
            )

        status = (
            "submetida"
            if submit_action == "submit"
            else "rascunho"
        )

        requisition = Requisition(
            machine_reference=machine_reference,
            brand=brand,
            model=model,
            serial_number=serial_number,
            items=items,
            priority=priority,
            due_date=due_date,
            description=description,
            user=user,
            status=status
        )

        if status == "submetida":
            requisition.requester_signature = signature
            requisition.requester_signed_at = datetime.utcnow()

        try:
            requisition.save()

            Suggestion.save_suggestion(
                "machine_reference",
                machine_reference,
                user
            )
            Suggestion.save_suggestion("brand", brand, user)
            Suggestion.save_suggestion("model", model, user)

            for item in items:
                Suggestion.save_suggestion(
                    "part_code",
                    item.part_code,
                    user
                )
                Suggestion.save_suggestion(
                    "part_description",
                    item.part_description,
                    user
                )
                Suggestion.save_suggestion(
                    "unit",
                    item.unit,
                    user
                )

            if status == "submetida":
                flash(
                    f"Requisição {requisition.requisition_number} "
                    "assinada e enviada para aprovação.",
                    "success"
                )
            else:
                flash(
                    f"Requisição {requisition.requisition_number} "
                    "guardada como rascunho.",
                    "success"
                )

            return redirect(
                url_for("requisition_detail", requisition_id=requisition.id)
            )

        except Exception as error:
            app.logger.exception(
                "Erro ao guardar a requisição"
            )

            flash(
                f"Não foi possível guardar a requisição: {error}",
                "error"
            )

    return render_template(
        "add_requisition.html",
        user=user,
        suggestions=suggestions
    )

@app.route("/requisitions/<string:requisition_id>")
@login_required
def requisition_detail(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    current_user = User.objects(
        id=ObjectId(session["user_id"])
    ).first_or_404()

    if (
        str(requisition.user.id) != str(current_user.id)
        and not current_user.is_admin
    ):
        abort(403)

    return render_template(
        "requisition_detail.html",
        requisition=requisition,
        current_user=current_user
    )


# --- Administração ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    users_page = request.args.get('users_page', 1, type=int)
    users_query = User.objects().order_by('username')
    total_users = users_query.count()
    total_users_pages = math.ceil(total_users / PER_PAGE)
    all_users = users_query.skip((users_page - 1) * PER_PAGE).limit(PER_PAGE).all()

    tasks_page = request.args.get('tasks_page', 1, type=int)
    tasks_query = Task.objects().order_by('-date_created')
    total_tasks = tasks_query.count()
    total_tasks_pages = math.ceil(total_tasks / PER_PAGE)
    all_tasks = tasks_query.skip((tasks_page - 1) * PER_PAGE).limit(PER_PAGE).all()

    # NOVO: tarefas pendentes de aprovação
    pending_page = request.args.get('pending_page', 1, type=int)
    pending_query = Task.objects(status='pendente').order_by('-date_created')
    total_pending = pending_query.count()
    total_pending_pages = math.ceil(total_pending / PER_PAGE)
    pending_tasks = pending_query.skip((pending_page - 1) * PER_PAGE).limit(PER_PAGE).all()

    current_user = User.objects(id=ObjectId(session['user_id'])).first()

    pending_requisitions = Requisition.objects(status="submetida").order_by("-date_created").all()
        
    all_requisitions = Requisition.objects().order_by("-date_created").all()
        
    total_pending_requisitions = Requisition.objects(status="submetida").count()

    return render_template('admin_dashboard.html',
                            all_users=all_users, users_page=users_page, total_users_pages=total_users_pages,
                            all_tasks=all_tasks, tasks_page=tasks_page, total_tasks_pages=total_tasks_pages,
                            pending_tasks=pending_tasks, pending_page=pending_page,
                            total_pending_pages=total_pending_pages, total_pending=total_pending,
                            current_user=current_user, per_page=PER_PAGE,
                            pending_requisitions=pending_requisitions,
                            all_requisitions=all_requisitions,
                            total_pending_requisitions=total_pending_requisitions,
                          )


@app.route('/admin/task/<string:task_id>/approve', methods=['POST'])
@admin_required
def approve_task(task_id):
    task = Task.objects(id=task_id).first_or_404()
    admin_user = User.objects(id=ObjectId(session['user_id'])).first()

    task.status = 'aprovada'
    task.approved_by = admin_user
    task.approved_at = datetime.utcnow()
    task.save()

    flash(f"Tarefa '{task.title}' aprovada e assinada por {admin_user.username}. Já está no dashboard global.", 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))


@app.route('/admin/task/<string:task_id>/reject', methods=['POST'])
@admin_required
def reject_task(task_id):
    task = Task.objects(id=task_id).first_or_404()
    task.status = 'rejeitada'
    task.approved_by = None
    task.approved_at = None
    task.save()

    flash(f"Tarefa '{task.title}' rejeitada.", 'info')
    return redirect(request.referrer or url_for('admin_dashboard'))


@app.route('/admin/user/<string:user_id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin_status(user_id):
    target_user = User.objects(id=ObjectId(user_id)).first_or_404()
    if str(target_user.id) == session['user_id']:
        flash('Você não pode alterar o seu próprio status de administrador.', 'error')
        return redirect(url_for('admin_dashboard'))

    target_user.is_admin = not target_user.is_admin
    target_user.save()
    flash(f"Status de administrador de '{target_user.username}' alterado para "
          f"'{'Admin' if target_user.is_admin else 'Não Admin'}'.", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<string:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    target_user = User.objects(id=ObjectId(user_id)).first_or_404()
    if str(target_user.id) == session['user_id']:
        flash('Você não pode apagar a sua própria conta de administrador.', 'error')
        return redirect(url_for('admin_dashboard'))

    if target_user.is_admin:
        num_admins = User.objects(is_admin=True).count()
        if num_admins <= 1:
            flash('Não pode apagar o único administrador da plataforma.', 'error')
            return redirect(url_for('admin_dashboard'))

    username_to_delete = target_user.username
    target_user.delete()
    flash(f"Utilizador '{username_to_delete}' e todos os seus dados apagados com sucesso.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/requisitions/<string:requisition_id>/review")
@admin_required
def review_requisition(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    current_user = User.objects(
        id=ObjectId(session["user_id"])
    ).first_or_404()

    return render_template(
        "review_requisition.html",
        requisition=requisition,
        current_user=current_user
    )


@app.route(
    "/admin/requisitions/<string:requisition_id>/approve",
    methods=["POST"]
)
@admin_required
def approve_requisition(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    admin_user = User.objects(
        id=ObjectId(session["user_id"])
    ).first_or_404()

    approver_signature = request.form.get(
        "approver_signature",
        ""
    ).strip()

    if requisition.status != "submetida":
        flash(
            "Esta requisição já foi analisada ou ainda não foi submetida.",
            "warning"
        )
        return redirect(
            url_for(
                "review_requisition",
                requisition_id=requisition.id
            )
        )

    if not requisition.requester_signature:
        flash(
            "A requisição não possui assinatura do requerente.",
            "error"
        )
        return redirect(
            url_for(
                "review_requisition",
                requisition_id=requisition.id
            )
        )

    if not approver_signature:
        flash(
            "O administrador deve assinar antes de aprovar.",
            "error"
        )
        return redirect(
            url_for(
                "review_requisition",
                requisition_id=requisition.id
            )
        )

    requisition.status = "aprovada"
    requisition.approved_by = admin_user
    requisition.approver_signature = approver_signature
    requisition.approved_at = datetime.utcnow()
    requisition.rejection_reason = None
    requisition.save()

    flash(
        f"Requisição {requisition.requisition_number} "
        f"aprovada por {admin_user.username}.",
        "success"
    )

    return redirect(
        url_for(
            "review_requisition",
            requisition_id=requisition.id
        )
    )


@app.route(
    "/admin/requisitions/<string:requisition_id>/reject",
    methods=["POST"]
)
@admin_required
def reject_requisition(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    rejection_reason = request.form.get(
        "rejection_reason",
        ""
    ).strip()

    if requisition.status != "submetida":
        flash(
            "Esta requisição já foi analisada ou ainda não foi submetida.",
            "warning"
        )
        return redirect(
            url_for(
                "review_requisition",
                requisition_id=requisition.id
            )
        )

    if not rejection_reason:
        flash(
            "Indique o motivo da rejeição.",
            "error"
        )
        return redirect(
            url_for(
                "review_requisition",
                requisition_id=requisition.id
            )
        )

    requisition.status = "rejeitada"
    requisition.rejection_reason = rejection_reason
    requisition.approved_by = None
    requisition.approver_signature = None
    requisition.approved_at = None
    requisition.save()

    flash(
        f"Requisição {requisition.requisition_number} rejeitada.",
        "info"
    )

    return redirect(url_for("admin_dashboard"))

# --- Error Handlers ---

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(debug=True)
