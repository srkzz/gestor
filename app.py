# app.py (Versão com Aprovação de Admin, Criação em Lote, Assinaturas e Exportação PDF)
import os
import math
import base64
import tempfile
import re
import boto3
import uuid
from werkzeug.utils import secure_filename
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime, date
from functools import wraps
from io import BytesIO
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

def get_r2_client():
    endpoint_url = os.environ.get("R2_ENDPOINT_URL")
    access_key_id = os.environ.get("R2_ACCESS_KEY_ID")
    secret_access_key = os.environ.get("R2_SECRET_ACCESS_KEY")

    if not all([
        endpoint_url,
        access_key_id,
        secret_access_key
    ]):
        raise RuntimeError(
            "As credenciais do Cloudflare R2 não estão configuradas."
        )

    return boto3.client(
        service_name="s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name="auto",
        config=Config(
            signature_version="s3v4",
            retries={
                "max_attempts": 3,
                "mode": "standard"
            }
        )
    )
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
    quotation_storage_key = db.StringField()
    quotation_original_name = db.StringField()
    quotation_content_type = db.StringField()
    quotation_size = db.IntField()
    quotation_uploaded_at = db.DateTimeField()
    quotation_uploaded_by = db.ReferenceField(
        User,
        required=False
    )

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

def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    try:
        return User.objects(
            id=ObjectId(user_id)
        ).first()
    except Exception:
        return None

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

@app.route("/dashboard")
@login_required
def user_dashboard():
    user = get_current_user()

    if not user:
        return redirect(url_for("login"))

    status_filter = request.args.get("status", "all")
    priority_filter = request.args.get("priority", "all")
    sort_by = request.args.get("sort_by", "date_created")
    sort_order = request.args.get("sort_order", "desc")
    search_query = request.args.get("search", "").strip()
    page = request.args.get("page", 1, type=int)

    if page < 1:
        page = 1

    # Lista completa, permanece sempre disponível
    all_requisitions_query = Requisition.objects(user=user)

    # Consulta separada para pesquisa e filtros
    filtered_query = Requisition.objects(user=user)

    valid_statuses = [
        "rascunho",
        "submetida",
        "aprovada",
        "rejeitada"
    ]

    if status_filter in valid_statuses:
        filtered_query = filtered_query(
            status=status_filter
        )

    valid_priorities = [
        "baixa",
        "media",
        "alta"
    ]

    if priority_filter in valid_priorities:
        filtered_query = filtered_query(
            priority=priority_filter
        )

    # Pesquisa global
    if search_query:
        safe_search = re.escape(search_query)

        filtered_query = filtered_query(
            __raw__={
                "$or": [
                    {
                        "machine_reference": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "brand": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "model": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "serial_number": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "description": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "items.part_code": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "items.part_description": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    },
                    {
                        "items.unit": {
                            "$regex": safe_search,
                            "$options": "i"
                        }
                    }
                ]
            }
        )

    # Esta parte deve ficar fora do if search_query
    allowed_sort_fields = [
        "date_created",
        "due_date",
        "machine_reference",
        "brand",
        "model",
        "priority",
        "status"
    ]

    if sort_by not in allowed_sort_fields:
        sort_by = "date_created"

    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    sort_field = (
        f"-{sort_by}"
        if sort_order == "desc"
        else sort_by
    )

    filters_active = (
    status_filter != "all"
    or priority_filter != "all"
    or bool(search_query)
    )

    total_filtered_requisitions = filtered_query.count()
    total_pages = math.ceil(
    total_filtered_requisitions / PER_PAGE
    )

    if total_pages < 1:
        total_pages = 1

    if page > total_pages:
        page = total_pages

    # Todas as requisições ficam sempre visíveis na tabela principal
    requisitions = (
        all_requisitions_query
        .order_by("-date_created")
        .all()
    )

    # Resultados específicos da pesquisa e filtros
    filtered_requisitions = (
        filtered_query
        .order_by(sort_field)
        .skip((page - 1) * PER_PAGE)
        .limit(PER_PAGE)
        .all()
    )
    # Contadores gerais
    total_requisitions_count = Requisition.objects(
        user=user
    ).count()

    draft_requisitions_count = Requisition.objects(
        user=user,
        status="rascunho"
    ).count()

    submitted_requisitions_count = Requisition.objects(
        user=user,
        status="submetida"
    ).count()

    approved_requisitions_count = Requisition.objects(
        user=user,
        status="aprovada"
    ).count()

    rejected_requisitions_count = Requisition.objects(
        user=user,
        status="rejeitada"
    ).count()

    return render_template(
        "user_dashboard.html",
        user=user,
        requisitions=requisitions,
        status_filter=status_filter,
        priority_filter=priority_filter,
        sort_by=sort_by,
        sort_order=sort_order,
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        per_page=PER_PAGE,
        total_filtered_requisitions=total_filtered_requisitions,
        total_requisitions_count=total_requisitions_count,
        draft_requisitions_count=draft_requisitions_count,
        submitted_requisitions_count=submitted_requisitions_count,
        approved_requisitions_count=approved_requisitions_count,
        rejected_requisitions_count=rejected_requisitions_count,
        filtered_requisitions=filtered_requisitions,
        filters_active=filters_active,
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

def signature_to_bytes(signature_data):
    if not signature_data:
        return None

    try:
        if "," in signature_data:
            signature_data = signature_data.split(",", 1)[1]

        image_bytes = base64.b64decode(signature_data)

        return BytesIO(image_bytes)

    except Exception:
        app.logger.exception(
            "Não foi possível converter a assinatura."
        )
        return None

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
    current_user = User.objects(
        id=ObjectId(session["user_id"])
    ).first()

    pending_requisitions = Requisition.objects(
        status="submetida"
    ).order_by("-date_created").all()

    total_pending_requisitions = Requisition.objects(
        status="submetida"
    ).count()

    all_requisitions = Requisition.objects().order_by(
        "-date_created"
    ).all()

    total_requisitions = Requisition.objects().count()

    total_submitted_requisitions = Requisition.objects(
        status="submetida"
    ).count()

    total_approved_requisitions = Requisition.objects(
        status="aprovada"
    ).count()

    total_rejected_requisitions = Requisition.objects(
        status="rejeitada"
    ).count()

    total_draft_requisitions = Requisition.objects(
        status="rascunho"
    ).count()

   

    return render_template('admin_dashboard.html',
                            all_users=all_users, users_page=users_page, total_users_pages=total_users_pages,
                            all_tasks=all_tasks, tasks_page=tasks_page, total_tasks_pages=total_tasks_pages,
                            pending_tasks=pending_tasks, pending_page=pending_page,
                            total_pending_pages=total_pending_pages, total_pending=total_pending,
                            current_user=current_user, per_page=PER_PAGE,
                            pending_requisitions=pending_requisitions,
                            all_requisitions=all_requisitions,
                            total_pending_requisitions=total_pending_requisitions,
                            total_requisitions=total_requisitions,
                            total_submitted_requisitions=total_submitted_requisitions,
                            total_approved_requisitions=total_approved_requisitions,
                            total_rejected_requisitions=total_rejected_requisitions,
                            total_draft_requisitions=total_draft_requisitions,
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

@app.route(
    "/requisitions/<string:requisition_id>/pdf"
)
@login_required
def requisition_pdf(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    # Apenas o requerente ou um administrador pode abrir o PDF
    is_owner = (
        str(requisition.user.id)
        == str(current_user.id)
    )

    if not is_owner and not current_user.is_admin:
        abort(403)

    if requisition.status != "aprovada":
        flash(
            "O PDF só está disponível para requisições aprovadas.",
            "warning"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    pdf = FPDF(
        orientation="P",
        unit="mm",
        format="A4"
    )

    pdf.set_auto_page_break(
        auto=True,
        margin=15
    )

    pdf.add_page()
    
    # Cabeçalho
    # Logótipo no canto superior esquerdo
    logo_path = os.path.join(
        app.root_path,
        "static",
        "img",
        "mota_engil_rwanda.png"
    )

    if os.path.exists(logo_path):
        pdf.image(
            logo_path,
            x=10,
            y=8,
            w=55
        )

    # Título alinhado à direita do logótipo
    pdf.set_xy(70, 11)

    pdf.set_font(
        "Helvetica",
        "B",
        16
    )

    pdf.cell(
        130,
        9,
        _pdf_safe("REQUISIÇÃO DE MATERIAL"),
        align="C"
    )

    pdf.set_xy(70, 21)

    pdf.set_font(
        "Helvetica",
        "B",
        11
    )

    pdf.cell(
        130,
        7,
        _pdf_safe(requisition.requisition_number),
        align="C"
    )

    # Continua o documento abaixo do cabeçalho
    pdf.set_y(38)


    # Estado
    pdf.set_font(
        "Helvetica",
        "B",
        10
    )

    pdf.set_fill_color(
        210,
        245,
        220
    )

    pdf.cell(
        0,
        8,
        _pdf_safe("ESTADO: APROVADA"),
        border=1,
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
        fill=True
    )

    pdf.ln(5)

    # Equipamento
    pdf.set_font(
        "Helvetica",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        _pdf_safe("DADOS DO EQUIPAMENTO"),
        new_x="LMARGIN",
        new_y="NEXT"
    )

    pdf.set_font(
        "Helvetica",
        "",
        10
    )

    equipment_lines = [
        (
            "Referência da máquina",
            requisition.machine_reference
        ),
        (
            "Marca",
            requisition.brand
        ),
        (
            "Modelo",
            requisition.model
        ),
        (
            "Número de série",
            requisition.serial_number or "-"
        ),
        (
            "Urgência",
            requisition.priority.capitalize()
        ),
        (
            "Data necessária",
            requisition.due_date.strftime(
                "%d/%m/%Y"
            )
        )
    ]

    for label, value in equipment_lines:
        pdf.set_font(
            "Helvetica",
            "B",
            10
        )

        pdf.cell(
            45,
            7,
            _pdf_safe(f"{label}:")
        )

        pdf.set_font(
            "Helvetica",
            "",
            10
        )

        pdf.cell(
            0,
            7,
            _pdf_safe(value),
            new_x="LMARGIN",
            new_y="NEXT"
        )

    pdf.ln(5)

    # Materiais
    pdf.set_font(
        "Helvetica",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        _pdf_safe("MATERIAIS REQUISITADOS"),
        new_x="LMARGIN",
        new_y="NEXT"
    )

    # Cabeçalho da tabela
    pdf.set_fill_color(
        50,
        60,
        70
    )

    pdf.set_text_color(
        255,
        255,
        255
    )

    pdf.set_font(
        "Helvetica",
        "B",
        9
    )

    pdf.cell(
        10,
        8,
        "#",
        border=1,
        align="C",
        fill=True
    )

    pdf.cell(
        38,
        8,
        _pdf_safe("Código"),
        border=1,
        align="C",
        fill=True
    )

    pdf.cell(
        92,
        8,
        _pdf_safe("Descrição"),
        border=1,
        align="C",
        fill=True
    )

    pdf.cell(
        25,
        8,
        _pdf_safe("Quantidade"),
        border=1,
        align="C",
        fill=True
    )

    pdf.cell(
        25,
        8,
        _pdf_safe("Unidade"),
        border=1,
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
        fill=True
    )

    pdf.set_text_color(
        0,
        0,
        0
    )

    pdf.set_font(
        "Helvetica",
        "",
        9
    )

    for index, item in enumerate(
        requisition.items,
        start=1
    ):
        pdf.cell(
            10,
            8,
            str(index),
            border=1,
            align="C"
        )

        pdf.cell(
            38,
            8,
            _pdf_safe(item.part_code),
            border=1
        )

        description = _pdf_safe(
            item.part_description
        )

        if len(description) > 52:
            description = (
                description[:49] + "..."
            )

        pdf.cell(
            92,
            8,
            description,
            border=1
        )

        pdf.cell(
            25,
            8,
            str(item.quantity),
            border=1,
            align="C"
        )

        pdf.cell(
            25,
            8,
            _pdf_safe(item.unit),
            border=1,
            new_x="LMARGIN",
            new_y="NEXT",
            align="C"
        )

    # Observações
    if requisition.description:
        pdf.ln(6)

        pdf.set_font(
            "Helvetica",
            "B",
            11
        )

        pdf.cell(
            0,
            7,
            _pdf_safe("DESCRIÇÃO OU OBSERVAÇÕES"),
            new_x="LMARGIN",
            new_y="NEXT"
        )

        pdf.set_font(
            "Helvetica",
            "",
            10
        )

        pdf.multi_cell(
            0,
            6,
            _pdf_safe(
                requisition.description
            ),
            border=1
        )

    pdf.ln(8)

    # Assinaturas
    pdf.set_font(
        "Helvetica",
        "B",
        12
    )

    pdf.cell(
        0,
        8,
        _pdf_safe("ASSINATURAS"),
        new_x="LMARGIN",
        new_y="NEXT"
    )

    signature_y = pdf.get_y() + 3

    # Assinatura do requerente
    requester_signature = signature_to_bytes(
        requisition.requester_signature
    )

    if requester_signature:
        try:
            pdf.image(
                requester_signature,
                x=20,
                y=signature_y,
                w=70,
                h=25,
                keep_aspect_ratio=True
            )
        except Exception:
            app.logger.exception(
                "Erro ao inserir assinatura do requerente no PDF."
            )

    # Assinatura do aprovador
    approver_signature = signature_to_bytes(
        requisition.approver_signature
    )

    if approver_signature:
        try:
            pdf.image(
                approver_signature,
                x=120,
                y=signature_y,
                w=70,
                h=25,
                keep_aspect_ratio=True
            )
        except Exception:
            app.logger.exception(
                "Erro ao inserir assinatura do aprovador no PDF."
            )

    pdf.set_y(
        signature_y + 28
    )

    pdf.set_font(
        "Helvetica",
        "B",
        9
    )

    pdf.cell(
        95,
        6,
        _pdf_safe(
            requisition.user.username
        ),
        align="C"
    )

    approver_name = (
        requisition.approved_by.username
        if requisition.approved_by
        else "-"
    )

    pdf.cell(
        95,
        6,
        _pdf_safe(approver_name),
        new_x="LMARGIN",
        new_y="NEXT",
        align="C"
    )

    pdf.set_font(
        "Helvetica",
        "",
        8
    )

    requester_date = (
        requisition.requester_signed_at.strftime(
            "%d/%m/%Y %H:%M"
        )
        if requisition.requester_signed_at
        else "-"
    )

    approved_date = (
        requisition.approved_at.strftime(
            "%d/%m/%Y %H:%M"
        )
        if requisition.approved_at
        else "-"
    )

    pdf.cell(
        95,
        5,
        _pdf_safe(
            f"Requerente | {requester_date}"
        ),
        align="C"
    )

    pdf.cell(
        95,
        5,
        _pdf_safe(
            f"Aprovador | {approved_date}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
        align="C"
    )

    pdf.ln(8)

    pdf.set_font(
        "Helvetica",
        "I",
        8
    )

    pdf.set_text_color(
        90,
        90,
        90
    )

    pdf.multi_cell(
        0,
        5,
        _pdf_safe(
            "Documento gerado automaticamente pelo "
            "Sistema de Gestão de Requisições."
        ),
        align="C"
    )

    pdf_output = bytes(
        pdf.output()
    )

    filename = (
        f"{requisition.requisition_number}.pdf"
    )

    return Response(
        pdf_output,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                f'inline; filename="{filename}"'
            )
        }
    )

@app.route(
    "/requisitions/<string:requisition_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_requisition(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    # Apenas quem criou pode editar
    if str(requisition.user.id) != str(current_user.id):
        abort(403)

    # Apenas rascunhos podem ser editados
    if requisition.status != "rascunho":
        flash(
            "Só é possível editar requisições em rascunho.",
            "warning"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

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

        if not all([
            machine_reference,
            brand,
            model,
            due_date_raw
        ]):
            flash(
                "Preencha a referência, marca, modelo e data necessária.",
                "error"
            )

            return render_template(
                "edit_requisition.html",
                requisition=requisition
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
                "edit_requisition.html",
                requisition=requisition
            )

        part_codes = request.form.getlist("part_code[]")
        part_descriptions = request.form.getlist(
            "part_description[]"
        )
        quantities = request.form.getlist("quantity[]")
        units = request.form.getlist("unit[]")

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
                    f"Material {index + 1}: indique o código e a descrição.",
                    "error"
                )

                return render_template(
                    "edit_requisition.html",
                    requisition=requisition
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
                    "edit_requisition.html",
                    requisition=requisition
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
                "Adicione pelo menos um material.",
                "error"
            )

            return render_template(
                "edit_requisition.html",
                requisition=requisition
            )

        requisition.machine_reference = machine_reference
        requisition.brand = brand
        requisition.model = model
        requisition.serial_number = serial_number
        requisition.priority = priority
        requisition.due_date = due_date
        requisition.description = description
        requisition.items = items
        submit_action = request.form.get(
            "submit_action",
            "draft"
        )

        requester_signature = request.form.get(
            "requester_signature",
            ""
        ).strip()

        if submit_action == "submit":
            if not requester_signature:
                flash(
                    "Tem de assinar antes de submeter a requisição.",
                    "error"
                )

                return render_template(
                    "edit_requisition.html",
                    requisition=requisition
                )

            requisition.requester_signature = requester_signature
            requisition.requester_signed_at = datetime.utcnow()
            requisition.status = "submetida"

        else:
            requisition.status = "rascunho"

        requisition.save()

        flash(
            f"Requisição {requisition.requisition_number} atualizada.",
            "success"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    return render_template(
        "edit_requisition.html",
        requisition=requisition
    )

@app.route("/admin/requisitions/<string:requisition_id>/delete",
    methods=["POST"])
@admin_required
def delete_requisition(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    requisition_number = requisition.requisition_number

    requisition.delete()

    flash(
        f"Requisição {requisition_number} eliminada com sucesso.",
        "success"
    )

    return redirect(
        request.referrer or url_for("admin_dashboard")
    )


@app.route("/admin/r2/test")
@admin_required
def test_r2_connection():
    bucket_name = os.environ.get("R2_BUCKET_NAME")

    if not bucket_name:
        flash(
            "A variável R2_BUCKET_NAME não está configurada.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    try:
        r2_client = get_r2_client()

        r2_client.head_bucket(
            Bucket=bucket_name
        )

        flash(
            "Ligação ao Cloudflare R2 confirmada com sucesso.",
            "success"
        )

    except (BotoCoreError, ClientError):
        app.logger.exception(
            "Erro ao testar a ligação ao Cloudflare R2."
        )

        flash(
            "Não foi possível ligar ao Cloudflare R2. "
            "Verifique as credenciais e o nome do bucket.",
            "error"
        )

    except RuntimeError as error:
        app.logger.error(str(error))

        flash(
            str(error),
            "error"
        )

    return redirect(url_for("admin_dashboard"))

@app.route(
    "/requisitions/<string:requisition_id>/quotation/upload",
    methods=["POST"]
)
@login_required
def upload_requisition_quotation(requisition_id):
    requisition = Requisition.objects(
        id=requisition_id
    ).first_or_404()

    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    is_owner = (
        str(requisition.user.id)
        == str(current_user.id)
    )

    if not is_owner and not current_user.is_admin:
        abort(403)

    quotation_file = request.files.get("quotation_file")

    if not quotation_file or not quotation_file.filename:
        flash(
            "Selecione um ficheiro PDF para anexar.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    original_name = secure_filename(
        quotation_file.filename
    )

    if not original_name:
        flash(
            "O nome do ficheiro não é válido.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    if not original_name.lower().endswith(".pdf"):
        flash(
            "A cotação tem de ser um ficheiro PDF.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    # Confirma que o conteúdo começa com a assinatura de um PDF.
    file_header = quotation_file.stream.read(5)
    quotation_file.stream.seek(0)

    if file_header != b"%PDF-":
        flash(
            "O ficheiro selecionado não parece ser um PDF válido.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    quotation_file.stream.seek(
        0,
        os.SEEK_END
    )

    file_size = quotation_file.stream.tell()
    quotation_file.stream.seek(0)

    max_file_size = 5 * 1024 * 1024

    if file_size <= 0:
        flash(
            "O ficheiro selecionado está vazio.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    if file_size > max_file_size:
        flash(
            "A cotação não pode exceder 5 MB.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    bucket_name = os.environ.get("R2_BUCKET_NAME")

    if not bucket_name:
        app.logger.error(
            "R2_BUCKET_NAME não está configurada."
        )

        flash(
            "O armazenamento de cotações não está disponível.",
            "error"
        )

        return redirect(
            url_for(
                "requisition_detail",
                requisition_id=requisition.id
            )
        )

    new_storage_key = (
        f"requisitions/{requisition.id}/quotations/"
        f"{uuid.uuid4().hex}.pdf"
    )

    old_storage_key = (
        requisition.quotation_storage_key
    )

    r2_client = None
    new_file_uploaded = False

    try:
        r2_client = get_r2_client()

        r2_client.upload_fileobj(
            quotation_file.stream,
            bucket_name,
            new_storage_key,
            ExtraArgs={
                "ContentType": "application/pdf",
                "ContentDisposition": (
                    f'inline; filename="{original_name}"'
                )
            }
        )

        new_file_uploaded = True

        requisition.quotation_storage_key = (
            new_storage_key
        )

        requisition.quotation_original_name = (
            original_name
        )

        requisition.quotation_content_type = (
            "application/pdf"
        )

        requisition.quotation_size = file_size

        requisition.quotation_uploaded_at = (
            datetime.utcnow()
        )

        requisition.quotation_uploaded_by = (
            current_user
        )

        requisition.save()

        # Só elimina a cotação anterior depois de a nova
        # estar carregada e os metadados estarem guardados.
        if (
            old_storage_key
            and old_storage_key != new_storage_key
        ):
            try:
                r2_client.delete_object(
                    Bucket=bucket_name,
                    Key=old_storage_key
                )
            except (BotoCoreError, ClientError):
                app.logger.exception(
                    "Não foi possível eliminar a "
                    "cotação anterior do R2."
                )

        flash(
            "Cotação anexada com sucesso.",
            "success"
        )

    except (BotoCoreError, ClientError):
        app.logger.exception(
            "Erro ao carregar a cotação no R2."
        )

        if (
            new_file_uploaded
            and r2_client
        ):
            try:
                r2_client.delete_object(
                    Bucket=bucket_name,
                    Key=new_storage_key
                )
            except (BotoCoreError, ClientError):
                app.logger.exception(
                    "Não foi possível limpar o upload "
                    "incompleto no R2."
                )

        flash(
            "Não foi possível carregar a cotação. "
            "Tente novamente.",
            "error"
        )

    except Exception:
        app.logger.exception(
            "Erro inesperado ao guardar a cotação."
        )

        if (
            new_file_uploaded
            and r2_client
        ):
            try:
                r2_client.delete_object(
                    Bucket=bucket_name,
                    Key=new_storage_key
                )
            except (BotoCoreError, ClientError):
                app.logger.exception(
                    "Não foi possível limpar o ficheiro "
                    "após erro."
                )

        flash(
            "Não foi possível guardar a cotação.",
            "error"
        )

    return redirect(
        url_for(
            "requisition_detail",
            requisition_id=requisition.id
        )
    )


# --- Error Handlers ---

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(debug=True)
