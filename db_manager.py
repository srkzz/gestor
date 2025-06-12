import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

from models import Base, User, Task # Importe os seus modelos

# Carrega as variáveis de ambiente do ficheiro .env
load_dotenv()

class DBManager:
    def __init__(self):
        self.engine = self._create_db_engine()
        self.Session = sessionmaker(bind=self.engine)

    def _create_db_engine(self):
        # Constrói a string de conexão para PostgreSQL
        host = os.getenv("PG_HOST")
        database = os.getenv("PG_DATABASE")
        user = os.getenv("PG_USER")
        password = os.getenv("PG_PASSWORD")

        if not all([host, database, user, password]):
            print("AVISO: Variáveis de ambiente do PostgreSQL não encontradas. Verifique o ficheiro .env.")
            print("Tentando usar uma conexão padrão (pode falhar se o BD não estiver acessível).")
            # Fallback para um SQLite em memória para testes rápidos, se não houver vars de PG
            # Em produção, você DEVE ter as vars de PG definidas.
            return create_engine('sqlite:///:memory:')

        db_url = f"postgresql://{user}:{password}@{host}/{database}"
        return create_engine(db_url)

    def create_tables(self):
        """Cria todas as tabelas definidas nos modelos."""
        Base.metadata.create_all(self.engine)
        print("Tabelas criadas ou já existentes.")

    def get_session(self):
        """Retorna uma nova sessão de banco de dados."""
        return self.Session()

    # --- Funções CRUD ---

    def add_user(self, username):
        session = self.get_session()
        try:
            existing_user = session.query(User).filter_by(username=username).first()
            if existing_user:
                return None, "Utilizador já existe."
            new_user = User(username=username)
            session.add(new_user)
            session.commit()
            return new_user, "Utilizador registado com sucesso!"
        except Exception as e:
            session.rollback()
            return None, f"Erro ao registar utilizador: {e}"
        finally:
            session.close()

    def get_users(self):
        session = self.get_session()
        try:
            users = session.query(User).all()
            return users
        finally:
            session.close()

    def get_user_by_username(self, username):
        session = self.get_session()
        try:
            user = session.query(User).filter_by(username=username).first()
            return user
        finally:
            session.close()

    def add_task(self, user_id, title, description, priority, due_date, category):
        session = self.get_session()
        try:
            new_task = Task(
                user_id=user_id,
                title=title,
                description=description,
                priority=priority,
                due_date=due_date, # due_date já deve ser um objeto date
                category=category
            )
            session.add(new_task)
            session.commit()
            return new_task, "Tarefa adicionada com sucesso!"
        except Exception as e:
            session.rollback()
            return None, f"Erro ao adicionar tarefa: {e}"
        finally:
            session.close()

    def get_tasks_by_user(self, user_id):
        session = self.get_session()
        try:
            tasks = session.query(Task).filter_by(user_id=user_id).order_by(Task.is_completed, Task.due_date).all()
            return tasks
        finally:
            session.close()

    def mark_task_completed(self, task_id):
        session = self.get_session()
        try:
            task = session.query(Task).get(task_id)
            if task:
                task.is_completed = True
                session.commit()
                return True, "Tarefa marcada como concluída."
            return False, "Tarefa não encontrada."
        except Exception as e:
            session.rollback()
            return False, f"Erro ao marcar tarefa: {e}"
        finally:
            session.close()

    def delete_task(self, task_id):
        session = self.get_session()
        try:
            task = session.query(Task).get(task_id)
            if task:
                session.delete(task)
                session.commit()
                return True, "Tarefa apagada com sucesso."
            return False, "Tarefa não encontrada."
        except Exception as e:
            session.rollback()
            return False, f"Erro ao apagar tarefa: {e}"
        finally:
            session.close()

    # ... (Adicione aqui funções para editar tarefa, pesquisar, estatísticas, etc.)