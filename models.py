from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, Date, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, date # Importe 'date' também
from app import db 
Base = declarative_base()

class User(Base):
    __tablename__ = 'users' # Nome da tabela no BD
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    # tasks = relationship('Task', back_populates='owner') # Se usar back_populates

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"

class Task(Base):
    __tablename__ = 'tasks' # Nome da tabela no BD
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String(10), nullable=False) # 'alta', 'média', 'baixa'
    due_date = Column(Date, nullable=False) # Armazena apenas a data
    category = Column(String(50), nullable=False)
    is_completed = Column(Boolean, default=False)
    date_created = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    # owner = relationship('User', back_populates='tasks') # Se usar back_populates

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', user_id={self.user_id})>"