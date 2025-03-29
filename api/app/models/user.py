from datetime import datetime
from enum import Enum

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel


class EmailVerificationStatus(str, Enum):
    verified = 'verified'
    verifying = 'verifying'
    none = 'none'


class User(SQLModel, table=True):
    __tablename__ = 'users'
    __table_args__ = (
        UniqueConstraint('username', name='uq_users_username'),
        UniqueConstraint('email', name='uq_users_email'),
        {'extend_existing': True},
    )

    id: int | None = Field(default=None, primary_key=True)
    username: str
    email: str | None = None
    full_name: str | None = None
    hashed_password: str
    email_verification_status: EmailVerificationStatus = EmailVerificationStatus.none
    email_verification_token: str | None = None
    password_reset_token: str | None = None

    sessions: list['Session'] = Relationship(back_populates='user')


class Session(SQLModel, table=True):
    __tablename__ = 'sessions'
    __table_args__ = {'extend_existing': True}

    id: int | None = Field(default=None, primary_key=True)
    expire_time: datetime
    is_finished: bool = False

    user_id: int = Field(foreign_key='users.id')
    user: User = Relationship(back_populates='sessions')
