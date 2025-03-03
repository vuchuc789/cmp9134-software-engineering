from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = 'users'  # type: ignore
    __table_args__ = (
        UniqueConstraint('username', name='uq_users_username'),
        {'extend_existing': True},
    )

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    email: str | None = None
    full_name: str | None = None
    hashed_password: str
