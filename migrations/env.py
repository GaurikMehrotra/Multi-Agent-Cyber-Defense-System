"""Migration URL is supplied at runtime, never stored in source."""

import os

from alembic import context
from sqlalchemy import create_engine

from src.db.models import Base

if context.is_offline_mode():
    context.configure(
        url=os.environ["DATABASE_URL"], target_metadata=Base.metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
