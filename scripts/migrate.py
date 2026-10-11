"""Load local environment securely and apply versioned migrations."""

from alembic import command
from alembic.config import Config
from dotenv import load_dotenv

load_dotenv(".env")
command.upgrade(Config("alembic.ini"), "head")
