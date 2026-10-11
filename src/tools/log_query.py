"""Read-only typed bounded log lookup."""

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from src.events.store import query


class LogArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: IPvAnyAddress
    limit: int = Field(default=20, ge=1, le=100)


def lookup(args: LogArgs, session_factory, start=None, end=None):
    with session_factory() as session:
        return query(session, str(args.ip), args.limit, start, end)
