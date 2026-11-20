from celery import Celery
import os

app = Celery(
    "pathfinder",
    broker=os.getenv("PATHFINDER_REDIS_BROKER", "redis://localhost:6379/0"),
    backend=os.getenv("PATHFINDER_REDIS_BACKEND", "redis://localhost:6379/1"),
)
app.conf.update(
    worker_concurrency=12,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=240,
)

# THIS LINE IS CRITICAL: it registers the task with the worker
import pathfinder.tasks  # noqa: E402,F401