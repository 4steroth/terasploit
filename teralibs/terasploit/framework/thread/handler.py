import contextlib
import queue
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any

from teralibs.terasploit.framework.thread.output_bus import OutputBus
from teralibs.tsf.utils.exception import WorkerThreadError


STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_KILLED = "killed"

_TERMINAL = frozenset({STATUS_COMPLETED, STATUS_FAILED, STATUS_KILLED})


class ModuleContext:
    """Execution context passed as the first argument to every module run()."""

    def __init__(
        self,
        job_id,
        bus,
        kill_event,
    ):
        self.job_id = job_id
        self.bus = bus
        self.kill_event = kill_event

    def is_killed(self):
        """Return True when this job has been asked to stop."""
        return self.kill_event.is_set()

    def info(self, message):
        """Emit an informational log message."""
        self.bus.emit(self.job_id, "info", message)

    def success(self, message):
        """Emit a success log message."""
        self.bus.emit(self.job_id, "success", message)

    def warning(self, message):
        """Emit a warning log message."""
        self.bus.emit(self.job_id, "warning", message)

    def error(self, message):
        """Emit an error log message."""
        self.bus.emit(self.job_id, "error", message)


@dataclass
class _TaskRecord:
    """Per-task state, cancellation signals and optional driver."""

    status: str
    result: Any = None
    error: Any = None
    traceback: Any = None
    kill_event: threading.Event = field(default_factory=threading.Event)
    done_event: threading.Event = field(default_factory=threading.Event)
    driver: Any = None

    def snapshot(self):
        """Return the public four-key view of this record."""
        return {
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "traceback": self.traceback,
        }


class ThreadHandler:
    """Manages a pool of daemon worker threads and a shared job queue."""

    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.output_bus = OutputBus()

        # Thread-safe queue holding incoming tasks for worker threads
        self._task_queue = queue.Queue()

        # Global shutdown signal used to stop worker threads gracefully
        self._shutdown = threading.Event()

        # Registry of task records keyed by task ID (state, signals, driver)
        self._tasks = {}

        # Lock used to synchronize access to shared state across threads
        self._lock = threading.Lock()

        # List of active worker thread objects managed by the scheduler
        self._workers = []

        self._start_workers()

    # Worker lifecycle

    def _start_workers(self):
        """Spawn max_threads daemon worker threads."""
        for index in range(self.max_threads):
            t = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name=f"tsf-worker-{index + 1}",
            )
            t.start()
            self._workers.append(t)

    def _worker_loop(self):
        """Main loop executed by each worker thread."""
        while not self._shutdown.is_set():
            try:
                task_id, func, args, kwargs = self._task_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if task_id is None:
                self._task_queue.task_done()
                return

            with self._lock:
                record = self._tasks[task_id]
                if record.status == STATUS_KILLED:
                    self._task_queue.task_done()
                    record.done_event.set()
                    continue
                record.status = STATUS_RUNNING

            kill_event = record.kill_event
            ctx = ModuleContext(task_id, self.output_bus, kill_event)

            try:
                result = func(ctx, *args, **kwargs)

                with self._lock:
                    if kill_event.is_set():
                        record.status = STATUS_KILLED
                    else:
                        record.status = STATUS_COMPLETED
                        record.result = result

            except WorkerThreadError as exc:
                ctx.error(str(exc))
                with self._lock:
                    if kill_event.is_set():
                        record.status = STATUS_KILLED
                    else:
                        record.status = STATUS_FAILED
                        record.error = str(exc)
                        record.traceback = traceback.format_exc()

            finally:
                self._task_queue.task_done()
                record.done_event.set()

    # Public interface

    def submit(
        self,
        func,
        *args,
        **kwargs,
    ):
        """
        Enqueue *func* for execution and return the task UUID string.
        """
        task_id = str(uuid.uuid4())

        with self._lock:
            self._tasks[task_id] = _TaskRecord(status=STATUS_QUEUED)

        self._task_queue.put((task_id, func, args, kwargs))
        return task_id

    def status(self, task_id):
        """
        Return a snapshot of the task record, or None if not found.
        """
        with self._lock:
            record = self._tasks.get(task_id)
            return record.snapshot() if record else None

    def all_tasks(self):
        """Return a snapshot of all task records."""
        with self._lock:
            return {tid: rec.snapshot() for tid, rec in self._tasks.items()}

    def active_tasks(self):
        """Return a snapshot of tasks that are queued or running."""
        with self._lock:
            return {tid: rec.snapshot() for tid, rec in self._tasks.items() if rec.status not in _TERMINAL}

    def active_count(self):
        """Return the number of tasks currently queued or running."""
        with self._lock:
            return sum(1 for rec in self._tasks.values() if rec.status not in _TERMINAL)

    def kill_task(self, task_id):
        """Gracefully stop a queued or running job."""
        full_id = self._resolve_id(task_id)
        if full_id is None:
            return False

        with self._lock:
            rec = self._tasks.get(full_id)
            if rec is None or rec.status in _TERMINAL:
                return False
            rec.kill_event.set()
            if rec.status == STATUS_QUEUED:
                rec.status = STATUS_KILLED
                rec.done_event.set()

        with self._lock:
            rec = self._tasks.get(full_id)
            driver = rec.driver if rec else None

        if driver is not None:
            with contextlib.suppress(Exception):
                driver.stop()

        return True

    def clear_completed(self):
        """Remove all terminal jobs from the records."""
        with self._lock:
            to_remove = [tid for tid, rec in self._tasks.items() if rec.status in _TERMINAL]
            for tid in to_remove:
                del self._tasks[tid]

        return len(to_remove)

    def register_driver(self, task_id, driver):
        """Associate an ExploitDriver with a task."""
        with self._lock:
            record = self._tasks.get(task_id)
            if record is not None:
                record.driver = driver

    def unregister_driver(self, task_id):
        """Remove the driver association for *task_id*."""
        with self._lock:
            record = self._tasks.get(task_id)
            if record is not None:
                record.driver = None

    def wait_until_done(self, task_id, poll=0.05):
        """Block until *task_id* leaves the running state."""
        full_id = self._resolve_id(task_id)
        if full_id is None:
            return True

        with self._lock:
            record = self._tasks.get(full_id)
        if record is None:
            return True

        return record.done_event.wait(timeout=poll)

    def _resolve_id(self, partial):
        """Match a full or 8-char prefix task ID against known tasks."""
        if not partial:
            return None
        with self._lock:
            if partial in self._tasks:
                return partial
            matches = [tid for tid in self._tasks if tid.startswith(partial)]
            return matches[0] if len(matches) == 1 else None

    def shutdown(self, timeout=5.0):
        """Signal all workers to stop and wait for them to finish."""
        self._shutdown.set()
        for worker in self._workers:
            worker.join(timeout=timeout)

    def set_max_threads(self, new_max):
        """Resize the worker pool to *new_max* threads."""
        new_max = max(1, int(new_max))
        current = len(self._workers)

        if new_max > current:
            for index in range(current, new_max):
                t = threading.Thread(
                    target=self._worker_loop,
                    daemon=True,
                    name=f"tsf-worker-{index + 1}",
                )
                t.start()
                self._workers.append(t)

        elif new_max < current:
            excess_workers = self._workers[new_max:]
            # Signal each excess worker to exit via sentinel task.
            for _ in range(current - new_max):
                self._task_queue.put((None, None, (), {}))
            # Shrink the active list immediately; excess threads will drain
            # their sentinel and exit on their own.
            self._workers = self._workers[:new_max]
            # Join excess threads in the background so shutdown() doesn't need
            # to worry about them and they don't outlive their intent.
            reaper = threading.Thread(
                target=lambda: [t.join(timeout=5.0) for t in excess_workers],
                daemon=True,
                name="tsf-worker-reaper",
            )
            reaper.start()

        self.max_threads = new_max
