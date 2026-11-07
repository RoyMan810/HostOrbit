class Denied(Exception):
    def __init__(self, code: str, status: int = 403, *, retry_after: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = retry_after
