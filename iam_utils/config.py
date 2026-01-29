import os


class IAMConfig:
    SECRET_KEY: str = "change_me"  # override in your application
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    PASSWORD_SCHEMES = ["bcrypt"]
    PASSWORD_DEPRECATED: str = "auto"

    def load_from_env(self, prefix: str = "IAM_") -> None:
        """Load configuration overrides from environment variables.

        Supported variables (with default prefix IAM_):
            - IAM_SECRET_KEY
            - IAM_ALGORITHM
            - IAM_ACCESS_TOKEN_EXPIRE_MINUTES
            - IAM_PASSWORD_SCHEMES (comma-separated)
            - IAM_PASSWORD_DEPRECATED
        """

        secret = os.getenv(f"{prefix}SECRET_KEY")
        if secret:
            self.SECRET_KEY = secret

        alg = os.getenv(f"{prefix}ALGORITHM")
        if alg:
            self.ALGORITHM = alg

        expires = os.getenv(f"{prefix}ACCESS_TOKEN_EXPIRE_MINUTES")
        if expires:
            try:
                self.ACCESS_TOKEN_EXPIRE_MINUTES = int(expires)
            except ValueError:
                pass

        schemes = os.getenv(f"{prefix}PASSWORD_SCHEMES")
        if schemes:
            parsed = [s.strip() for s in schemes.split(",") if s.strip()]
            if parsed:
                self.PASSWORD_SCHEMES = parsed

        deprecated = os.getenv(f"{prefix}PASSWORD_DEPRECATED")
        if deprecated:
            self.PASSWORD_DEPRECATED = deprecated


iam_config = IAMConfig()
