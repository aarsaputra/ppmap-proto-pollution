import time
import functools
import logging
from typing import Callable, Tuple, Type, Union

logger = logging.getLogger(__name__)


def retry_request(
    max_attempts: int = 3,
    backoff: float = 2.0,
    backoff_type: str = "exponential",
    exceptions: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception,
):
    """
    Retry a function with exponential backoff on specified exceptions.

    Args:
        max_attempts: Maximum number of execution attempts.
        backoff: Base delay between retries in seconds.
        backoff_type: 'exponential' or 'linear'.
        exceptions: Tuple of exception types that trigger a retry.
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.error(
                            f"Failed {func.__name__} after {max_attempts} attempts: {type(e).__name__} - {e}"
                        )
                        raise

                    delay = (
                        backoff * (2 ** (attempt - 1))
                        if backoff_type == "exponential"
                        else backoff * attempt
                    )
                    logger.warning(
                        f"Retry {attempt}/{max_attempts} for {func.__name__} "
                        f"due to {type(e).__name__}. Waiting {delay:.1f}s..."
                    )
                    time.sleep(delay)

        return wrapper

    return decorator
