import asyncio
import typing
from functools import wraps


def async_run(
    func: typing.Callable[..., typing.Awaitable[typing.Any]]
) -> typing.Callable:
    @wraps(func)
    def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        return asyncio.run(func(*args, **kwargs))

    return wrapper
