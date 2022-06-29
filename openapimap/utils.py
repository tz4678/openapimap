import datetime
import random


def random_datetime(
    start: datetime.datetime = datetime.datetime(1900, 1, 1, 0, 0, 0),
    end: datetime.datetime = datetime.datetime.now(),
) -> datetime.datetime:
    return start + (end - start) * random.random()


def random_email() -> str:
    return (
        'user'
        + str(random.randint(100000, 999999))
        + '@'
        + random.choice(['gmail.com', 'yahoo.com', 'live.com'])
    )


def random_phone_number() -> str:
    # +1 NXX-NXX-XXXX
    # N=digits 2–9, X=digits 0–9
    return f'+1 {random.randint(200, 999)}-{random.randint(200, 999)}-{random.randint(0, 9999):04}'
