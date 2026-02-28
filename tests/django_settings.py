SECRET_KEY = "test-secret-key-for-django-tests"
ROOT_URLCONF = "tests.django_urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
INSTALLED_APPS = ["django.contrib.contenttypes"]
CAP_CHALLENGE_COUNT = 2
CAP_CHALLENGE_SIZE = 8
CAP_CHALLENGE_DIFFICULTY = 1
