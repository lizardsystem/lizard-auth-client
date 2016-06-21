from django.http import HttpResponseRedirect
from django.conf import settings

from lizard_auth_client.decorators import attempt_auto_login


def string_has_any_prefix(prefix_list, some_string):
    '''
    Note: needs to be optimized for something better than O(N) efficiency.
    '''
    return any(some_string.startswith(p) for p in prefix_list)

# url prefixes which shouldn't result in a redirect
exempt_urls = [
    'sso',
    'api',
    'admin',
]

# some urls are variable, because they are configurable via Django settings
exempt_urls_from_settings = [
    'STATIC_URL',
    'MEDIA_URL',
    'LOGIN_REDIRECT_URL',
    'LOGIN_URL',
]

# copy these special urls from settings, if they have a value
for key in exempt_urls_from_settings:
    if hasattr(settings, key):
        url = getattr(settings, key)
        if url:
            exempt_urls.append(url)

# strip slashes on both sides
exempt_urls = [exempt_url.strip('/') for exempt_url in exempt_urls]

# strip whitespace
exempt_urls = [exempt_url.strip() for exempt_url in exempt_urls]

# strip out empty urls
exempt_urls = [exempt_url for exempt_url in exempt_urls if url]


class LoginRequiredMiddleware(object):
    """
    Middleware that requires a user to be authenticated to view any page other
    than EXEMPT_URLS (which you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def process_request(self, request):
        assert hasattr(request, 'user'), '''The Login Required middleware
        requires authentication middleware to be installed. Edit your
        MIDDLEWARE_CLASSES setting to insert
        'django.contrib.auth.middlware.AuthenticationMiddleware'.
        If that doesn't work, ensure your TEMPLATE_CONTEXT_PROCESSORS
        setting includes 'django.core.context_processors.auth'.'''

        if not request.user.is_authenticated():
            path = request.path_info.strip('/')
            if not string_has_any_prefix(exempt_urls, path):
                return HttpResponseRedirect(settings.LOGIN_URL)


class AttemptAutoLoginMiddleware(object):
    """Apply the attempt_auto_login decorator on every view function."""

    def process_view(self, request, view_func, view_args, view_kwargs):
        assert hasattr(request, 'user'), '''The AttemptAutoLoginMiddleware
        requires authentication middleware to be installed. Edit your
        MIDDLEWARE_CLASSES setting to insert
        'django.contrib.auth.middlware.AuthenticationMiddleware'.
        If that doesn't work, ensure your TEMPLATE_CONTEXT_PROCESSORS
        setting includes 'django.core.context_processors.auth'.'''

        auto_login_view_func = attempt_auto_login(view_func)
        return auto_login_view_func(request, *view_args, **view_kwargs)
