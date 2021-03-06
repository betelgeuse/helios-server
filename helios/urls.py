# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *

from django.conf import settings

from views import *

urlpatterns = None

urlpatterns = patterns('',
  (r'^$', home),
  (r'^testcookie$', test_cookie),
  (r'^testcookie_2$', test_cookie_2),
  (r'^nocookies$', nocookies),
  (r'^stats$', stats),
  (r'^socialbuttons$', socialbuttons),

  # election shortcut by shortname
  (r'^e/(?P<election_short_name>[^/]+)$', election_shortcut),
  
  # trustee login
  (r'^t/(?P<election_short_name>[^/]+)/(?P<trustee_email>[^/]+)/(?P<trustee_secret>[^/]+)$', trustee_login),
  
  # election
  (r'^elections/params$', election_params),
  (r'^elections/verifier$', election_verifier),
  (r'^elections/single_ballot_verifier$', election_single_ballot_verifier),
  (r'^elections/new$', election_new),
  (r'^elections/administered$', elections_administered),
  
  (r'^elections/(?P<election_uuid>[^/]+)', include('helios.election_urls')),
  
)


