"""
Hanken Username/Password Authentication
"""

from django.core.urlresolvers import reverse
from django import forms
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponseRedirect

import logging

# some parameters to indicate that status updating is possible
STATUS_UPDATES = False


def create_user(username, name = None):
  from auth.models import User

  user = User.get_by_type_and_id('hanken', username)
  if user:
    raise Exception('user exists')

  info = {'name': name}
  user = User.update_or_create(user_type='hanken', user_id=username, info = info)
  user.save()

class LoginForm(forms.Form):
  username = forms.CharField(max_length=50)
  password = forms.CharField(widget=forms.PasswordInput(), max_length=100)

import httplib
import urllib
import re

def password_check(user, password):
  conn = httplib.HTTPSConnection('www.hanken.fi')
  params = {'username': "s" + user.user_id, 'password': password}
  headers = {"Content-type": "application/x-www-form-urlencoded"}
  conn.request('POST','/student/Auth/ShsWeb', urllib.urlencode(params), headers)
  response = conn.getresponse()
  result = False;
  if response.status == httplib.OK:
    data = response.read()
    match = re.search('s:[0-9]:"s([0-9]{6})";}', data)
    if match and match.group(1) == user.user_id:
      result = True
      logging.info('Good password for %s' % user.user_id)
    else:
      logging.warn('Bad authentication for %s' % user.user_id)
  else:
      logging.warn("Hanken returned %s %s" % (response.status, response.reason))

  conn.close()
  return result

# the view for logging in
def hanken_login_view(request):
  from auth.view_utils import render_template
  from auth.views import after
  from auth.models import User

  error = None

  if request.method == "GET":
    form = LoginForm()
  else:
    form = LoginForm(request.POST)

    # set this in case we came here straight from the multi-login chooser
    # and thus did not have a chance to hit the "start/password" URL
    request.session['auth_system_name'] = 'hanken'
    if request.POST.has_key('return_url'):
      request.session['auth_return_url'] = request.POST.get('return_url')

    if form.is_valid():
      username = form.cleaned_data['username'].strip()
      if username.startswith('s'):
        username = username[1:]

      password = form.cleaned_data['password'].strip()
      try:
        user = User.get_by_type_and_id('hanken', username)
        if password_check(user, password):
          request.session['hanken_user'] = user
          return HttpResponseRedirect(reverse(after))
      except User.DoesNotExist:
        logging.info('User %s not found' % username)
      error = 'Bad Username or Password'

  return render_template(request, 'hanken/login', {'form': form, 'error': error})

def get_auth_url(request, redirect_url = None):
  return reverse(password_login_view)

def get_user_info_after_auth(request):
  user = request.session['hanken_user']
  del request.session['hanken_user']
  user_info = user.info

  return {'type': 'hanken', 'user_id' : user.user_id, 'name': user.name, 'info': user.info, 'token': None}

def update_status(token, message):
  pass

def send_message(user_id, user_name, user_info, subject, body):
  if user_info.has_key('email'):
    email = user_info['email']
    name = user_name or user_info.get('name', email)
    send_mail(subject, body, settings.SERVER_EMAIL, ["%s <%s>" % (name, email)], fail_silently=False)
