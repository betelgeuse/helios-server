The Helios Election Server
==========================

LICENSE: this code is released under the GPL v3 or later.

NEEDS:
- http://github.com/openid/python-openid
- rabbitmq 1.8
-- http://www.rabbitmq.com/debian.html
-- update the deb source
-- apt-get install rabbitmq-server

- celery 2.0.2 and django-celery 2.0.2 for async jobs
-- http://celeryq.org
-- apt-get install python-setuptools
-- easy_install celery
-- easy_install django-celery

- South for schema migration
-- easy_install South


GETTING SOUTH WORKING ON EXISTING INSTALL
- as of Helios v3.0.4, we're using South to migrate data models
- if you've already loaded the data model beforehand, you need to tell South that you've migrated appropriately
- so, if your data model is up to date with the code, do

python manage.py syncdb

to get the south db models set up, and then:

python manage.py migrate --list

- if there are some unchecked migrations, and you are SURE that your database is up to date with the models (which should be the case if you're between v3.0.0 and v3.0.4 inclusive), then do

python manage.py migrate --fake
