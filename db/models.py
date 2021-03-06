"""
DB models for Mongo
"""
from flask_login import UserMixin
from mongoengine import StringField, ListField, ReferenceField, DateTimeField, BooleanField, Document, connect

from config import config

DEFAULT_STRING_MAX_LENGTH = 10000
mongo_config = config['MONGO']

connect(mongo_config['MONGO_DB'],host=mongo_config['MONGO_HOST'])


class Role(Document):
    name = StringField(max_length=80, unique=True)
    description = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)


class User(Document, UserMixin):
    email = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    password = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    name = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    surname = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    active = BooleanField(default=True)
    confirmed_at = DateTimeField()
    roles = ListField(ReferenceField(Role), default=[])


class Project(Document):
    name = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    managers = ListField(ReferenceField(User), required=True)
    users = ListField(ReferenceField(User), default=[])
    invited_managers = ListField(ReferenceField(User), default=[])
    invited_users = ListField(ReferenceField(User), default=[])


class Activity(Document):
    idle_activity = BooleanField(default=False)
    activity_type = StringField(max_length=DEFAULT_STRING_MAX_LENGTH, default='os')
    user = ReferenceField(User)
    start_time = DateTimeField()
    end_time = DateTimeField()
    executable_name = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    browser_url = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    browser_title = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    ip_address = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    mac_address = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
    value = StringField(max_length=DEFAULT_STRING_MAX_LENGTH)
