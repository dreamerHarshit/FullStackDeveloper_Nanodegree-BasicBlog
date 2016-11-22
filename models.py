import os
import re
import string
import webapp2
import jinja2
import hashlib
import hmac
import random
from google.appengine.ext import db


class User(db.Model):
	username=db.StringProperty(required=True)
	pwd_hash=db.StringProperty(required=True)


class Post(db.Model):
	subject=db.StringProperty(required=True)
	content=db.TextProperty(required=True)
	created=db.DateTimeProperty(auto_now_add=True)
	last_modified=db.DateTimeProperty(auto_now = True)
	author = db.ReferenceProperty(User)

	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html",p = self)

class Comment(db.Model):
	post_id = db.IntegerProperty(required=True)
	author = db.ReferenceProperty(User)
	comment = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
