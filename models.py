import os
import re
import string
import webapp2
import jinja2
import hashlib
import hmac
import random
from google.appengine.ext import ndb


class User(ndb.Model):
	username=ndb.StringProperty(required=True)
	pwd_hash=ndb.StringProperty(required=True)


class Post(ndb.Model):
	subject=ndb.StringProperty(required=True)
	content=ndb.TextProperty(required=True)
	created=ndb.DateTimeProperty(auto_now_add=True)
	last_modified=ndb.DateTimeProperty(auto_now = True)
	author = ndb.StructuredProperty(User)

	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html",p = self)

class CommentModel(ndb.Model):
	post_id = ndb.IntegerProperty(required=True)
	author = ndb.StructuredProperty(User)
	comment = ndb.StringProperty(required=True)
	created = ndb.DateTimeProperty(auto_now_add=True)
