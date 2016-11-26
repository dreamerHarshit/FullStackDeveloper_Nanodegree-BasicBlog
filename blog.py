import os
import re
import string
import webapp2
import jinja2
import hashlib
import hmac
import random
from google.appengine.ext import ndb
from models import *
template_dir=os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
secret='abcdef'

USER_RE=re.compile(r"^.{3,20}$")
def valid_username(username):
	'''validate username'''
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	'''Validate password'''
	return password and PASS_RE.match(password)

EMAIL_RE =re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	'''Validate Email'''
	return not email or EMAIL_RE.match(email)

def hash_str(s):
	'''Encrypt Password with HMAC'''
	return hmac.new(secret,s).hexdigest()

def make_secure_val(s):
	'''make secure valur'''
	return "%s|%s"	% (s,hash_str(s))

def check_secure_val(h):
	'''Validate secure valur'''
	val=h.split('|')[0]
	if h==make_secure_val(val):
		return val	

def make_salt():
	''' generating salt for hasing'''
	return ''.join(random.choice(string.letters) for x in xrange(5))		

def make_pw_hash(name,pw,salt=None):
	'''Encrypt password with HASH'''
	if not salt:
		salt=make_salt()
	h=hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' % (h,salt)

def valid_pw(name, pw, h):
    """Decrypt Password"""
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


#All Handlers
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def check_for_valid_cookie():
	cookie = self.request.cookies.get('cookie')
	if cookie:
		is_valid_cookie = check_secure_val(cookie)
		if is_valid_cookie:
			return self.request.cookies.get('cookie').split("|")[0]
		else:
			return None
	else:
		return None			

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **kw):
        kw['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Return Cookie Value"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        """Initialise Web Page with signed-in user"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('user')
        self.user = User.gql("WHERE username = '%s'" % username).get()

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

class BlogFront(BlogHandler):
	def get(self):
		posts=ndb.gql("select * from Post order by created desc limit 10")
		print posts
		self.render('front.html',posts=posts)


class Signup(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		params = dict(username = username,
                      email = email)
		user=User.gql("WHERE username='%s'"%username).get()
		if user:
			have_error=True
			self.render("signup.html",have_error=have_error,username=username)

		else:
			if not valid_username(username):
				params['error_username'] = "That's not a valid username."
				have_error = True
			if not valid_password(password):
				params['error_password'] = "That wasn't a valid password."
				have_error = True
			
			if password != verify:
				params['error_verify'] = "Your passwords didn't match."
				have_error = True
			if not valid_email(email):
				params['error_email'] = "That's not a valid email."
				have_error = True
		
		if have_error:
			self.render("signup.html",have_error=have_error,username=username)

		else:
			user=User(username=username,pwd_hash=make_pw_hash(username,password))
			user.put()
			user_cookie=make_secure_val(str(username))
			self.response.headers.add_header("Set-Cookie","user=%s;path=/"%user_cookie)
			self.redirect("/blog")

class Login(BlogHandler):
	"""Handler For logint"""
	def get(self):
		self.render("login.html")

	def post(self):
		username=self.request.get("username")
		password=self.request.get("password")
		user=User.gql("WHERE username = '%s'" % username).get()
		if user and valid_pw(username, password, user.pwd_hash):
			#//print "hello\n"
			user_cookie = make_secure_val(str(username))
			self.response.headers.add_header("Set-Cookie",
                                             "user=%s; Path=/" % user_cookie)
			self.redirect("/blog")
		else:
			error = "Invalid username"
			self.render("login.html", username=username, error=error)

class Logout(BlogHandler):
	def get(self):
		self.response.headers.add_header("Set-Cookie", "user=; Path=/")
		self.redirect("/blog")

class PostPage(BlogHandler):
	def get(self, post_id):
		key = ndb.Key('Post',int(post_id),parent=blog_key())
		post = key.get()
		key = ndb.Key('CommentModel',int(post_id),parent=blog_key())
		comments = key.get()
		print comments
		if not post:
			self.error(404)
			return
		self.render("permalink.html",post = post,comment=comments)

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect("/login")
		subject=self.request.get("subject")
		content=self.request.get("content")
		
		if subject and content:
			p=Post(parent=blog_key(),subject = subject,content = content,author=self.user)
			p.put()
			self.redirect("/blog")
		else:
			error="subject and content please!"	
			self.render("newpost.html",subject=subject,content=content,error=error)

class EditPost(BlogHandler):
	"""Handler for EditPost"""
	def get(self):
		if self.user:
			post_id=self.request.get("post")
			key = ndb.Key('Post', int(post_id), parent=blog_key())
			post=key.get()
			if not post:
				self.error(404)
				return
			self.render("editpost.html",subject=post.subject,content=post.content)
		else:
			self.redirect("/login")		

	def post(self):
		post_id=self.request.get("subject")
		key = ndb.Key('Post',int(post_id),parent=blog_key())
		post=key.get()
		if post and post.author.username==self.user.username:
			if not self.user:
				return self.redirect("/login")
			subject=self.request.get("subject")
			content=self.request.get("content")
			if subject and content:
				post.subject=subject
				post.content=content
				post.put()
				self.redirect("/blog")
			else:
				error = "missing subject or content"
				self.render("editpost.html",subject=subject,content=content,error=error)
		else:
			self.redirect("/blog")

class DeletePost(BlogHandler):
	"""Handler for deleting a post"""
	def get(self):
		if self.user:
			post_id=self.request.get("post")
			key = ndb.Key('Post',int(post_id),parent=blog_key())
			post=key.get()
			if not post:
				self.error(404)
				return
			self.render("deletepost.html",post=post)
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect("/login")
		
		post_id=self.request.get("post")
		key = ndb.Key('Post',int(post_id),parent=blog_key())
		post=key.get()
		if post and post.author.username==self.user.username:
			key.delete()
		self.redirect("/blog")

class Comment(BlogHandler):
	def get(self,post_id):
		if self.user:
			print "hello1"
			print "p="+post_id
			self.render("comment.html",post_id=post_id)
		else:
			self.redirect("/login")
	def post(self,post_id):
		if self.user:
			print "hello2"
			comment=self.request.get("comment")
			print "c="+comment
			print "p="+post_id
			if comment:
				print "hello3"
				p=CommentModel(post_id=int(post_id),comment=comment,author=self.user)
				if p:
					print "hello4"
				p.put()
				self.redirect("/blog/%s"% post_id)
			else:
				error="content please!"
				self.render("comment.html", comment=comment, error=error)
		else:
			self.redirect('/login')
		
class EditComment(BlogHandler):
    """Handler for EditComment"""
    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = ndb.Key('Comment',int(comment_id),parent=blog_key())
            comment = key.get()
            if not comment:
                self.error(404)
                return
            self.render("editcomment.html",
                        content=comment.content, post_id=comment.post_id)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect("/login")
        comment_id = self.request.get("comment")
        key = ndb.Key('Comment',int(comment_id),parent=blog_key())
        comment = key.get()
        if comment and comment.author.username == self.user.username:
            content = self.request.get("content")
            if content:
                comment.content = content
                comment.put()
                self.redirect("/blog/%s" % comment.post_id)
            else:
                error = "Missing subject or content"
                self.render("editcomment.html",
                            content=content,
                            post_id=comment.post_id,
                            error=error)
        else:
            self.redirect("/blog/%s" % comment.post_id)


class DeleteComment(BlogHandler):
    """Handler for DeleteComment"""
    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = ndb.Key('Comment',int(comment_id),parent=blog_key())
            comment = key.get()
            if not comment:
                self.error(404)
                return
            self.render("deletecomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect("/login")
        comment_id = self.request.get("comment")
        key = ndb.Key('Comment',int(comment_id),parent=blog_key())
        comment = key.get()
        if comment and comment.author.username == self.user.username:
            post_id = comment.post_id
            key.delete()
        self.redirect("/blog/%s" % post_id)



app = webapp2.WSGIApplication([('/',BlogFront),
                               ('/signup', Signup),
                               ('/login',Login),
                               ('/logout',Logout),
                               ('/blog', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/edit',EditPost),
                               ('/blog/delete',DeletePost),
                               ('/blog/newpost', NewPost),
                               ('/comment/edit', EditComment),
                               ('/comment/delete', DeleteComment),
                               ('/comment/new/([0-9]+)',Comment)
                               ],
                              debug=True)