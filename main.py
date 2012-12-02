#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import urllib
import jinja2
import re
import random
import hmac
import hashlib
import time

from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache
from datetime import datetime 
from google.appengine.api import images

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),'templates')), autoescape = True)

###Cookie Hashing
def make_secure_val(val):
	return '%s|%s' % (val,hmac.new("google",val).hexdigest())

def check_secure_val(val):
	value = val.split('|')[0]
	if val == make_secure_val(value):
		return value

#CSRF
def check_secure_val_CSRF(val):
	value = val.split('|')[0]
	if val == make_secure_val_CSRF(value):
		return value

def make_secure_val_CSRF(val):
	return '%s|%s' % (val,hmac.new("4592",val).hexdigest())

###Password Hashing
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name,password,salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + password + salt).hexdigest()
	return '%s|%s' % (salt,h)

def valid_pw(name,password,h):
	salt = h.split('|')[0]
	if h == make_pw_hash(name,password,salt):
		return True

##Input Validation
def validate_username(s):
	return re.match(r"^[a-zA-Z0-9_-]{3,20}$",s)

def validate_password(s):
	return re.match(r"^.{3,20}$",s)

def validate_email(s):
	return re.match(r"^[\S]+@[\S]+\.[\S]+$",s)

###Get Username Information
def get_username(cookie):
	user_id = cookie.split('|')[0]
	user_object = User.by_id(int(user_id))
	username = user_object.name
	return username

###Check if logged in 
def check_login(self):
	cookie = self.request.cookies.get('user_id')
	if check_secure_val(str(cookie)):
		return get_username(cookie)

###User entity
class User(db.Model):
	name = db.StringProperty(required = True)
	avatar = db.BlobProperty(default = None)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	hometown = db.StringProperty()
	music = db.StringProperty()
	numposts = db.IntegerProperty(default = 0)
	rsvpcount = db.IntegerProperty(default = 0)
	events = db.StringListProperty()
	soundcloud = db.StringListProperty()

	@classmethod
	def by_name(cls,name):
		user_get = User.all().filter('name =',name).get()
		return user_get

	@classmethod
	def by_id(cls,uid):
		user_get = User.get_by_id(uid)
		return user_get

	@classmethod
	def register(cls,name,pw,email = None):
		password_hash = make_pw_hash(name,pw)
		return User(name = name,password_hash = password_hash,email = email)

	@classmethod
	def login(cls,name,pw):
		user = cls.by_name(name)
		if user and valid_pw(name,pw,user.password_hash):
			return user

	@classmethod
	def update_numpost(cls,username):
		user = cls.by_name(username)
		if user:
			user.numposts += 1
			user.put()

	@classmethod
	def update_rsvpcount(cls,event_id,username):
		user = cls.by_name(username)
		if user:
			if str(event_id) not in user.events:
				user.rsvpcount += 1
				user.put()

	@classmethod
	def update_events(cls,event_name,event_id,username):
		user = cls.by_name(username)
		if user:
			if str(event_id) not in user.events:
				user.events.append(event_id)
				user.put()

	@classmethod
	def update_soundcloud(cls,link,username):
		soundcloud = User.all().filter('name =',username).filter('soundcloud =',link).fetch(1)
		if link not in soundcloud:
			user = User.by_name(username)
			user.soundcloud.append(link)
			user.put()

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

		if self.request.url.endswith('.json'):
			self.format = '.json'
		else:
			self.format = '.html'

	def login_user(self,username,password):
		user_login = User.login(username,password)

		if user_login:
			user_id = User.by_name(username).key().id()
			cookie_val = make_secure_val(str(user_id))
			self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/' % cookie_val)
			self.redirect('/')

		else:
			invalid = "Invalid login, try again"
			self.render('home-login.html',invalid = invalid)

class HomeHandler(Handler):
	def get(self):
		if self.user:
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			self.render('home.html',username = username, check = CSRF)
		else:
			self.render('home-login.html')

	def post(self):
		username_login = self.request.get('username-login')
		password_login = self.request.get('password-login')

		if username_login and password_login:
			self.login_user(username_login,password_login)

		self.username = self.request.get('username-signup')
		self.email = self.request.get('email-signup')
		self.password = self.request.get('password-signup')
		self.verify = self.request.get('verify-password-signup')
		error = False

		valid_username = validate_username(self.username)
		valid_password = validate_password(self.password)
		valid_email = validate_email(self.email)
		
		if len(self.email) == 0:
			valid_email = True

		params = dict(username = self.username, email = self.email)

		if self.username and self.password and self.verify:
			if not valid_username:
				params['error'] = "That's not a valid username"
				error = True

			if not valid_password:
				params['error'] = "That's not a valid password"
				error = True 

			elif self.password != self.verify:
				params['error'] = "The passwords you entered don't match"
				error = True

			if not valid_email:
				params['error'] = "That's not a valid email"
				error = True

			if error: 
				self.render('home-login.html',**params)

			else:
				check_user = User.by_name(self.username)

				if(check_user):
					exists = "That user already exists"
					self.render('home-login.html',error = exists)

				else:
					new_user = User.register(self.username,self.password,self.email)
					new_user.put()

					user_id = new_user.key().id()
					cookie_val = make_secure_val(str(user_id))
					self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/' % cookie_val)
					self.redirect('/editprofile')
		else:
			self.render('home-login.html',error = "Invalid entry")


###Event entity
class Event(db.Model):
	creator = db.StringProperty(required = True)
	numattendees = db.IntegerProperty(default = 1)
	name = db.StringProperty(required = True)
	date = db.StringProperty(required = True)
	city = db.StringProperty(required = True)
	address = db.StringProperty(required = True)
	time = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_name(cls,name):
		event = Event.all().filter('name =',name).fetch(10)
		return event

	@classmethod
	def by_id(cls,uid):
		event = Event.get_by_id(uid)
		return event

	@classmethod
	def get_event(cls,name):
		event_get = Event.by_name(name)
		return event_get

def update_numattendees(event_id,username):
	event = Event.by_id(int(event_id))
	user_events = User.all().filter('name =',username).filter('events =',event_id).get()
	if not user_events:
		event.numattendees += 1
		event.put()

def events(update = False):
	key = 'events'
	event = memcache.get(key)
	if event is None or update:
		event = db.GqlQuery("SELECT * FROM Event ORDER BY created DESC")
		event = list(event)
		memcache.set(key,event)
	return event

class EventHandler(Handler):
	def get(self):
		if self.user:
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			result = events()
			self.render('events.html',username = username,events = result, check = CSRF)
		else:
			self.redirect('/')

	def post(self):
		search = self.request.get('search')
		add_event = self.request.get('add-event')
		rsvp = self.request.get('RSVP-button')
		username = self.user.name

		if add_event:
			name = self.request.get('event-name')
			date = self.request.get('date')
			city = self.request.get('city')
			address = self.request.get('address')
			time = self.request.get('time')
			eventid = self.request.get('rsvp-id')

			if name and date and city and address and time:
				e = Event(creator = self.user.name,name = name,date = date, city = city, address = address, time = time)
				e.put()
				User.update_rsvpcount(name,self.user.name)
				User.update_events(name,eventid,self.user.name)
				events(True)
				self.redirect(self.request.referer)
			else:
				self.render('events.html',error = "Please provide all details")

		if rsvp:
			rsvp_id = self.request.get('rsvp-id')
			event_name = self.request.get('rsvp-name')

			update_numattendees(rsvp_id,username)
			User.update_rsvpcount(rsvp_id,username)
			User.update_events(event_name,rsvp_id,username)
			result = events(True)
			self.render('events.html',username = username,message = "Thanks! You've RSVP'd",events = result)

		if search:
			search_query = self.request.get('event-name')
			result = Event.get_event(search_query)
			if result:
				self.render('events.html',username = username,events = result)
			else:
				self.render('events.html',username = username,message = "No results found")

###Thread entity
class Thread(db.Model):
	title = db.StringProperty(required = True)
	author = db.StringProperty()
	category = db.StringProperty(required = True)
	numposts = db.IntegerProperty(default = 0)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	recent = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_name(cls,name):
		thread = Thread.all().filter('title =',name).fetch(10)
		return thread

	@classmethod
	def by_id(cls,tid):
		thread_get = Thread.get_by_id(tid)
		return thread_get

	@classmethod
	def update_numposts(cls,tid):
		thread = Thread.by_id(tid)
		thread.numposts += 1
		thread.put()

	@classmethod
	def get_count(cls,category):
		total = 0
		for thread in Thread.all().filter('category =',category):
			total += 1 
		return total

	@classmethod
	def most_recent(cls,category):
		recent = Thread.all().filter('category =',category).order("-created")
		for p in recent.run(limit = 1):
			return datetime.strptime(str(p.created),'%Y-%m-%d %H:%M:%S.%f').strftime('%m-%d-%Y')

	@classmethod
	def reformat_time(cls,time):
		return datetime.strptime(str(time),'%Y-%m-%d %H:%M:%S.%f').strftime('%m-%d-%Y %H:%M')

###Memcache thread handling
def threads(category,update = False):
	key = category
	post = memcache.get(key)
	if post is None or update:
		post = db.GqlQuery("SELECT * FROM Thread WHERE category = :1 ORDER BY recent DESC",category)
		post = list(post)
		memcache.set(key,post)
	return post

class ForumHandler(Handler):
	def get(self):
		if self.user:
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			category = ['generaldiscussion','musictheory','albumreview']
			posts = []
			created = []
			for x in category:
				threads = Thread.get_count(x)
				time = Thread.most_recent(x)
				posts.append(threads)
				created.append(time)
			self.render('forum-main.html',username = username,thread = posts,times = created, check = CSRF)
		else:
			self.redirect('/')	

class ForumThreadHandler(Handler):
	def get(self,category):
		if self.user:
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			category = str(category[1:])
			if category == 'generaldiscussion' or category == 'musictheory' or category == 'albumreview':
				result = threads(category)
				titles = {'generaldiscussion':'General Discussion','musictheory':'Music Theory','albumreview':'Album Review'}
				self.render('forum-thread.html',username = username,category = titles[category],thread_table = result, Thread = Thread, check = CSRF)
			else:
				self.render('404.html',category = category, check = CSRF)
		else:
			self.redirect('/')

	def post(self,category):
		title = self.request.get('title')
		content = self.request.get('content')
		addThread = self.request.get('add-thread')
		author = self.user.name
		search = self.request.get('search')
		query = self.request.get('thread-name')
		username = self.user.name

		if addThread and title and content:
			category = str(category[1:])
			p = Thread(title = title, author = author,category = category,numposts = 1,content = content)
			p.put()
			User.update_numpost(author)
			threads(category,True)
			self.redirect(self.request.referer)

		if search and query:
			results = Thread.by_name(query)
			if results:
				searchq = 'Search ' + query
				self.render('forum-thread.html',username = username,thread_table = results, category = searchq, Thread = Thread)
			else:
				self.redirect(self.request.referer)
		else:
			self.redirect(self.request.referer)

###Post entity
class Post(db.Model):
	threadid = db.IntegerProperty(required = True)
	author = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

###Get posts
def posts(thread,update = False):
	key = str(thread)
	post = memcache.get(key)
	if post is None or update:
		post = db.GqlQuery("SELECT * FROM Post WHERE threadid = :1 ORDER BY created ASC",thread)
		post = list(post)
		memcache.set(key,post)
	return post

class PostHandler(Handler):
	def get(self,thread):
		if self.user:
			thread = thread[1:]
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			post = None
			if Thread.by_id(int(thread)):
				threads = Thread.by_id(int(thread))
				category = threads.category
				if posts(int(thread)):
					post = posts(int(thread))
				self.render('forum-posts.html',username = username,thread = threads,post = post, User = User,category = category, check = CSRF)
			else: 
				self.render('404.html')
		else:
			self.redirect('/')

	def post(self,thread):
		content = self.request.get('post-content')
		if content:
			author = self.user.name
			p = Post(threadid = int(thread[1:]),author = author,content = content)
			p.put()
			posts(int(thread[1:]),True)

			User.update_numpost(author)
			category = Thread.by_id(int(thread[1:])).category
			Thread.update_numposts(int(thread[1:]))
			threads(category,True)

			self.redirect(self.request.referer)
		else:
			self.render('forum-posts.html')

class ProfileHandler(Handler):
	def get(self,profile):
		if self.user:
			profile = profile[1:]
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			user = User.by_name(profile)
			name = user.name
			hometown = user.hometown
			music = user.music
			uid = user.key().id()
			posts = user.numposts
			rsvp = user.rsvpcount
			soundcloud = user.soundcloud
			self.render('profile.html', username = username, uid = uid, name = name, hometown = hometown, music = music, posts = posts, rsvp = rsvp, soundcloud = soundcloud,check = CSRF)
		else:
			self.redirect('/')

class EditProfileHandler(Handler):
	def get(self):
		if self.user:
			username = self.user.name
			CSRF = make_secure_val_CSRF(username)
			self.render('edit-profile.html',username = username, check = CSRF)
		else:
			self.redirect('/')

	def post(self):
		username = self.user.name
		hometown = self.request.get('hometown')
		music = self.request.get('music')
		link = self.request.get('soundcloud')
		image = self.request.get('image')

		if hometown and music and image:
			avatar = images.resize(self.request.get('image'),66,66)
			user = User.by_name(username)
			user.hometown = hometown
			user.music = music
			user.avatar = db.Blob(avatar)
			if link:
				start = link.find("http://")
				if start == -1:
					start = link.find("https://")
				end = link.find('"',start)
				link = link[start:end]
				soundcloud = User.all().filter('name =',username).filter('soundcloud =',link).get()
				if not soundcloud:
					user = User.by_name(username)
					user.soundcloud.append(link)
			user.put()
			self.render('edit-profile.html',username = username,confirm = "Updated, check out your profile ", here = "here")

		else:
			response = "Please fill out all information"
			self.render('edit-profile.html',username = username,response = response)

		

class ImageHandler(Handler):
	def get(self,uid):
		user = User.by_id(int(uid[1:]))
		if user.avatar:
			self.response.headers['Content-Type'] = 'image/jpg'
			self.response.out.write(user.avatar)
		else:
			self.redirect('/static/images/naeem.png')

class Logout(Handler):
	def post(self):
		CSRF = self.request.get('check')
		self.response.out.write(CSRF)
		if check_secure_val_CSRF(CSRF):
			self.response.headers.add_header('Set-Cookie','user_id=;Path=/')
		self.redirect('/')

PAGE_RE = r'(/(?:[a-zA-Z0-9_ -]+/?)*)'        

app = webapp2.WSGIApplication([('/', HomeHandler),
							   ('/events',EventHandler),
							   ('/forum/home',ForumHandler),
							   ('/forum/category' + PAGE_RE,ForumThreadHandler),
							   ('/forum/posts' + PAGE_RE,PostHandler),
							   ('/profile' + PAGE_RE,ProfileHandler),
							   ('/editprofile',EditProfileHandler),
							   ('/image' + PAGE_RE,ImageHandler),
							   ('/logout',Logout)],debug=True)
