import cherrypy
import random
import string
import base64
import urlparse
import time
import json
import os
import errno
import hashlib

VERSION = "0.1"

TOKEN_LENGTH = 65
NOTE_ROOT = "./notes"
HASH_ROUNDS = 100
SESSION_TIMEOUT = 60


class Session(object):
    session_timeout = 60
    index = dict()

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.time = time.time()

    def valid(self):
        return ((time.time() - self.time) < SESSION_TIMEOUT)

    def activity(self):
        self.time = time.time()

    def index_load(self):
        user_dir = os.path.join(NOTE_ROOT, self.email)
        if os.path.exists(user_dir):
            user_index = os.path.join(user_dir, 'index')
            if os.path.exists(user_index):
                try:
                    f = open(user_index, 'r')
                    self.index = json.loads(f.read())
                    f.close()
                except Exception, e:
                    print "ERROR: Could not read index: %s" % e

    def index_sync(self, load=True):
        user_dir = os.path.join(NOTE_ROOT, self.email)
        if not os.path.exists(user_dir):
            try:
                os.makedirs(user_dir)
            except OSError as e:
                if e.errno == errno.EEXIST and os.path.isdir(user_dir):
                    pass
                else:
                    raise

        user_index = os.path.join(user_dir, 'index')

        f = open(user_index, 'w')
        f.write(json.dumps(self.index).replace("},", "}, \n"))
        f.close()

    def index_update(self, note_update):
        if len(self.index) == 0:
            self.index_load()

        if not 'key' in note_update:
            raise cherrypy.HTTPError(500)

        key = note_update['key']

        if not key in self.index:
            self.index[key] = {'version': 0, 'deleted': 0, 'versions': dict(), 'minversion': 1}
            now = time.time()
            self.index[key]['versions'][0] = {'modifydate': now, 'tags': [], 'createdate': now, 'systemtags': [], 'syncnum': 0}
            #raise cherrypy.HTTPError(500)

        entry = None
        note = self.index[key]

        version = note['version']
        if 'version' in note_update:
            version = note_update['version']

        entry = note['versions'][version]

        if not entry:
            raise cherrypy.HTTPError(500)

        for k in entry:
            if k in note_update and k != 'key' and k != 'content' and k != 'version' and k != 'deleted' and k != 'minversion':
                entry[k] = note_update[k]

        if 'deleted' in note_update:
            note['deleted'] = note_update['deleted']

        note['versions'][version] = entry
        self.index[key] = note
        self.index_sync()

        entry['deleted'] = self.index[key]['deleted']
        entry['key'] = key
        entry['minversion'] = self.index[key]['minversion']
        entry['version'] = self.index[key]['version']

        return entry

    def index_get(self, note_id, version=None):
        if note_id in self.index:
            note = self.index[note_id]
            v = note['version']
            if version:
                if version < 0 or version > note['version']:
                    raise Exception("SESSION: Note version out of bounds")
                v = version

        else:
            raise cherrypy.HTTPError(500)

        entry = note['versions'][v]
        entry['key'] = note_id
        entry['deleted'] = note['deleted']
        entry['minversion'] = note['minversion']
        entry['version'] = v
        return entry
 
    def index_entries(self, load=True):
        if len(self.index) == 0 and load:
            self.index_load()

        entries = []

        for keys in self.index:
            entries.append(self.index_get(keys))

        return entries

    def index_size(self):
        if len(self.index) == 0:
            self.index_load()

        return len(self.index)

    def index_trash(self, note_id):
        if len(self.index) == 0:
            self.index_load()

        if note_id in self.index:
            self.index[note_id]['deleted'] = 1
            self.index_sync()


    def index_delete(self, note_id):
        if len(self.index) == 0:
            self.index_load()

        if note_id in self.index:
            del self.index[note_id]
            self.index_sync(False)

    def index_exists(self, note_id):
        return note_id in self.index


class SimpleNoteAPI(object):
    auth_tokens = dict()
    sessions = dict()

    def __init__(self):
        pass

    def login(self, **kwargs):
        if len(cherrypy.request.params) != 1 \
                or cherrypy.request.headers['Content-Type'] != 'application/x-www-form-urlencoded':
            print "ERROR: Invalid auth request"
            raise cherrypy.HTTPError(403)

        try:
            form_data = kwargs.keys()[0]
            missing_padding = 4 - len(form_data) % 4
            if missing_padding:
                form_data += '=' * missing_padding

            form_data = base64.decodestring(form_data)
            params = urlparse.parse_qs(form_data)
        except Exception, e:
            print "ERROR: Unable to parse form data: %s" % e
            print "Form Data is: %s" % kwargs
            raise cherrypy.HTTPError(403)

        if not 'email' in params or not 'password' in params:
            print "ERROR: Invalid auth form"
            raise cherrypy.HTTPError(403)

        email = params['email'][0]
        password = params['password'][0]

        if not self.authenticated(email, password):
            print "ERROR: Authentication failure"
            raise cherrypy.HTTPError(403)

        rnd = random.SystemRandom()
        token = ''.join(rnd.choice('0123456789ABCDEF') for _ in range(TOKEN_LENGTH))
        self.auth_tokens[token] = email
        if not email in self.sessions:
            self.sessions[email] = Session(email, password)
        else:
            self.sessions[email].activity()

        #Clean up old sessions
        #This should be in a thread with a timer, not here...
        return token
        tstart = time.time()
        for k, v in self.sessions.iteritems():
            if not v.valid():
                v.index_sync()
                for ak, av in self.auth_tokens.iteritems():
                    if av == v.email:
                        del self.auth_tokens[ak]

                del self.sessions[k]
        print "INFO: Cleanup took %fs" % (time.time() - tstart)

        return token

    def data(self, note_id=None, note_version=None, auth=None, email=None, **kwargs):
        session = self.get_session(auth)
        if session and session.valid():
            session.activity()

            if cherrypy.request.method == "DELETE":
                #print "NOTE DELETE: %s" % note_id
                self.note_delete(session, note_id)
            elif cherrypy.request.method == "POST":
                if note_id:
                    #print "NOTE UPDATE: id: %s content:%s" % (note_id, kwargs)
                    data = json.loads(kwargs.keys()[0])

                    return self.note_update(session, data)
                else:
                    #print "NOTE ADD: %s" % kwargs
                    arguments = json.loads(kwargs.keys()[0])
                    if len(arguments) > 0:
                        if not 'content' in arguments:
                            arguments = {'content': arguments}
                        return self.note_update(session, arguments)
                    else:
                        print "ERROR: Cannot create empty note"
                        raise cherrypy.HTTPError(500)

            elif cherrypy.request.method == "GET":
                    return self.note_get(session, note_id, note_version)

        else:
            raise cherrypy.HTTPError(403)

        return

    def index(self, auth, email, length = 100, since = 0, tags = "", **kwargs):
        #print "INDEX: %s" % email
        session = self.get_session(auth)
        if session and session.valid():
            try:
                session.activity()

                cherrypy.response.headers['Content-Type'] = 'application/json'
                return self.note_list(session)
            except IOError, e:
                print "ERROR: Unable to get note list: %s" % e

        else:
            cherrypy.response.status = 403

    def authenticated(self, email, password):
        user_dir = os.path.realpath(os.path.join(NOTE_ROOT, email))
        if not os.path.exists(user_dir):
            print "ERROR: Auth failed. No user"
            return False

        fname = os.path.realpath(os.path.join(user_dir, 'auth_token'))
        if not os.path.exists(fname):
            print "ERROR: Auth failed. No auth token"
            return False

        fd = open(fname, 'r')
        token = json.loads(fd.read())
        fd.close()

        if not 'salt' in token or not 'secret' in token:
            print "ERROR: Auth failed. Invalid auth token"
            return False

        i = HASH_ROUNDS
        h = str(password)
        hash = hashlib.sha1()
        while i > 0:
            hash.update(token['salt']+h)
            i -= 1

        digest = hash.hexdigest()
        #print "SALT: %s " % token['salt']
        #print "DIGEST: %s" % digest
        return digest == token['secret']


    def get_session(self, auth):
        if auth in self.auth_tokens.keys():
            sid = self.auth_tokens[auth]
            return self.sessions[sid]

        return None


    #Note manipulation methods
    def note_list(self, session):
        nl = {u'count': 0, u'data': [], u'time': time.time()}
        if len(session.index) == 0:
            session.index_load()

        nl['count'] = session.index_size()
        nl['data'] = session.index_entries()
        return json.dumps(nl)


    def note_get(self, session, note_id, version = None):
       # print "GET: %s" % note_id
        entry = session.index_get(note_id)
        if not entry:
            raise Exception("ERROR: Entry not found in session")

        if not version:
            version = entry['version']
        else:
            version = entry['version'] - version

        user_dir = os.path.realpath(os.path.join(NOTE_ROOT, session.email))
        fname = os.path.realpath(os.path.join(user_dir, "%s.%d" % (note_id, entry['version']) ))

        if fname.startswith(user_dir) and\
                os.path.exists(fname):

            f = open(fname, "r")
            data = f.read()
            f.close()

            entry['content'] = data
            return json.dumps(entry)
        else:
            raise Exception("Invalid ID: %s" % note_id)

    def note_update(self, session, note):
       # print "UPDATE/ADD: %s" % note
        entry = None

        if 'key' in note:
            entry = session.index_get(note['key'])

        if not entry:
            note_id = ""
            rnd = random.SystemRandom()

            user_dir = os.path.realpath(os.path.join(NOTE_ROOT, session.email))
            if not os.path.exists(user_dir):
                try:
                    os.makedirs(user_dir)
                except OSError as e:
                    if e.errno == errno.EEXIST and os.path.isdir(user_dir):
                        pass
                    else:
                        raise
            while True:
                note_id = ''.join(rnd.choice(string.ascii_letters+string.digits) for _ in range(40))
                if not session.index_exists(note_id):
                    break

            note['key'] = note_id

        entry = session.index_update(note)

        if 'content' in note:
            user_dir = os.path.realpath(os.path.join(NOTE_ROOT, session.email))
            fname = os.path.realpath(os.path.join(user_dir, "%s.%d" % (entry['key'], entry['version'])))

            if fname.startswith(user_dir):
                f = open(fname, "w")
                f.write(note['content'])
                f.close()

        return json.dumps(entry)

    def note_delete(self, session, note_id):
        user_dir = os.path.realpath(os.path.join(NOTE_ROOT, session.email))
        note = session.index_get(note_id)

        for i in range(0, note['version']+1):
            fname = os.path.realpath(os.path.join(user_dir, '%s.%d' % (note_id, i)))

            if fname.startswith(user_dir) and\
                    os.path.exists(fname):

                os.unlink(fname)

        session.index_delete(note_id)


api = SimpleNoteAPI()

d = cherrypy.dispatch.RoutesDispatcher()
d.connect('login', '/api/login', controller=api, action='login', conditions=dict(method=['POST']))
d.connect('index', '/api2/index', controller=api, action='index', conditions=dict(method=['GET']))
d.connect('update', '/api2/data/:note_id', controller=api, action='data', conditions=dict(method=['POST','GET','DELETE']))
d.connect('update_version', '/api2/data/:note_id/:note_version', controller=api, action='data', conditions=dict(method=['POST','GET']))
d.connect('create', '/api2/data', controller=api, action='data')

conf = {'/': {'request.dispatch': d}}

cherrypy.quickstart(api, '/', config=conf)
