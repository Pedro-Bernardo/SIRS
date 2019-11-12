from flask import *
import json

app = Flask(__name__)

app.secret_key = '_5#y2L"F4Q8z\n\xec]/'
password = 'HARDCODED_PASSWORD'
notes = {}

nextNoteID = 0

@app.route('/')
def hello():
    return '''
        <form method="post" action="/setNote">
            <p><input type=text name=note>
            <p><input type=submit value=Submit note>
        </form>
    '''


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('hello'))
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>
    '''

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/seeNote', methods=['GET'])
def seeNote():
	noteID = request.args.get('note')
	pw = request.args['password']

	if noteID is not None and pw is not None and pw == password:
		noteID = int(noteID)
		return "<html><h1>{}</h1></html>".format(notes[noteID])

	return 'invalid'

@app.route('/setNote', methods=['POST'])
def setNote():
    global nextNoteID
    
    text = request.form['note']
    
    if text is not None:
        noteID = nextNoteID
        nextNoteID += 1
        notes[noteID] = text
    
    return json.dumps({'noteID': noteID})


if __name__ == "__main__":
    app.run(host="0.0.0.0")