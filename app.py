from flask import Flask, request, render_template_string, redirect, url_for, session
from markupsafe import escape
import html

app = Flask(__name__)
app.secret_key = 'dev'

questions = [
    {
        'id': 1,
        'title': 'シンプルなXSS（属性内）',
        'description': '反射値がHTML属性内に入り込むケース。XSSが発生するか確認せよ。',
        'template': '<input name="q" value="{}">',
        'vulnerable': True,
        'context': 'attribute',
        'filter_script': False
    }
    # ...（他の問題も追加可能）
]

def sanitize_for_event_attr(value):
    return value.replace('"', '[BLOCKED]')

def sanitize_html_tags(value, allowed_tags):
    import re
    def replacer(match):
        tag = match.group(1).lower()
        return match.group(0) if tag in allowed_tags else ''
    return re.sub(r'<\/?([a-zA-Z0-9]+)[^>]*>', replacer, value)

def is_blocked(value, blocked_keywords):
    lowered = value.lower()
    return any(kw in lowered for kw in blocked_keywords)

def get_current_question():
    index = session.get('question_index', 0)
    return questions[index] if index < len(questions) else None

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'answers' not in session:
        session['answers'] = []
        session['question_index'] = 0

    q = get_current_question()
    if not q:
        return redirect(url_for('results'))

    user_input = ''
    user_answer = ''
    submitted = False
    rendered_input = ''
    error_message = ''

    if request.method == 'GET':
        raw = request.args.get('q', None)
        if raw is not None and raw.strip() != '':
            submitted = True
            user_input = raw
            rendered_input = q['template'].format(user_input)

    if request.method == 'POST':
        user_answer = request.form.get('answer', '')
        session['answers'].append(user_answer)
        session['question_index'] += 1
        return redirect(url_for('index'))

    html = f'''
    <h1>問題 {q['id']}：{q['title']}</h1>
    <p>{q['description']}</p>
    <form method="get">
        <label>入力値:</label>
        <input type="text" name="q">
        <input type="submit" value="送信">
    </form>
    <div style="margin-top:20px; border:1px solid #ccc; padding:10px; min-height:2em">
        <strong>反映結果:</strong><br>
        {escape(error_message) if error_message else rendered_input}
    </div>
    <form method="post">
        <label>回答案:</label>
        <input type="text" name="answer" style="z-index:999; position:relative;">
        <button type="submit">次へ</button>
    </form>
    '''
    return render_template_string(html)

@app.route('/results')
def results():
    html = '<h1>回答一覧</h1><ol>'
    for i, ans in enumerate(session.get('answers', []), 1):
        html += f'<li>問題 {i}: {escape(ans)}</li>'
    html += '</ol>'
    return html

if __name__ == '__main__':
    app.run(debug=True)
