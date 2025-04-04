from flask import Flask, request, render_template_string, redirect, url_for, session
from markupsafe import escape
import html

app = Flask(__name__)
app.secret_key = 'dev'

questions = [
    {
        'id': 1,
        'title': 'Simple XSS',
        'description': '反射値がHTML属性内に入り込むケース。',
        'template': '<input name="q" value="{}">',
        'vulnerable': True,
        'context': 'attribute',
        'filter_script': False
    },
    {
        'id': 2,
        'title': 'scriptタグが使えないケース',
        'description': '禁則文字:script ',
        'template': '{}',
        'vulnerable': True,
        'context': 'html',
        'filter_script': True
    },
    {
        'id': 3,
        'title': 'Script内に反射するケース 1',
        'description': '禁則文字: >',
        'template': '<script>var msg = "{}";</script>',
        'vulnerable': True,
        'context': 'js_string',
        'filter_script': False,
        'blocked_keywords': ['>']
    },
    {
        'id': 4,
        'title': 'イベント属性に反射するケース1',
        'description': '禁則文字: "',
        'template': '<div onmouseover={}>カーソルを当ててみてください</div>',
        'vulnerable': True,
        'context': 'event_attr',
        'filter_script': True
    },
    {
        'id': 5,
        'title': 'Script内に反射するケース 2',
        'description': '禁則文字:> <',
        'template': '<script>var json = {{"status": "ok", "data": "{}"}};</script>',
        'vulnerable': True,
        'context': 'js_injection',
        'filter_script': False,
        'blocked_keywords': ['>','<']
    },
    {
        'id': 6,
        'title': 'iframeタグのみ許可されている状態',
        'description': '禁則文字: iframe以外のタグ',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'allowed_tags': ['iframe']
    },
    {
        'id': 7,
        'title': 'scriptもalertも使えないケース',
        'description': '禁則文字:script alert',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'blocked_keywords': ['script', 'alert']
    },
    {
        'id': 8,
        'title': 'promptやconfirm,console.log も使えないケース',
        'description': '禁則文字:script prompt confirm eval function',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'blocked_keywords': ['script', 'alert', 'prompt', 'console.log', 'confirm', 'eval', 'function']
    },
    {
        'id': 9,
        'title': 'イベント属性に反射するケース2',
        'description': '禁則文字:" >',
        'template': '<div onmouseover="console.log(1);{};doSomething()">ホバーしてみて</div>',
        'vulnerable': True,
        'context': 'event_handler_complex',
        'filter_script': True,
        'blocked_keywords': ['"','>']
    },
    {
        'id': 10,
        'title': 'イベント属性に反射するケース3',
        'description': '禁則文字:alert " >',
        'template': "<a href='#' onclick='logClick('{}')'>リンク</a>",
        'vulnerable': True,
        'context': 'attr_escape_escape',
        'filter_script': True,
        'blocked_keywords': ['alert','"','>']
    },
    {
        'id': 11,
        'title': 'eval経由でのスクリプト実行 (alert/prompt/confirm禁止)',
        'description': '禁則文字: alert prompt confirm > < \\',
        'template': '<script>{}</script>',
        'vulnerable': True,
        'context': 'script_eval_b64',
        'filter_script': True,
        'blocked_keywords': ['alert', 'prompt', 'confirm','<','>','\\']
    },
    {
        'id': 12,
        'title': "onmouseover属性内反射",
        'description': "禁則文字: alert prompt confirm > <",
        'template': '<div onmouseover="console.log(\'1{} \');">ホバーしてみて</div>',
        'vulnerable': True,
        'context': 'event_attr_quote_entity',
        'filter_script': True,
        'sanitize_single_quote': True,
        'blocked_keywords': ['alert', 'prompt', 'confirm','<','>']
    },
    {
    'id': 13,
    'title': 'href属性内反射',
    'description': '禁則文字: ">, alert, script',
    'template': '<a href="{}">クリック</a>',
    'vulnerable': True,
    'context': 'a_href_attr',
    'filter_script': True,
    'blocked_keywords': ['"', '>', 'alert', 'script','\\','prompt','console','confirm']
    },
    {
    'id': 14,
    'title': 'スペースのスペースが・・？',
    'description': '禁則文字: %20(space) / script ',
    'template': '{}',
    'vulnerable': True,
    'context': 'html_strict_space_blocked',
    'filter_script': True,
    'blocked_keywords': [' ', '/', 'script', 'svg', 'onload']
    },
    {
  "id": 15,
  "title": "JSON.parse 1",
  "description": "禁則文字:script > <",
  "template": "<script>$(function(){{ var data = $.parseJSON('{{\"1\":{{\"value\":\"{}\"}}}}'); }});</script>",
  "vulnerable": True,
  "context": "js_json_parse",
  "filter_script": True,
  "blocked_keywords": ["script", "<", ">"]
    },
    {
  "id": 16,
  "title": "JSON.parse 2",
  "description": "禁則文字:script > < \" ",
  "template": "<script>$(function(){{ var data = $.parseJSON('{{\"1\":{{\"value\":\"{}\"}}}}'); }});</script>",
  "vulnerable": True,
  "context": "js_json_parse",
  "filter_script": True,
  "blocked_keywords": ["script", "<", ">","\""]
    },
    {
        'id': 17,
        'title': '全て大文字に変換されるケース',
        'description': '禁則文字: script eval { ]',
        'template': '<div>{}</div>',
        'vulnerable': True,
        'context': 'uppercase_only',
        'filter_script': True,
        'force_uppercase': True,
        'blocked_keywords': ['SCRIPT', 'EVAL','script']
    }
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

    goto_index = request.args.get('goto')
    if goto_index is not None and goto_index.isdigit():
        idx = int(goto_index)
        if 0 <= idx < len(questions):
            session['question_index'] = idx

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

            if q.get('force_uppercase'):
                user_input = user_input.upper()
            if q.get('filter_script') and '<script' in user_input.lower():
                error_message = 'script タグは禁止されています。WAF回避を試みてください。'
                rendered_input = ''
            elif q.get('blocked_keywords') and is_blocked(user_input, q['blocked_keywords']):
                error_message = '指定された文字列がブロックされています。回避手法を試してください。'
                rendered_input = ''
            elif q['id'] == 4:
                rendered_input = q['template'].format(sanitize_for_event_attr(user_input))
            elif q['id'] == 6:
                rendered_input = q['template'].format(sanitize_html_tags(user_input, q['allowed_tags']))
            else:
                if q.get('sanitize_single_quote'):
                    user_input = user_input.replace("'", "&#39;")
                rendered_input = q['template'].format(user_input) if q['vulnerable'] else q['template'].format(escape(user_input))

    if request.method == 'POST':
        if 'prev' in request.form:
            session['question_index'] = max(session['question_index'] - 1, 0)
        else:
            user_answer = request.form.get('answer', '')
            session['answers'].append(user_answer)
            session['question_index'] += 1
        return redirect(url_for('index'))

    nav_links = ' | '.join([f'<a href="?goto={q["id"]-1}">問題 {q["id"]}</a>' for q in questions])

    html = f'''
     <head>
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
    <nav style="margin-bottom:20px">{nav_links}</nav>
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
        <button type="submit" name="next">次へ</button>
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
    app.run(host='0.0.0.0', port=10000)
