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
    },
    {
        'id': 2,
        'title': 'script タグが使えないケース（タグ内挿入）',
        'description': 'script タグが使えない前提で XSS を試みよ。',
        'template': '{}',
        'vulnerable': True,
        'context': 'html',
        'filter_script': True
    },
    {
        'id': 3,
        'title': 'JSコンテキスト内での反射',
        'description': 'JavaScriptの文字列内に入力が埋め込まれるケース。',
        'template': '<script>var msg = "{}";</script>',
        'vulnerable': True,
        'context': 'js_string',
        'filter_script': False,
        'blocked_keywords': ['>']
    },
    {
        'id': 4,
        'title': 'イベント属性（" が使用できない）',
        'description': 'onmouseover属性などに挿入されるケース。ただし " は使用できない。',
        'template': '<div onmouseover={}>カーソルを当ててみてください</div>',
        'vulnerable': True,
        'context': 'event_attr',
        'filter_script': True
    },
    {
        'id': 5,
        'title': 'JSON風データをJSに埋め込むケース（XSS可）',
        'description': 'JSON風データがJavaScript内に埋め込まれる。スクリプト実行可能性を探れ。',
        'template': '<script>var json = {{"status": "ok", "data": "{}"}};</script>',
        'vulnerable': True,
        'context': 'js_injection',
        'filter_script': False,
        'blocked_keywords': ['>','<']
    },
    {
        'id': 6,
        'title': 'WAF回避・iframeのみ許可',
        'description': 'iframeタグのみ挿入可能。他のタグは除外される。',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'allowed_tags': ['iframe']
    },
    {
        'id': 7,
        'title': 'scriptもalertも使えないケース',
        'description': 'scriptタグおよびalertという文字列も使用できない状況下でXSSを試みよ。',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'blocked_keywords': ['<script', 'alert']
    },
    {
        'id': 8,
        'title': 'prompt/console.log も使えない XSS回避パターン',
        'description': 'script, alert に加えて prompt, console.log, confirm, eval, function も禁止された環境でXSSを実行せよ。',
        'template': '{}',
        'vulnerable': True,
        'context': 'html_strict',
        'filter_script': True,
        'blocked_keywords': ['<script', 'alert', 'prompt', 'console.log', 'confirm', 'eval', 'function']
    },
    {
        'id': 9,
        'title': 'イベント属性内・複雑構文・"使用不可',
        'description': '既にonmouseover内に様々なJavaScriptコードが書かれており、" は使用できない。;alert(1); のように注入せよ。',
        'template': '<div onmouseover="console.log(1);{};doSomething()">ホバーしてみて</div>',
        'vulnerable': True,
        'context': 'event_handler_complex',
        'filter_script': True,
        'blocked_keywords': ['"','>']
    },
    {
        'id': 10,
        'title': 'XSSが無効なハンドラ内に反射→イベント属性への脱出型XSS',
        'description': 'JavaScriptのイベントハンドラ中の文字列として反射されるが、構文上そのままではXSSは発生しない。\' で脱出して onmouseover=... を追加し、イベント属性ベースでのXSSを実行せよ。ただし alert は使用禁止。',
        'template': "<a href='#' onclick='logClick('{}')'>リンク</a>",
        'vulnerable': True,
        'context': 'attr_escape_escape',
        'filter_script': True,
        'blocked_keywords': ['alert','"','>']
    },
    {
        'id': 11,
        'title': 'eval(atob(...)) 経由でのスクリプト実行 (alert/prompt/confirm禁止)',
        'description': 'scriptタグ内に反射されるが、evalからしか開始できず、alert/prompt/confirmは禁止されている。Base64でコードを埋め込み、eval → atob の流れで実行を試みよ。禁則文字:alert prompt confirm> <',
        'template': '<script>{}</script>',
        'vulnerable': True,
        'context': 'script_eval_b64',
        'filter_script': True,
        'blocked_keywords': ['alert', 'prompt', 'confirm','<','>','\\']
    },
    {
        'id': 12,
        'title': "'で囲まれたonmouseover属性内反射（'は&#39;にサニタイズ）",
        'description': "onmouseover属性内にシングルクォートで囲まれた文字列として反射される。ユーザー入力の' は &#39; に変換されるが、それでも発火する構文を構築せよ。禁則文字:alert prompt confirm > <",
        'template': '<div onmouseover="console.log(\'1{} \');">ホバーしてみて</div>',
        'vulnerable': True,
        'context': 'event_attr_quote_entity',
        'filter_script': True,
        'sanitize_single_quote': True,
        'blocked_keywords': ['alert', 'prompt', 'confirm','<','>']
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
    app.run(host='0.0.0.0', port=10000)
