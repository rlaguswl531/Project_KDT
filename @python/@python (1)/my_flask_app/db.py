from flask import Flask, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

# Flask 애플리케이션 생성
app = Flask(__name__)

# 비밀 키 설정 (세션 관리용)
app.secret_key = 'your_secret_key'

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 경고 메시지 비활성화

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 사용자 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 가입일 필드 추가

# 사용자 정보 페이지 라우트 정의
@app.route('/user-info')
def user_info():
    # 세션에서 로그인된 사용자 확인
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()  # 사용자 정보 조회
        if user:
            return render_template(
                'user_info.html',
                username=user.username,
                email=user.email,
                join_date=user.created_at.strftime('%Y-%m-%d %H:%M:%S')  # 가입일 표시 (포맷팅)
            )
    else:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

# 로그인 페이지 라우트 정의 (테스트용 간단한 HTML 반환)
@app.route('/login')
def login():
    return '<h1>로그인 페이지</h1>'

# 로그아웃 라우트 정의
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)  # 세션에서 사용자 이름 제거
    flash('로그아웃 되었습니다.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)