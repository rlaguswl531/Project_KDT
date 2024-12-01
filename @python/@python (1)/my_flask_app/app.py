from flask import Flask, render_template, request, redirect, flash, session, url_for, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.recaptcha import RecaptchaField
from flask_socketio import SocketIO
import requests
import boto3
import json
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# 기본 설정
app.secret_key = 'E4rSE8GqcU4s3xVe63g9N/7ur5b6RtdN+xl3UQEz'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcPMIoqAAAAAMUKzcffSZb3H8XXBeoIzYKBbcOM'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcPMIoqAAAAAJ1lsX73z3sK6iKrpRKyhFIx6EAO'

# 확장 라이브러리 설정
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# AWS 클라이언트 설정
ec2 = boto3.client('ec2', region_name='ap-northeast-2')
cloudwatch = boto3.client('cloudwatch', region_name='ap-northeast-2')
logs = boto3.client('logs', region_name='ap-northeast-2')  # CloudWatch Logs client

# 사용자 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# 로그인 폼 정의
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

# 데이터베이스 초기화
with app.app_context():
    db.create_all()

def fetch_ec2_metrics():
    metrics = []
    
    try:
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                status = "운영 중" if instance['State']['Name'] == 'running' else "중지됨"
                
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'Unnamed')

                # CPU 사용량
                cpu_data = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                    EndTime=datetime.now(timezone.utc),
                    Period=60,
                    Statistics=['Average']
                )
                cpu = round(cpu_data['Datapoints'][-1]['Average'], 2) if cpu_data['Datapoints'] else 0

                # RAM 사용량
                ram_data = cloudwatch.get_metric_statistics(
                    Namespace='CWAgent',
                    MetricName='mem_used_percent',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                    EndTime=datetime.now(timezone.utc),
                    Period=60,
                    Statistics=['Average']
                )
                ram = round(ram_data['Datapoints'][-1]['Average'], 2) if ram_data['Datapoints'] else 0

                # 디스크 사용량
                disk_data = cloudwatch.get_metric_statistics(
                    Namespace='CWAgent',
                    MetricName='disk_used_percent',  # 디스크 사용량 메트릭 이름 수정
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                    EndTime=datetime.now(timezone.utc),
                    Period=60,
                    Statistics=['Average']
                )
                disk = round(disk_data['Datapoints'][-1]['Average'], 2) if disk_data['Datapoints'] else 0

                # 네트워크 트래픽
                network_in_data = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='NetworkIn',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                    EndTime=datetime.now(timezone.utc),
                    Period=60,
                    Statistics=['Sum']
                )
                network_out_data = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='NetworkOut',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                    EndTime=datetime.now(timezone.utc),
                    Period=60,
                    Statistics=['Sum']
                )
                network_in = round(network_in_data['Datapoints'][-1]['Sum'], 2) if network_in_data['Datapoints'] else 0
                network_out = round(network_out_data['Datapoints'][-1]['Sum'], 2) if network_out_data['Datapoints'] else 0

                metrics.append({
                    "instance_id": instance_id,
                    "name": name,
                    "status": status,
                    "cpu": cpu,
                    "disk": disk,  # 디스크 사용량
                    "ram": ram,    # RAM 사용량
                    "network": network_in,  # 네트워크 입력
                })
    except Exception as e:
        print(f"Error fetching metrics: {e}")
    return metrics

def get_cloudwatch_logs():
    log_group = '/aws/ec2/cpu-usage'  # 로그 그룹 이름을 올바르게 지정
    log_stream = 'cpu-usage-log'  # 로그 스트림 이름도 확인 필요

    # 로그 이벤트 가져오기
    response = logs.filter_log_events(
        logGroupName=log_group,
        logStreamNames=[log_stream],
        startTime=int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp() * 1000),  # 최근 5분 동안의 로그
        endTime=int(datetime.now(timezone.utc).timestamp() * 1000),
    )

    log_data = []
    for event in response['events']:
        log_data.append({
            'timestamp': event['timestamp'],
            'message': event['message']
        })

    return log_data

# 클라이언트 요청 시 실시간 데이터 전송
@socketio.on('request_data')
def send_metrics():
    data = fetch_ec2_metrics()
    if not data:
        print("No metrics data available.")
    else:
        print("Sending metrics data:", data)  # 전송할 데이터 확인
    socketio.emit('update_table', data)

# 로그 데이터를 반환하는 API
@app.route('/logs')
def logs_data():
    logs_data = get_cloudwatch_logs()  # 로그 데이터 가져오기
    return jsonify({'logs': logs_data})

# 기본 라우트들
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            flash('로그인 성공!')
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('로그인 실패! 사용자 이름이나 비밀번호를 확인하세요.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        if User.query.filter_by(username=username).first():
            flash('이미 등록된 사용자입니다.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('회원가입 완료!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        logs_data = get_cloudwatch_logs()  # Fetch logs for monitoring display
        return render_template('dashboard.html', username=session['username'], logs=logs_data)
    else:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))

@app.route('/grafana_proxy')
def grafana_dashboard():
    grafana_url = "https://g-0fcccca017.grafana-workspace.ap-northeast-2.amazonaws.com/d/ee56suif3e874f/new-dashboard?orgId=1&from=1732846705424&to=1732850305424"
    headers = {"Authorization": "Bearer glsa_YBJE8Cxvgd3oSHBD3tytrDYUOTqJ0IRX_1e7b7ad0"}

    try:
        grafana_response = requests.get(grafana_url, headers=headers)
        if grafana_response.status_code == 200:
            return Response(
                grafana_response.content,
                status=grafana_response.status_code,
                content_type=grafana_response.headers.get('Content-Type')
            )
        else:
            return f"Failed to fetch Grafana: {grafana_response.status_code}", grafana_response.status_code
    except Exception as e:
        return f"Error connecting to Grafana: {str(e)}", 500

@app.route('/grafana_api_data')
def grafana_api_data():
    grafana_url = "https://g-0fcccca017.grafana-workspace.ap-northeast-2.amazonaws.com/api/dashboards/uid/ee56suif3e874f"
    headers = {"Authorization": "Bearer glsa_YBJE8Cxvgd3oSHBD3tytrDYUOTqJ0IRX_1e7b7ad0"}

    try:
        response = requests.get(grafana_url, headers=headers)
        print(f"Response Status: {response.status_code}")  # 상태 코드 출력
        if response.status_code == 200:
            data = response.json()
            print(f"Response Data: {data}")  # 응답 데이터 출력
            # 패널 데이터 추출
            panels = data.get('dashboard', {}).get('panels', [])
            processed_data = []

            for panel in panels:
                if panel['type'] == 'barchart':
                    # 패널 제목 및 데이터 추출
                    processed_data.append({
                        "title": panel['title'],
                        "targets": panel['targets']
                    })

            return {"panels": processed_data}, 200  # 성공적으로 패널 데이터 반환
        else:
            print(f"Error: {response.text}")  # 오류 메시지 출력
            return {"error": f"Failed to fetch Grafana: {response.status_code}"}, response.status_code
    except Exception as e:
        print(f"Error connecting to Grafana: {str(e)}")  # 예외 메시지 출력
        return {"error": f"Error connecting to Grafana: {str(e)}"}, 500

@app.route('/api/ec2_instances')
def get_ec2_instances():
    instances_info = []
    try:
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'Unnamed')
                instances_info.append({"id": instance_id, "name": name})
    except Exception as e:
        print(f"Error fetching EC2 instances: {e}")
        return {"error": str(e)}, 500

    return {"instances": instances_info}

# 추가 라우트
@app.route('/forgot-password', methods=['GET', 'POST'])
def find():
    return render_template('forgot-password.html')

@app.route('/user_info')
def user_info():
    return render_template('user_info.html')

@app.route('/dashboard2')
def dashboard2():
    return render_template('dashboard2.html')

@app.route('/dashboard3')
def dashboard3():
    return render_template('dashboard3.html')

@app.route('/dashboard4')
def dashboard4():
    return render_template('dashboard4.html')

@app.route('/security_alerts')
def security_alerts():
    return render_template('security_alerts.html')

@app.route('/full_monitoring')
def full_monitoring():
    return render_template('full_monitoring.html')

@app.route('/api_monitoring')
def api_monitoring():
    return render_template('api_monitoring.html')

@app.route('/aws_integration')
def aws_integration():
    return render_template('aws_integration.html')

@app.route('/account_management')
def account_management():
    return render_template('account_management.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
