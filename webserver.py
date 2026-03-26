from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost/postgres'
db = SQLAlchemy(app)

class ComputerInfo(db.Model):
    __tablename__ = 'computerinfo'
    id = db.Column(db.Integer, primary_key=True)
    snapshotid = db.Column(db.Integer, db.ForeignKey('systemsnapshots.snapshotid'))
    csname = db.Column(db.String(255), nullable=False)

class SystemSnapshots(db.Model):
    __tablename__ = 'systemsnapshots'
    snapshotid = db.Column(db.Integer, primary_key=True)
    systemuuid = db.Column(db.String(255))
    snapshottime = db.Column(db.DateTime)

@app.route('/')
def index():
    systems = db.session.query(ComputerInfo.csname).distinct().all()
    times = db.session.query(SystemSnapshots.snapshottime).distinct().all()
    return render_template('index.html', systems=systems, times=times)

@app.route('/filter', methods=['POST'])
def filter():
    system = request.form.get('system')
    time = request.form.get('time')
    latest_time = request.form.get('latest_time')

    if latest_time:
        snapshots = SystemSnapshots.query.join(
            ComputerInfo, ComputerInfo.snapshotid == SystemSnapshots.snapshotid
        ).filter(ComputerInfo.csname == system).order_by(SystemSnapshots.snapshottime.desc()).first()
    else:
        snapshots = SystemSnapshots.query.join(
            ComputerInfo, ComputerInfo.snapshotid == SystemSnapshots.snapshotid
        ).filter(ComputerInfo.csname == system, SystemSnapshots.snapshottime == time).all()

    return render_template('filter.html', snapshots=snapshots)

if __name__ == '__main__':
    app.run(debug=True)