from flask import Blueprint, render_template, make_response, request
from io import StringIO
import csv
from app import VisitLog, User, db
from flask_login import login_required, current_user
from auth import check_rights

bp = Blueprint('reports', __name__)

@bp.route('/visits')
@login_required
def visits():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if current_user.role.name == 'admin':
        query = VisitLog.query
    else:
        query = VisitLog.query.filter_by(user_id=current_user.id)
        
    visits = query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('reports/visits.html', visits=visits)

@bp.route('/visits/pages')
@login_required
@check_rights('admin')
def pages_stats():
    stats = db.session.query(
        VisitLog.path,
        db.func.count(VisitLog.id).label('count')
    ).group_by(VisitLog.path).order_by(db.desc('count')).all()
    
    if 'export' in request.args:
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Страница', 'Количество посещений'])
        cw.writerows(stats)
        
        output = make_response(si.getvalue().encode('utf-8-sig'))
        output.headers["Content-Disposition"] = "attachment; filename=pages_stats.csv"
        return output
        
    return render_template('reports/pages_stats.html', stats=stats)

@bp.route('/visits/users')
@login_required
@check_rights('admin')
def users_stats():
    stats = db.session.query(
        User.last_name,
        User.first_name,
        db.func.count(VisitLog.id).label('count')
    ).join(VisitLog).group_by(User.id).order_by(db.desc('count')).all()
    
    if 'export' in request.args:
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Пользователь', 'Количество посещений'])
        for stat in stats:
            cw.writerow([f"{stat.last_name} {stat.first_name}", stat.count])
        
        output = make_response(si.getvalue().encode('utf-8-sig'))
        output.headers["Content-Disposition"] = "attachment; filename=users_stats.csv"
        return output
        
    return render_template('reports/users_stats.html', stats=stats)