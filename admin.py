from flask import Blueprint, render_template
from auth import login_required


admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
def admin_dashboard():
    # Add logic for admin dashboard here
    return render_template('admin/dashboard.html')

@admin_bp.route('/manage_users')
def manage_users():
    # Add logic for managing users here
    return render_template('admin/manage_users.html')
