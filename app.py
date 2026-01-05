import os
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for, make_response
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
import json
import csv
import io
from urllib.parse import urlparse

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Jinja2 custom filters
@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    if not value:
        return []
    try:
        return json.loads(value)
    except:
        return []

# Context processor to make is_admin available in all templates
@app.context_processor
def inject_is_admin():
    """Make is_admin available in all templates"""
    # Check session first for performance, then verify with database
    if session.get("is_admin"):
        return dict(is_admin=True)
    return dict(is_admin=is_admin_user())

# Database helper functions
class PostgresRow:
    """Make PostgreSQL rows work like SQLite rows"""
    def __init__(self, data):
        self._data = dict(data)
    def __getitem__(self, key):
        return self._data[key]
    def __contains__(self, key):
        return key in self._data
    def get(self, key, default=None):
        return self._data.get(key, default)
    def keys(self):
        return self._data.keys()
    def __iter__(self):
        return iter(self._data)
    def __getattr__(self, name):
        return self._data.get(name)

class PostgresCursor:
    """Wrapper to make PostgreSQL cursor work like SQLite cursor"""
    def __init__(self, cursor, conn):
        self.cursor = cursor
        self.conn = conn
        self._lastrowid = None
    
    def fetchone(self):
        result = self.cursor.fetchone()
        if result:
            return PostgresRow(dict(result))
        return None
    
    def fetchall(self):
        results = self.cursor.fetchall()
        return [PostgresRow(dict(r)) for r in results]
    
    def lastrowid(self):
        # For PostgreSQL, we need to get the ID from the RETURNING clause
        # If _lastrowid was set, return it
        if self._lastrowid is not None:
            return self._lastrowid
        # Otherwise try to get from cursor (won't work for PostgreSQL)
        return getattr(self.cursor, 'lastrowid', None)
    
    def set_lastrowid(self, rowid):
        self._lastrowid = rowid

class PostgresConnection:
    """Wrapper to make PostgreSQL connection work like SQLite connection"""
    def __init__(self, conn):
        self.conn = conn
        self.row_factory = None
    
    def execute(self, query, params=None):
        from psycopg2.extras import RealDictCursor
        
        # Handle PRAGMA table_info (SQLite-specific) - convert to PostgreSQL equivalent
        if query.strip().upper().startswith('PRAGMA TABLE_INFO'):
            # Extract table name from PRAGMA table_info(table_name)
            import re
            match = re.search(r'PRAGMA\s+table_info\((\w+)\)', query, re.IGNORECASE)
            if match:
                table_name = match.group(1)
                # Convert to PostgreSQL information_schema query
                # SQLite PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
                pg_query = """
                    SELECT 
                        ordinal_position - 1 as cid,
                        column_name as name,
                        data_type as type,
                        CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END as notnull,
                        column_default as dflt_value,
                        0 as pk
                    FROM information_schema.columns
                    WHERE table_name = %s
                    ORDER BY ordinal_position
                """
                cursor = self.conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute(pg_query, (table_name,))
                return PostgresCursor(cursor, self.conn)
        
        # Skip other PRAGMA statements (SQLite-specific, not supported in PostgreSQL)
        if query.strip().upper().startswith('PRAGMA'):
            # Return a dummy cursor that does nothing
            class DummyCursor:
                def fetchone(self):
                    return None
                def fetchall(self):
                    return []
                def lastrowid(self):
                    return None
            return PostgresCursor(DummyCursor(), self.conn)
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        # Convert SQLite DDL to PostgreSQL DDL for CREATE TABLE statements
        if query.strip().upper().startswith('CREATE TABLE'):
            # Convert SQLite-specific syntax to PostgreSQL
            query = query.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
            query = query.replace('AUTOINCREMENT', '')
        
        # Convert SQLite placeholders (?) to PostgreSQL placeholders (%s)
        # For INSERT queries, add RETURNING id to get the last inserted ID
        original_query = query
        is_insert = query.strip().upper().startswith('INSERT')
        needs_returning = is_insert and 'RETURNING' not in query.upper()
        
        if params:
            # Replace ? with %s in query (simple replacement, works for most cases)
            query = query.replace('?', '%s')
            if needs_returning:
                # Add RETURNING id to get the inserted ID
                query = query.rstrip(';') + ' RETURNING id'
            cursor.execute(query, params)
        else:
            if needs_returning:
                query = query.rstrip(';') + ' RETURNING id'
            cursor.execute(query)
        
        pg_cursor = PostgresCursor(cursor, self.conn)
        
        # If it's an INSERT with RETURNING, fetch the ID
        if needs_returning:
            result = cursor.fetchone()
            if result:
                pg_cursor.set_lastrowid(result['id'])
        
        return pg_cursor
    
    def commit(self):
        self.conn.commit()
    
    def close(self):
        self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

def get_db():
    """Get database connection - supports both SQLite (local) and PostgreSQL (Railway)"""
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Use PostgreSQL on Railway
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            # Parse DATABASE_URL (Railway format: postgresql://user:pass@host:port/dbname)
            # Convert to psycopg2 format if needed
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg2.connect(database_url, sslmode='require')
            # Wrap in PostgresConnection to make it work like SQLite
            db = PostgresConnection(conn)
            # Create a custom row factory that returns PostgresRow objects
            def row_factory(cursor, row):
                return PostgresRow(dict(row))
            db.row_factory = row_factory
            return db
        except ImportError:
            # Fallback to SQLite if psycopg2 not available
            pass
        except Exception as e:
            print(f"Error connecting to PostgreSQL: {e}")
            # Fallback to SQLite
            pass
    
    # Use SQLite for local development
    db = sqlite3.connect('database.db', timeout=10.0)
    db.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency (allows multiple readers)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.commit()
    except:
        pass  # Ignore if WAL mode can't be set
    return db

def init_db():
    """Initialize database with schema"""
    db = get_db()
    
    # Users table
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)
    
    # Add is_admin column to existing users table if it doesn't exist (migration)
    try:
        cursor = db.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'is_admin' not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            db.commit()
        
        # Make the first user an admin if no admins exist (run this check every time)
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if admin_count == 0:
            first_user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
            if first_user:
                db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user["id"],))
                db.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists or table doesn't exist yet
    
    # Sections table
    db.execute("""
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    # Categories table
    db.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            section_id INTEGER,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE SET NULL
        )
    """)
    
    # Add section_id column to existing categories table if it doesn't exist (migration)
    try:
        cursor = db.execute("PRAGMA table_info(categories)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'section_id' not in columns:
            db.execute("ALTER TABLE categories ADD COLUMN section_id INTEGER")
            db.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists or table doesn't exist yet
    
    # Fields table (custom fields for categories)
    db.execute("""
        CREATE TABLE IF NOT EXISTS fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            field_type TEXT NOT NULL,
            options TEXT,
            required INTEGER DEFAULT 0,
            display_order INTEGER DEFAULT 0,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
        )
    """)
    
    # Entities table
    db.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
        )
    """)
    
    # Tags table - now category-specific
    db.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            color TEXT DEFAULT '#007bff',
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
        )
    """)
    
    # Migrate tags table to remove user_id and use category_id only
    try:
        # Check if user_id column exists (old schema)
        cursor = db.execute("PRAGMA table_info(tags)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'user_id' in columns:
            # Old schema exists - need to recreate table without user_id
            # First, ensure category_id exists
            if 'category_id' not in columns:
                db.execute("ALTER TABLE tags ADD COLUMN category_id INTEGER")
                db.execute("UPDATE tags SET category_id = (SELECT id FROM categories WHERE user_id = tags.user_id LIMIT 1) WHERE category_id IS NULL")
            
            # Create new table with correct schema (no user_id)
            db.execute("""
                CREATE TABLE tags_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    color TEXT DEFAULT '#007bff',
                    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
                )
            """)
            
            # Copy data from old table to new table
            db.execute("""
                INSERT INTO tags_new (id, category_id, name, color)
                SELECT id, category_id, name, COALESCE(color, '#007bff')
                FROM tags
                WHERE category_id IS NOT NULL
            """)
            
            # Drop old table
            db.execute("DROP TABLE tags")
            # Rename new table
            db.execute("ALTER TABLE tags_new RENAME TO tags")
            db.commit()
        elif 'category_id' not in columns:
            # Add category_id if it doesn't exist
            db.execute("ALTER TABLE tags ADD COLUMN category_id INTEGER")
            db.execute("UPDATE tags SET category_id = (SELECT id FROM categories WHERE user_id = tags.user_id LIMIT 1) WHERE category_id IS NULL")
            db.commit()
        
        # Create index
        db.execute("CREATE INDEX IF NOT EXISTS idx_tags_category ON tags(category_id)")
        db.commit()
    except sqlite3.OperationalError as e:
        # Table might not exist yet or migration already done
        pass
    
    # Entity tags junction table
    db.execute("""
        CREATE TABLE IF NOT EXISTS entity_tags (
            entity_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (entity_id, tag_id),
            FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
        )
    """)
    
    # Field values table (stores values for custom fields)
    db.execute("""
        CREATE TABLE IF NOT EXISTS field_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            field_id INTEGER NOT NULL,
            value TEXT,
            FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (field_id) REFERENCES fields(id) ON DELETE CASCADE,
            UNIQUE(entity_id, field_id)
        )
    """)
    
    db.commit()
    db.close()

# Initialize database on first run
init_db()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_admin_user():
    """Check if current logged-in user is an admin"""
    if not session.get("user_id"):
        return False
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    if user and user["is_admin"]:
        return True
    return False

def require_admin():
    """Decorator-like function to require admin access"""
    if not session.get("user_id"):
        return redirect("/login")
    if not is_admin_user():
        flash("Access denied. Admin privileges required.")
        return redirect("/dashboard")
    return None

@app.route("/")
def index():
    """Show homepage"""
    if not session.get("user_id"):
        return redirect("/login")
    return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Must provide username and password")
            return render_template("login.html")
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()
        
        if not user or not check_password_hash(user["hash"], password):
            flash("Invalid username and/or password")
            return render_template("login.html")
        
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        # Store admin status in session for quick access
        try:
            session["is_admin"] = bool(user["is_admin"] if user["is_admin"] is not None else 0)
        except (KeyError, IndexError):
            session["is_admin"] = False
        return redirect("/dashboard")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not username or not password or not confirmation:
            flash("Must provide username, password, and confirmation")
            return render_template("register.html")
        
        if password != confirmation:
            flash("Passwords do not match")
            return render_template("register.html")
        
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists")
            db.close()
            return render_template("register.html")
        
        db.close()
        flash("Registration successful! Please log in.")
        return redirect("/login")
    
    return render_template("register.html")

@app.route("/set-admin")
def set_admin():
    """Set first user as admin - no authentication required (temporary route for initial setup)"""
    db = get_db()
    
    # Make first user admin if no admins exist
    admin_count = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
    if admin_count == 0:
        first_user = db.execute("SELECT id, username FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user:
            db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user["id"],))
            db.commit()
            db.close()
            return f"""<html><body style="font-family: Arial, sans-serif; padding: 20px; text-align: center;">
                <h2>✅ Admin Access Granted</h2>
                <p>Admin privileges have been granted to the first user: <strong>{first_user['username']}</strong> (ID: {first_user['id']})</p>
                <p><a href="/login" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Go to Login</a></p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">⚠️ Remember to remove or protect this route after use!</p>
            </body></html>"""
        else:
            db.close()
            return """<html><body style="font-family: Arial, sans-serif; padding: 20px; text-align: center;">
                <h2>❌ No Users Found</h2>
                <p>No users found in database. Please register a user first.</p>
                <p><a href="/register" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Go to Register</a></p>
            </body></html>"""
    else:
        db.close()
        return f"""<html><body style="font-family: Arial, sans-serif; padding: 20px; text-align: center;">
            <h2>✅ Admin System Active</h2>
            <p>Admin system is working. Current admins: <strong>{admin_count}</strong></p>
            <p><a href="/admin" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">Go to Admin Panel</a></p>
        </body></html>"""

@app.route("/fix-admin")
def fix_admin():
    """Fix admin status for first user - diagnostic route (admin only)"""
    # Require admin access
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    
    # Make first user admin if no admins exist
    admin_count = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
    if admin_count == 0:
        first_user = db.execute("SELECT id, username FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user:
            db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user["id"],))
            db.commit()
            flash(f"Admin privileges granted to first user: {first_user['username']} (ID: {first_user['id']})")
        else:
            flash("No users found in database")
    else:
        flash(f"Admin system is working. Current admins: {admin_count}")
    
    db.close()
    return redirect("/admin")

@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    """Show user dashboard with sections and categories"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    
    # Get all sections for this user
    sections = db.execute(
        "SELECT * FROM sections WHERE user_id = ? ORDER BY display_order, created_at",
        (session["user_id"],)
    ).fetchall()
    
    # Get categories not in any section
    unassigned_categories = db.execute(
        "SELECT * FROM categories WHERE user_id = ? AND section_id IS NULL ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    
    # Get categories for each section
    sections_with_categories = []
    for section in sections:
        categories = db.execute(
            "SELECT * FROM categories WHERE section_id = ? ORDER BY created_at DESC",
            (section["id"],)
        ).fetchall()
        sections_with_categories.append({
            "section": dict(section),
            "categories": [dict(cat) for cat in categories]
        })
    
    db.close()
    
    return render_template("dashboard.html", 
                         sections_with_categories=sections_with_categories,
                         unassigned_categories=[dict(cat) for cat in unassigned_categories])

@app.route("/category/new", methods=["GET", "POST"])
def new_category():
    """Create new category"""
    if not session.get("user_id"):
        return redirect("/login")
    
    if request.method == "POST":
        name = request.form.get("name")
        if not name:
            flash("Category name is required")
            return render_template("new_category.html")
        
        db = get_db()
        db.execute(
            "INSERT INTO categories (user_id, name) VALUES (?, ?)",
            (session["user_id"], name)
        )
        db.commit()
        db.close()
        
        flash("Category created successfully!")
        return redirect("/dashboard")
    
    return render_template("new_category.html")

@app.route("/section/new", methods=["GET", "POST"])
def new_section():
    """Create new section"""
    if not session.get("user_id"):
        return redirect("/login")
    
    if request.method == "POST":
        name = request.form.get("name")
        if not name:
            flash("Section name is required")
            return render_template("new_section.html")
        
        db = get_db()
        # Get max display_order
        max_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) FROM sections WHERE user_id = ?",
            (session["user_id"],)
        ).fetchone()[0]
        
        db.execute(
            "INSERT INTO sections (user_id, name, display_order) VALUES (?, ?, ?)",
            (session["user_id"], name, max_order + 1)
        )
        db.commit()
        db.close()
        
        flash("Section created successfully!")
        return redirect("/dashboard")
    
    return render_template("new_section.html")

@app.route("/section/<int:section_id>/update", methods=["POST"])
def update_section(section_id):
    """Update section name"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    section = db.execute(
        "SELECT * FROM sections WHERE id = ? AND user_id = ?",
        (section_id, session["user_id"])
    ).fetchone()
    
    if not section:
        flash("Section not found")
        db.close()
        return redirect("/dashboard")
    
    name = request.form.get("name")
    if not name or not name.strip():
        flash("Section name cannot be empty")
        db.close()
        return redirect("/dashboard")
    
    db.execute(
        "UPDATE sections SET name = ? WHERE id = ? AND user_id = ?",
        (name.strip(), section_id, session["user_id"])
    )
    db.commit()
    db.close()
    
    flash("Section name updated successfully!")
    return redirect("/dashboard")

@app.route("/section/<int:section_id>/delete", methods=["POST"])
def delete_section(section_id):
    """Delete section"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    section = db.execute(
        "SELECT * FROM sections WHERE id = ? AND user_id = ?",
        (section_id, session["user_id"])
    ).fetchone()
    
    if not section:
        flash("Section not found")
        db.close()
        return redirect("/dashboard")
    
    # Categories will be unassigned (section_id set to NULL) due to ON DELETE SET NULL
    db.execute("DELETE FROM sections WHERE id = ?", (section_id,))
    db.commit()
    db.close()
    
    flash("Section deleted successfully!")
    return redirect("/dashboard")

@app.route("/category/<int:category_id>/move", methods=["POST"])
def move_category(category_id):
    """Move category to a section"""
    if not session.get("user_id"):
        return redirect("/login")
    
    section_id = request.form.get("section_id")
    if section_id == "" or section_id == "none":
        section_id = None
    elif section_id:
        section_id = int(section_id)
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    # If section_id is provided, verify it belongs to user
    if section_id:
        section = db.execute(
            "SELECT * FROM sections WHERE id = ? AND user_id = ?",
            (section_id, session["user_id"])
        ).fetchone()
        if not section:
            flash("Section not found")
            db.close()
            return redirect("/dashboard")
    
    db.execute(
        "UPDATE categories SET section_id = ? WHERE id = ?",
        (section_id, category_id)
    )
    db.commit()
    db.close()
    
    flash("Category moved successfully!")
    return redirect("/dashboard")

@app.route("/category/<int:category_id>")
def view_category(category_id):
    """View category with entities"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        return redirect("/dashboard")
    
    entities = db.execute(
        "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    tags = db.execute(
        "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    # Get tags and field values for each entity
    entities_with_tags = []
    try:
        for entity in entities:
            entity_id = entity["id"]
            entity_tags = db.execute(
                """SELECT t.* FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_id = ?""",
                (entity_id,)
            ).fetchall()
            
            # Get field values for this entity - use integer keys for consistency
            entity_field_values = {}
            primary_image = None  # Find first image field value
            
            for field in fields:
                field_id = int(field["id"])  # Ensure field_id is integer
                value = db.execute(
                    "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                    (entity_id, field_id)
                ).fetchone()
                field_value = value["value"] if value else ""
                entity_field_values[field_id] = field_value
                
                # Store first image found as primary image
                if not primary_image and field["field_type"] == "image" and field_value:
                    primary_image = field_value
            
            # Convert Row objects to dictionaries
            entity_dict = {
                "id": entity["id"],
                "category_id": entity["category_id"],
                "name": entity["name"],
                "created_at": entity["created_at"],
                "updated_at": entity["updated_at"]
            }
            
            entities_with_tags.append({
                "entity": entity_dict,
                "tags": [{"id": tag["id"], "name": tag["name"], "color": tag["color"]} for tag in entity_tags],
                "field_values": entity_field_values,
                "primary_image": primary_image  # Add primary image for easy access
            })
    except Exception as e:
        print(f"ERROR building entities_with_tags: {e}")
        import traceback
        traceback.print_exc()
    
    db.close()
    
    # Debug: Print entity count
    print(f"DEBUG: Category {category_id} has {len(entities_with_tags)} entities")
    print(f"DEBUG: entities_with_tags type: {type(entities_with_tags)}")
    if entities_with_tags:
        print(f"DEBUG: First entity structure: {entities_with_tags[0]}")
    
    # Convert fields to dictionaries with integer IDs
    fields_list = []
    for f in fields:
        fields_list.append({
            "id": int(f["id"]),  # Ensure ID is integer
            "label": f["label"],
            "field_type": f["field_type"],
            "options": f["options"] if f["options"] else "",
            "required": f["required"]
        })
    
    return render_template("category.html", 
                         category={"id": category["id"], "name": category["name"], "created_at": category["created_at"]}, 
                         entities_with_tags=entities_with_tags,
                         fields=fields_list,
                         all_tags=[{"id": t["id"], "name": t["name"], "color": t["color"]} for t in tags])

@app.route("/category/<int:category_id>/fields", methods=["GET", "POST"])
def manage_fields(category_id):
    """Manage fields for a category"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        return redirect("/dashboard")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            label = request.form.get("label")
            field_type = request.form.get("field_type")
            options = request.form.get("options", "")
            required = 1 if request.form.get("required") else 0
            
            if not label or not field_type:
                flash("Label and field type are required")
            else:
                # Get max display_order
                max_order = db.execute(
                    "SELECT COALESCE(MAX(display_order), 0) FROM fields WHERE category_id = ?",
                    (category_id,)
                ).fetchone()[0]
                
                db.execute(
                    """INSERT INTO fields (category_id, label, field_type, options, required, display_order)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (category_id, label, field_type, options, required, max_order + 1)
                )
                db.commit()
                flash("Field added successfully!")
        
        elif action == "edit":
            field_id = request.form.get("field_id")
            label = request.form.get("label")
            field_type = request.form.get("field_type")
            options = request.form.get("options", "")
            required = 1 if request.form.get("required") else 0
            
            db.execute(
                """UPDATE fields SET label = ?, field_type = ?, options = ?, required = ?
                   WHERE id = ? AND category_id = ?""",
                (label, field_type, options, required, field_id, category_id)
            )
            db.commit()
            flash("Field updated successfully!")
        
        elif action == "delete":
            field_id = request.form.get("field_id")
            db.execute("DELETE FROM fields WHERE id = ? AND category_id = ?", 
                      (field_id, category_id))
            db.commit()
            flash("Field deleted successfully!")
        
        elif action == "reorder":
            order_data = json.loads(request.form.get("order", "[]"))
            for idx, field_id in enumerate(order_data):
                db.execute(
                    "UPDATE fields SET display_order = ? WHERE id = ? AND category_id = ?",
                    (idx, field_id, category_id)
                )
            db.commit()
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    db.close()
    
    return render_template("manage_fields.html", category=category, fields=fields)

@app.route("/category/<int:category_id>/entity/new", methods=["GET", "POST"])
def new_entity(category_id):
    """Create new entity"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    tags = db.execute(
        "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    if request.method == "POST":
        name = request.form.get("name")
        if not name:
            flash("Entity name is required")
            db.close()
            return render_template("new_entity.html", category=category, fields=fields, tags=tags)
        
        # Create entity
        cursor = db.execute(
            "INSERT INTO entities (category_id, name) VALUES (?, ?)",
            (category_id, name)
        )
        entity_id = cursor.lastrowid
        
        # Save field values
        for field in fields:
            field_id = field["id"]
            value = request.form.get(f"field_{field_id}")
            
            # Handle checkbox_list (multiple selections)
            if field["field_type"] == "checkbox_list":
                selected_values = request.form.getlist(f"field_{field_id}")
                value = ",".join(selected_values) if selected_values else ""
            
            # Handle file uploads
            if field["field_type"] == "image":
                file = request.files.get(f"field_{field_id}")
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(f"{entity_id}_{field_id}_{file.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    value = filename
            
            elif field["field_type"] == "image_album":
                # Handle multiple image uploads
                files = request.files.getlist(f"field_{field_id}")
                image_filenames = []
                
                for file in files:
                    if file and file.filename and allowed_file(file.filename):
                        filename = secure_filename(f"{entity_id}_{field_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        image_filenames.append(filename)
                
                if image_filenames:
                    value = json.dumps(image_filenames)
                else:
                    value = ""
            
            if value or field["required"]:
                db.execute(
                    "INSERT OR REPLACE INTO field_values (entity_id, field_id, value) VALUES (?, ?, ?)",
                    (entity_id, field_id, value or "")
                )
        
        # Save tags
        selected_tags = request.form.getlist("tags")
        for tag_id in selected_tags:
            db.execute(
                "INSERT OR IGNORE INTO entity_tags (entity_id, tag_id) VALUES (?, ?)",
                (entity_id, int(tag_id))
            )
        
        db.commit()
        db.close()
        
        flash("Entity created successfully!")
        return redirect(url_for("view_category", category_id=category_id))
    
    db.close()
    return render_template("new_entity.html", category=category, fields=fields, tags=tags)

@app.route("/category/<int:category_id>/entity/<int:entity_id>/edit", methods=["GET", "POST"])
def edit_entity(category_id, entity_id):
    """Edit entity"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    entity = db.execute(
        "SELECT * FROM entities WHERE id = ? AND category_id = ?",
        (entity_id, category_id)
    ).fetchone()
    
    if not entity:
        flash("Entity not found")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    # Get current field values
    field_values = {}
    for field in fields:
        value = db.execute(
            "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
            (entity_id, field["id"])
        ).fetchone()
        field_values[field["id"]] = value["value"] if value else ""
    
    # Get current tags
    entity_tags = db.execute(
        """SELECT tag_id FROM entity_tags WHERE entity_id = ?""",
        (entity_id,)
    ).fetchall()
    entity_tag_ids = [row["tag_id"] for row in entity_tags]
    
    tags = db.execute(
        "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    if request.method == "POST":
        name = request.form.get("name")
        if not name:
            flash("Entity name is required")
            db.close()
            return render_template("edit_entity.html", 
                                 category=category, entity=entity, 
                                 fields=fields, field_values=field_values,
                                 tags=tags, entity_tag_ids=entity_tag_ids)
        
        # Update entity
        db.execute(
            "UPDATE entities SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (name, entity_id)
        )
        
        # Update field values
        for field in fields:
            field_id = field["id"]
            value = request.form.get(f"field_{field_id}")
            
            # Handle checkbox_list (multiple selections)
            if field["field_type"] == "checkbox_list":
                selected_values = request.form.getlist(f"field_{field_id}")
                value = ",".join(selected_values) if selected_values else ""
            
            # Handle file uploads
            if field["field_type"] == "image":
                file = request.files.get(f"field_{field_id}")
                if file and file.filename and allowed_file(file.filename):
                    # Delete old file if exists
                    old_value = field_values.get(field_id)
                    if old_value:
                        old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_value)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    
                    filename = secure_filename(f"{entity_id}_{field_id}_{file.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    value = filename
                else:
                    value = field_values.get(field_id, "")
            
            elif field["field_type"] == "image_album":
                # Get existing images (keep list)
                existing_images = []
                keep_images = request.form.getlist(f"keep_image_{field_id}")
                for keep_img in keep_images:
                    if keep_img:
                        existing_images.append(keep_img)
                
                # Get images to delete
                delete_images = request.form.getlist(f"delete_image_{field_id}")
                for del_img in delete_images:
                    if del_img in existing_images:
                        existing_images.remove(del_img)
                    # Delete file from filesystem
                    del_path = os.path.join(app.config['UPLOAD_FOLDER'], del_img)
                    if os.path.exists(del_path):
                        try:
                            os.remove(del_path)
                        except:
                            pass
                
                # Handle new image uploads
                files = request.files.getlist(f"field_{field_id}")
                for file in files:
                    if file and file.filename and allowed_file(file.filename):
                        filename = secure_filename(f"{entity_id}_{field_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        existing_images.append(filename)
                
                if existing_images:
                    value = json.dumps(existing_images)
                else:
                    value = ""
            
            if value or field["required"]:
                db.execute(
                    "INSERT OR REPLACE INTO field_values (entity_id, field_id, value) VALUES (?, ?, ?)",
                    (entity_id, field_id, value or "")
                )
        
        # Update tags
        db.execute("DELETE FROM entity_tags WHERE entity_id = ?", (entity_id,))
        selected_tags = request.form.getlist("tags")
        for tag_id in selected_tags:
            db.execute(
                "INSERT INTO entity_tags (entity_id, tag_id) VALUES (?, ?)",
                (entity_id, int(tag_id))
            )
        
        db.commit()
        db.close()
        
        flash("Entity updated successfully!")
        return redirect(url_for("view_category", category_id=category_id))
    
    db.close()
    return render_template("edit_entity.html", 
                         category=category, entity=entity, 
                         fields=fields, field_values=field_values,
                         tags=tags, entity_tag_ids=entity_tag_ids)

@app.route("/category/<int:category_id>/entity/<int:entity_id>")
def view_entity(category_id, entity_id):
    """View entity details"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    entity = db.execute(
        "SELECT * FROM entities WHERE id = ? AND category_id = ?",
        (entity_id, category_id)
    ).fetchone()
    
    if not entity:
        flash("Entity not found")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    # Get field values
    field_values = {}
    for field in fields:
        value = db.execute(
            "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
            (entity_id, field["id"])
        ).fetchone()
        raw_value = value["value"] if value else ""
        # Strip leading/trailing whitespace for textarea fields
        if field["field_type"] == "textarea" and raw_value:
            # First, strip the entire string to remove leading/trailing whitespace and newlines
            raw_value = raw_value.strip()
            # Then, if there are multiple lines, remove leading whitespace from each line
            if '\n' in raw_value:
                lines = raw_value.split('\n')
                # Remove leading whitespace from each line (but preserve line structure)
                cleaned_lines = [line.lstrip() for line in lines]
                raw_value = '\n'.join(cleaned_lines)
        field_values[field["id"]] = raw_value
    
    # Get tags
    entity_tags = db.execute(
        """SELECT t.* FROM tags t
           JOIN entity_tags et ON t.id = et.tag_id
           WHERE et.entity_id = ?""",
        (entity_id,)
    ).fetchall()
    
    db.close()
    return render_template("view_entity.html", 
                         category=category, entity=entity, 
                         fields=fields, field_values=field_values,
                         tags=entity_tags)

@app.route("/category/<int:category_id>/update", methods=["POST"])
def update_category(category_id):
    """Update category name"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    name = request.form.get("name")
    if not name or not name.strip():
        flash("Category name cannot be empty")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    db.execute(
        "UPDATE categories SET name = ? WHERE id = ? AND user_id = ?",
        (name.strip(), category_id, session["user_id"])
    )
    db.commit()
    db.close()
    
    flash("Category name updated successfully!")
    return redirect(url_for("view_category", category_id=category_id))

@app.route("/category/<int:category_id>/delete", methods=["POST"])
def delete_category(category_id):
    """Delete category"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    # Delete all related data - first get image files before deleting records
    entities = db.execute(
        "SELECT id FROM entities WHERE category_id = ?",
        (category_id,)
    ).fetchall()
    
    # Delete uploaded images before deleting records
    for entity in entities:
        entity_id = entity["id"]
        field_values = db.execute(
            """SELECT fv.value, f.field_type FROM field_values fv
               JOIN fields f ON fv.field_id = f.id
               WHERE fv.entity_id = ? AND (f.field_type = 'image' OR f.field_type = 'image_album')""",
            (entity_id,)
        ).fetchall()
        for row in field_values:
            if row["value"]:
                if row["field_type"] == "image":
                    # Single image
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], row["value"])
                    if os.path.exists(filepath):
                        try:
                            os.remove(filepath)
                        except:
                            pass
                elif row["field_type"] == "image_album":
                    # Multiple images stored as JSON
                    try:
                        image_list = json.loads(row["value"])
                        for img_filename in image_list:
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                            if os.path.exists(filepath):
                                try:
                                    os.remove(filepath)
                                except:
                                    pass
                    except:
                        pass
    
    # Delete the category (entities, fields, tags, field_values, entity_tags will be deleted via CASCADE)
    db.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    db.commit()
    db.close()
    
    flash("Category deleted successfully!")
    return redirect("/dashboard")

@app.route("/category/<int:category_id>/entity/<int:entity_id>/delete", methods=["POST"])
def delete_entity(category_id, entity_id):
    """Delete entity"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    # Delete associated images (single image and image album)
    field_values = db.execute(
        """SELECT fv.value, f.field_type FROM field_values fv
           JOIN fields f ON fv.field_id = f.id
           WHERE fv.entity_id = ? AND (f.field_type = 'image' OR f.field_type = 'image_album')""",
        (entity_id,)
    ).fetchall()
    
    for row in field_values:
        if row["value"]:
            if row["field_type"] == "image":
                # Single image
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], row["value"])
                if os.path.exists(filepath):
                    os.remove(filepath)
            elif row["field_type"] == "image_album":
                # Multiple images stored as JSON
                try:
                    image_list = json.loads(row["value"])
                    for img_filename in image_list:
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                        if os.path.exists(filepath):
                            os.remove(filepath)
                except:
                    pass
    
    db.execute("DELETE FROM entities WHERE id = ? AND category_id = ?", 
              (entity_id, category_id))
    db.commit()
    db.close()
    
    flash("Entity deleted successfully!")
    return redirect(url_for("view_category", category_id=category_id))

@app.route("/category/<int:category_id>/tags", methods=["GET", "POST"])
def manage_tags(category_id):
    """Manage tags for a specific category"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    
    # Verify category belongs to user
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    try:
        if request.method == "POST":
            action = request.form.get("action")
            
            if action == "create":
                name = request.form.get("name")
                color = request.form.get("color", "#007bff")
                if name:
                    db.execute(
                        "INSERT INTO tags (category_id, name, color) VALUES (?, ?, ?)",
                        (category_id, name, color)
                    )
                    db.commit()
                    flash("Tag created successfully!")
            
            elif action == "delete":
                tag_id = request.form.get("tag_id")
                db.execute("DELETE FROM tags WHERE id = ? AND category_id = ?", 
                          (tag_id, category_id))
                db.commit()
                flash("Tag deleted successfully!")
        
        tags = db.execute(
            "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
            (category_id,)
        ).fetchall()
        
        tags_list = [dict(t) for t in tags]
        category_dict = dict(category)
    finally:
        db.close()
    
    return render_template("tags.html", tags=tags_list, category=category_dict)

@app.route("/category/<int:category_id>/compare")
def compare_entities(category_id):
    """Compare 1-4 entities side by side"""
    if not session.get("user_id"):
        return redirect("/login")
    
    # Get entity IDs from query parameters (entity1, entity2, entity3, entity4)
    entity_ids = []
    for i in range(1, 5):
        entity_id = request.args.get(f"entity{i}")
        if entity_id:
            entity_ids.append(entity_id)
    
    if not entity_ids or len(entity_ids) > 4:
        flash("Please select 1 to 4 entities to compare")
        return redirect(url_for("view_category", category_id=category_id))
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect("/dashboard")
    
    # Fetch all entities
    entities = []
    for entity_id in entity_ids:
        entity = db.execute(
            "SELECT * FROM entities WHERE id = ? AND category_id = ?",
            (entity_id, category_id)
        ).fetchone()
        if not entity:
            flash(f"Entity {entity_id} not found")
            db.close()
            return redirect(url_for("view_category", category_id=category_id))
        entities.append(entity)
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    # Get field values for all entities
    def get_field_values(entity_id):
        values = {}
        primary_image = None
        for field in fields:
            field_id = int(field["id"])
            value = db.execute(
                "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                (entity_id, field_id)
            ).fetchone()
            raw_value = value["value"] if value else ""
            
            # Strip leading/trailing whitespace for textarea fields
            if field["field_type"] == "textarea" and raw_value:
                # First, strip the entire string to remove leading/trailing whitespace and newlines
                raw_value = raw_value.strip()
                # Then, if there are multiple lines, remove leading whitespace from each line
                if '\n' in raw_value:
                    lines = raw_value.split('\n')
                    # Remove leading whitespace from each line (but preserve line structure)
                    cleaned_lines = [line.lstrip() for line in lines]
                    raw_value = '\n'.join(cleaned_lines)
            
            values[field_id] = raw_value
            
            # Find first image field value
            if not primary_image and field["field_type"] == "image" and raw_value:
                primary_image = raw_value
        return values, primary_image
    
    # Get tags for all entities
    def get_entity_tags(entity_id):
        tags = db.execute(
            """SELECT t.* FROM tags t
               JOIN entity_tags et ON t.id = et.tag_id
               WHERE et.entity_id = ?""",
            (entity_id,)
        ).fetchall()
        return [{"id": tag["id"], "name": tag["name"], "color": tag["color"]} for tag in tags]
    
    # Prepare data for each entity
    entities_data = []
    for entity in entities:
        field_values, primary_image = get_field_values(entity["id"])
        entities_data.append({
            "entity": {
                "id": entity["id"],
                "name": entity["name"],
                "created_at": entity["created_at"],
                "updated_at": entity["updated_at"]
            },
            "field_values": field_values,
            "tags": get_entity_tags(entity["id"]),
            "primary_image": primary_image
        })
    
    db.close()
    
    return render_template("compare.html",
                         category={"id": category["id"], "name": category["name"]},
                         entities_data=entities_data,
                         fields=[{"id": f["id"], "label": f["label"], "field_type": f["field_type"]} for f in fields],
                         num_entities=len(entities_data))

@app.route("/api/category/<int:category_id>/entities")
def api_entities(category_id):
    """API endpoint for getting entities with filtering and sorting"""
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, session["user_id"])
    ).fetchone()
    
    if not category:
        db.close()
        return jsonify({"error": "Category not found"}), 404
    
    # Get filter and sort parameters
    tags_param = request.args.get("tags", None)
    sort_by = request.args.get("sort", "name")
    sort_order = request.args.get("order", "asc")
    
    # Build query
    query = "SELECT DISTINCT e.* FROM entities e"
    params = [category_id]
    
    if tags_param:
        # Parse multiple tag IDs (comma-separated)
        tag_ids = [int(tid.strip()) for tid in tags_param.split(',') if tid.strip().isdigit()]
        
        if tag_ids:
            # Filter entities that have ALL selected tags (AND logic)
            # We need to join entity_tags for each tag and ensure the entity has all of them
            query += " WHERE e.category_id = ?"
            for i, tag_id in enumerate(tag_ids):
                query += f""" AND EXISTS (
                    SELECT 1 FROM entity_tags et{i}
                    WHERE et{i}.entity_id = e.id AND et{i}.tag_id = ?
                )"""
                params.append(tag_id)
        else:
            query += " WHERE e.category_id = ?"
    else:
        query += " WHERE e.category_id = ?"
    
    # Add sorting
    valid_sort_fields = ["name", "created_at", "updated_at"]
    if sort_by in valid_sort_fields:
        query += f" ORDER BY e.{sort_by}"
        if sort_order.lower() == "desc":
            query += " DESC"
        else:
            query += " ASC"
    else:
        query += " ORDER BY e.name"
    
    entities = db.execute(query, params).fetchall()
    
    # Get fields for this category to find image fields
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    # Get tags and primary_image for each entity
    result = []
    for entity in entities:
        tags = db.execute(
            """SELECT t.* FROM tags t
               JOIN entity_tags et ON t.id = et.tag_id
               WHERE et.entity_id = ?""",
            (entity["id"],)
        ).fetchall()
        
        # Find primary image (first image field value)
        primary_image = None
        for field in fields:
            if field["field_type"] == "image":
                value = db.execute(
                    "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                    (entity["id"], field["id"])
                ).fetchone()
                if value and value["value"]:
                    primary_image = value["value"]
                    break  # Use first image found
        
        result.append({
            "id": entity["id"],
            "name": entity["name"],
            "created_at": entity["created_at"],
            "updated_at": entity["updated_at"],
            "tags": [{"id": t["id"], "name": t["name"], "color": t["color"]} for t in tags],
            "primary_image": primary_image
        })
    
    db.close()
    return jsonify(result)

# Admin Panel Routes
@app.route("/admin")
def admin_dashboard():
    """Admin dashboard with system statistics"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    
    # Get system statistics
    stats = {}
    
    # User statistics
    stats['total_users'] = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    # Section statistics
    stats['total_sections'] = db.execute("SELECT COUNT(*) FROM sections").fetchone()[0]
    
    # Category statistics
    stats['total_categories'] = db.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    
    # Entity statistics
    stats['total_entities'] = db.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    
    # Field statistics
    stats['total_fields'] = db.execute("SELECT COUNT(*) FROM fields").fetchone()[0]
    
    # Tag statistics
    stats['total_tags'] = db.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
    
    # Field value statistics
    stats['total_field_values'] = db.execute("SELECT COUNT(*) FROM field_values").fetchone()[0]
    
    # Entity tags statistics
    stats['total_entity_tags'] = db.execute("SELECT COUNT(*) FROM entity_tags").fetchone()[0]
    
    # Get user breakdown
    users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    user_stats = []
    admin_users = []
    for user in users:
        user_id = user["id"]
        user_sections = db.execute("SELECT COUNT(*) FROM sections WHERE user_id = ?", (user_id,)).fetchone()[0]
        user_categories = db.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (user_id,)).fetchone()[0]
        user_entities = db.execute("SELECT COUNT(*) FROM entities e JOIN categories c ON e.category_id = c.id WHERE c.user_id = ?", (user_id,)).fetchone()[0]
        user_stats.append({
            "id": user_id,
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "sections": user_sections,
            "categories": user_categories,
            "entities": user_entities
        })
        if user["is_admin"]:
            admin_users.append({"id": user_id, "username": user["username"]})
    
    # Calculate upload folder size
    upload_size = 0
    upload_count = 0
    try:
        for root, dirs, files in os.walk(UPLOAD_FOLDER):
            for file in files:
                filepath = os.path.join(root, file)
                if os.path.exists(filepath):
                    upload_size += os.path.getsize(filepath)
                    upload_count += 1
    except:
        pass
    
    # Format upload size
    if upload_size < 1024:
        upload_size_str = f"{upload_size} B"
    elif upload_size < 1024 * 1024:
        upload_size_str = f"{upload_size / 1024:.2f} KB"
    else:
        upload_size_str = f"{upload_size / (1024 * 1024):.2f} MB"
    
    db.close()
    
    return render_template("admin.html", 
                         stats=stats, 
                         user_stats=user_stats,
                         admin_users=admin_users,
                         upload_size=upload_size_str,
                         upload_count=upload_count)

@app.route("/admin/users")
def admin_users():
    """Admin user management page"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    
    # Get detailed stats for each user
    users_with_stats = []
    for user in users:
        user_id = user["id"]
        sections = db.execute("SELECT COUNT(*) FROM sections WHERE user_id = ?", (user_id,)).fetchone()[0]
        categories = db.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (user_id,)).fetchone()[0]
        entities = db.execute("SELECT COUNT(*) FROM entities e JOIN categories c ON e.category_id = c.id WHERE c.user_id = ?", (user_id,)).fetchone()[0]
        fields = db.execute("SELECT COUNT(*) FROM fields f JOIN categories c ON f.category_id = c.id WHERE c.user_id = ?", (user_id,)).fetchone()[0]
        tags = db.execute("SELECT COUNT(*) FROM tags t JOIN categories c ON t.category_id = c.id WHERE c.user_id = ?", (user_id,)).fetchone()[0]
        
        users_with_stats.append({
            "id": user_id,
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "sections": sections,
            "categories": categories,
            "entities": entities,
            "fields": fields,
            "tags": tags
        })
    
    db.close()
    
    return render_template("admin_users.html", users=users_with_stats)

@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
def admin_toggle_admin(user_id):
    """Toggle admin status for a user"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    # Prevent self-demotion (must have at least one admin)
    if user_id == session.get("user_id"):
        flash("You cannot remove your own admin privileges. Another admin must do it.")
        return redirect("/admin/users")
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Check if this is the last admin
    current_admin_status = user["is_admin"]
    if current_admin_status:
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if admin_count <= 1:
            flash("Cannot remove admin privileges. At least one admin must remain.")
            db.close()
            return redirect("/admin/users")
    
    # Toggle admin status
    new_admin_status = 0 if current_admin_status else 1
    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_admin_status, user_id))
    db.commit()
    db.close()
    
    action = "granted" if new_admin_status else "revoked"
    flash(f"Admin privileges {action} for user '{user['username']}'")
    return redirect("/admin/users")

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    """Delete a user and all their data"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    # Prevent self-deletion
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account")
        return redirect("/admin/users")
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Get all entities for this user to delete associated images
    entities = db.execute(
        """SELECT e.id FROM entities e 
           JOIN categories c ON e.category_id = c.id 
           WHERE c.user_id = ?""",
        (user_id,)
    ).fetchall()
    
    # Delete uploaded images
    for entity in entities:
        entity_id = entity["id"]
        field_values = db.execute(
            """SELECT fv.value, f.field_type FROM field_values fv
               JOIN fields f ON fv.field_id = f.id
               WHERE fv.entity_id = ? AND (f.field_type = 'image' OR f.field_type = 'image_album')""",
            (entity_id,)
        ).fetchall()
        for row in field_values:
            if row["value"]:
                if row["field_type"] == "image":
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], row["value"])
                    if os.path.exists(filepath):
                        try:
                            os.remove(filepath)
                        except:
                            pass
                elif row["field_type"] == "image_album":
                    try:
                        image_list = json.loads(row["value"])
                        for img_filename in image_list:
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                            if os.path.exists(filepath):
                                try:
                                    os.remove(filepath)
                                except:
                                    pass
                    except:
                        pass
    
    # Delete user (cascade will handle related data)
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    
    flash(f"User '{user['username']}' and all associated data deleted successfully!")
    return redirect("/admin/users")

@app.route("/admin/user/<int:user_id>/data")
def admin_view_user_data(user_id):
    """View user's dashboard data (sections and categories)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Get all sections for this user
    sections = db.execute(
        "SELECT * FROM sections WHERE user_id = ? ORDER BY display_order, created_at",
        (user_id,)
    ).fetchall()
    
    # Get categories not in any section
    unassigned_categories = db.execute(
        "SELECT * FROM categories WHERE user_id = ? AND section_id IS NULL ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    
    # Get categories for each section
    sections_with_categories = []
    for section in sections:
        categories = db.execute(
            "SELECT * FROM categories WHERE section_id = ? ORDER BY created_at DESC",
            (section["id"],)
        ).fetchall()
        sections_with_categories.append({
            "section": dict(section),
            "categories": [dict(cat) for cat in categories]
        })
    
    db.close()
    
    return render_template("admin_user_data.html", 
                         user=dict(user),
                         sections_with_categories=sections_with_categories,
                         unassigned_categories=[dict(cat) for cat in unassigned_categories])

@app.route("/admin/user/<int:user_id>/category/<int:category_id>")
def admin_view_user_category(user_id, category_id):
    """View user's category with entities"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, user_id)
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect(url_for("admin_view_user_data", user_id=user_id))
    
    entities = db.execute(
        "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    tags = db.execute(
        "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
        (category_id,)
    ).fetchall()
    
    # Get tags and field values for each entity
    entities_with_tags = []
    try:
        for entity in entities:
            entity_id = entity["id"]
            entity_tags = db.execute(
                """SELECT t.* FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_id = ?""",
                (entity_id,)
            ).fetchall()
            
            # Get field values for this entity
            entity_field_values = {}
            primary_image = None
            
            for field in fields:
                field_id = int(field["id"])
                value = db.execute(
                    "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                    (entity_id, field_id)
                ).fetchone()
                field_value = value["value"] if value else ""
                entity_field_values[field_id] = field_value
                
                # Store first image found as primary image
                if not primary_image and field["field_type"] == "image" and field_value:
                    primary_image = field_value
            
            entity_dict = {
                "id": entity["id"],
                "category_id": entity["category_id"],
                "name": entity["name"],
                "created_at": entity["created_at"],
                "updated_at": entity["updated_at"]
            }
            
            entities_with_tags.append({
                "entity": entity_dict,
                "tags": [{"id": tag["id"], "name": tag["name"], "color": tag["color"]} for tag in entity_tags],
                "field_values": entity_field_values,
                "primary_image": primary_image
            })
    except Exception as e:
        print(f"ERROR building entities_with_tags: {e}")
        import traceback
        traceback.print_exc()
    
    # Convert fields to dictionaries with integer IDs
    fields_list = []
    for f in fields:
        fields_list.append({
            "id": int(f["id"]),
            "label": f["label"],
            "field_type": f["field_type"],
            "options": f["options"] if f["options"] else "",
            "required": f["required"]
        })
    
    db.close()
    
    return render_template("admin_user_category.html", 
                         user=dict(user),
                         category={"id": category["id"], "name": category["name"], "created_at": category["created_at"]}, 
                         entities_with_tags=entities_with_tags,
                         fields=fields_list,
                         all_tags=[{"id": t["id"], "name": t["name"], "color": t["color"]} for t in tags])

@app.route("/admin/user/<int:user_id>/category/<int:category_id>/entity/<int:entity_id>")
def admin_view_user_entity(user_id, category_id, entity_id):
    """View user's entity details"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    category = db.execute(
        "SELECT * FROM categories WHERE id = ? AND user_id = ?",
        (category_id, user_id)
    ).fetchone()
    
    if not category:
        flash("Category not found")
        db.close()
        return redirect(url_for("admin_view_user_data", user_id=user_id))
    
    entity = db.execute(
        "SELECT * FROM entities WHERE id = ? AND category_id = ?",
        (entity_id, category_id)
    ).fetchone()
    
    if not entity:
        flash("Entity not found")
        db.close()
        return redirect(url_for("admin_view_user_category", user_id=user_id, category_id=category_id))
    
    fields = db.execute(
        "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
        (category_id,)
    ).fetchall()
    
    # Get field values
    field_values = {}
    for field in fields:
        value = db.execute(
            "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
            (entity_id, field["id"])
        ).fetchone()
        raw_value = value["value"] if value else ""
        # Strip leading/trailing whitespace for textarea fields
        if field["field_type"] == "textarea" and raw_value:
            raw_value = raw_value.strip()
            if '\n' in raw_value:
                lines = raw_value.split('\n')
                cleaned_lines = [line.lstrip() for line in lines]
                raw_value = '\n'.join(cleaned_lines)
        field_values[field["id"]] = raw_value
    
    # Get tags
    entity_tags = db.execute(
        """SELECT t.* FROM tags t
           JOIN entity_tags et ON t.id = et.tag_id
           WHERE et.entity_id = ?""",
        (entity_id,)
    ).fetchall()
    
    db.close()
    
    return render_template("admin_user_entity.html", 
                         user=dict(user),
                         category=dict(category), 
                         entity=dict(entity), 
                         fields=fields, 
                         field_values=field_values,
                         tags=entity_tags)

@app.route("/admin/backup/all")
def admin_backup_all():
    """Download complete system backup (all users' data)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    
    # Build comprehensive backup structure
    backup_data = {
        "backup_date": datetime.now().isoformat(),
        "backup_type": "full_system_backup",
        "users": []
    }
    
    # Get all users
    users = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    
    for user in users:
        user_id = user["id"]
        user_data = {
            "id": user_id,
            "username": user["username"],
            "sections": [],
            "categories": []
        }
        
        # Get sections
        sections = db.execute(
            "SELECT * FROM sections WHERE user_id = ? ORDER BY display_order, created_at",
            (user_id,)
        ).fetchall()
        
        for section in sections:
            section_dict = dict(section)
            user_data["sections"].append(section_dict)
        
        # Get all categories for this user
        categories = db.execute(
            "SELECT * FROM categories WHERE user_id = ? ORDER BY created_at",
            (user_id,)
        ).fetchall()
        
        for category in categories:
            category_id = category["id"]
            category_dict = dict(category)
            
            # Get fields for this category
            fields = db.execute(
                "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
                (category_id,)
            ).fetchall()
            category_dict["fields"] = [dict(f) for f in fields]
            
            # Get tags for this category
            tags = db.execute(
                "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
                (category_id,)
            ).fetchall()
            category_dict["tags"] = [dict(t) for t in tags]
            
            # Get entities for this category
            entities = db.execute(
                "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
                (category_id,)
            ).fetchall()
            
            entities_list = []
            for entity in entities:
                entity_id = entity["id"]
                entity_dict = dict(entity)
                
                # Get field values for this entity
                field_values = db.execute(
                    "SELECT * FROM field_values WHERE entity_id = ?",
                    (entity_id,)
                ).fetchall()
                entity_dict["field_values"] = [dict(fv) for fv in field_values]
                
                # Get tags for this entity
                entity_tags = db.execute(
                    """SELECT tag_id FROM entity_tags WHERE entity_id = ?""",
                    (entity_id,)
                ).fetchall()
                entity_dict["tag_ids"] = [row["tag_id"] for row in entity_tags]
                
                entities_list.append(entity_dict)
            
            category_dict["entities"] = entities_list
            user_data["categories"].append(category_dict)
        
        backup_data["users"].append(user_data)
    
    db.close()
    
    # Create JSON response
    response = make_response(json.dumps(backup_data, indent=2, ensure_ascii=False))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=system_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    return response

@app.route("/admin/user/<int:user_id>/backup")
def admin_backup_user(user_id):
    """Download backup for a specific user"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Build user backup structure
    backup_data = {
        "backup_date": datetime.now().isoformat(),
        "backup_type": "user_backup",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "sections": [],
            "categories": []
        }
    }
    
    # Get sections
    sections = db.execute(
        "SELECT * FROM sections WHERE user_id = ? ORDER BY display_order, created_at",
        (user_id,)
    ).fetchall()
    
    for section in sections:
        section_dict = dict(section)
        backup_data["user"]["sections"].append(section_dict)
    
    # Get all categories for this user
    categories = db.execute(
        "SELECT * FROM categories WHERE user_id = ? ORDER BY created_at",
        (user_id,)
    ).fetchall()
    
    for category in categories:
        category_id = category["id"]
        category_dict = dict(category)
        
        # Get fields for this category
        fields = db.execute(
            "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
            (category_id,)
        ).fetchall()
        category_dict["fields"] = [dict(f) for f in fields]
        
        # Get tags for this category
        tags = db.execute(
            "SELECT * FROM tags WHERE category_id = ? ORDER BY name",
            (category_id,)
        ).fetchall()
        category_dict["tags"] = [dict(t) for t in tags]
        
        # Get entities for this category
        entities = db.execute(
            "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
            (category_id,)
        ).fetchall()
        
        entities_list = []
        for entity in entities:
            entity_id = entity["id"]
            entity_dict = dict(entity)
            
            # Get field values for this entity
            field_values = db.execute(
                "SELECT * FROM field_values WHERE entity_id = ?",
                (entity_id,)
            ).fetchall()
            entity_dict["field_values"] = [dict(fv) for fv in field_values]
            
            # Get tags for this entity
            entity_tags = db.execute(
                """SELECT tag_id FROM entity_tags WHERE entity_id = ?""",
                (entity_id,)
            ).fetchall()
            entity_dict["tag_ids"] = [row["tag_id"] for row in entity_tags]
            
            entities_list.append(entity_dict)
        
        category_dict["entities"] = entities_list
        backup_data["user"]["categories"].append(category_dict)
    
    db.close()
    
    # Create JSON response
    response = make_response(json.dumps(backup_data, indent=2, ensure_ascii=False))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=user_backup_{user["username"]}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    return response

@app.route("/admin/backup/all/csv")
def admin_backup_all_csv():
    """Download complete system backup as CSV (entities only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        'User ID', 'Username', 'Section ID', 'Section Name', 
        'Category ID', 'Category Name', 'Entity ID', 'Entity Name',
        'Created At', 'Updated At', 'Field Label', 'Field Type', 
        'Field Value', 'Tags'
    ])
    
    # Get all users
    users = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    
    for user in users:
        user_id = user["id"]
        username = user["username"]
        
        # Get all categories for this user
        categories = db.execute(
            "SELECT c.*, s.id as section_id, s.name as section_name FROM categories c LEFT JOIN sections s ON c.section_id = s.id WHERE c.user_id = ? ORDER BY c.created_at",
            (user_id,)
        ).fetchall()
        
        for category in categories:
            category_id = category["id"]
            category_name = category["name"]
            # Handle nullable section_id and section_name from LEFT JOIN
            section_id = category["section_id"] if category["section_id"] is not None else ""
            section_name = category["section_name"] if category["section_name"] is not None else ""
            
            # Get fields for this category
            fields = db.execute(
                "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
                (category_id,)
            ).fetchall()
            
            # Get entities for this category
            entities = db.execute(
                "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
                (category_id,)
            ).fetchall()
            
            for entity in entities:
                entity_id = entity["id"]
                entity_name = entity["name"]
                created_at = entity["created_at"]
                updated_at = entity["updated_at"]
                
                # Get tags for this entity
                entity_tags = db.execute(
                    """SELECT t.name FROM tags t
                       JOIN entity_tags et ON t.id = et.tag_id
                       WHERE et.entity_id = ?""",
                    (entity_id,)
                ).fetchall()
                tag_names = ", ".join([tag["name"] for tag in entity_tags])
                
                # Write a row for each field value
                if fields:
                    for field in fields:
                        field_id = field["id"]
                        field_label = field["label"]
                        field_type = field["field_type"]
                        
                        # Get field value
                        value = db.execute(
                            "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                            (entity_id, field_id)
                        ).fetchone()
                        field_value = value["value"] if value else ""
                        
                        # Clean field value for CSV (remove newlines, limit length)
                        if field_value:
                            field_value = field_value.replace('\n', ' ').replace('\r', ' ')
                            if len(field_value) > 500:
                                field_value = field_value[:500] + "..."
                        
                        writer.writerow([
                            user_id, username, section_id, section_name,
                            category_id, category_name, entity_id, entity_name,
                            created_at, updated_at, field_label, field_type,
                            field_value, tag_names
                        ])
                else:
                    # If no fields, write entity row with empty field columns
                    writer.writerow([
                        user_id, username, section_id, section_name,
                        category_id, category_name, entity_id, entity_name,
                        created_at, updated_at, "", "", "", tag_names
                    ])
    
    db.close()
    
    # Create CSV response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=system_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route("/admin/user/<int:user_id>/backup/csv")
def admin_backup_user_csv(user_id):
    """Download backup for a specific user as CSV"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        'Section ID', 'Section Name', 'Category ID', 'Category Name', 
        'Entity ID', 'Entity Name', 'Created At', 'Updated At', 
        'Field Label', 'Field Type', 'Field Value', 'Tags'
    ])
    
    # Get all categories for this user
    categories = db.execute(
        "SELECT c.*, s.id as section_id, s.name as section_name FROM categories c LEFT JOIN sections s ON c.section_id = s.id WHERE c.user_id = ? ORDER BY c.created_at",
        (user_id,)
    ).fetchall()
    
    for category in categories:
        category_id = category["id"]
        category_name = category["name"]
        # Handle nullable section_id and section_name from LEFT JOIN
        section_id = category["section_id"] if category["section_id"] is not None else ""
        section_name = category["section_name"] if category["section_name"] is not None else ""
        
        # Get fields for this category
        fields = db.execute(
            "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
            (category_id,)
        ).fetchall()
        
        # Get entities for this category
        entities = db.execute(
            "SELECT * FROM entities WHERE category_id = ? ORDER BY name",
            (category_id,)
        ).fetchall()
        
        for entity in entities:
            entity_id = entity["id"]
            entity_name = entity["name"]
            created_at = entity["created_at"]
            updated_at = entity["updated_at"]
            
            # Get tags for this entity
            entity_tags = db.execute(
                """SELECT t.name FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_id = ?""",
                (entity_id,)
            ).fetchall()
            tag_names = ", ".join([tag["name"] for tag in entity_tags])
            
            # Write a row for each field value
            if fields:
                for field in fields:
                    field_id = field["id"]
                    field_label = field["label"]
                    field_type = field["field_type"]
                    
                    # Get field value
                    value = db.execute(
                        "SELECT value FROM field_values WHERE entity_id = ? AND field_id = ?",
                        (entity_id, field_id)
                    ).fetchone()
                    field_value = value["value"] if value else ""
                    
                    # Clean field value for CSV
                    if field_value:
                        field_value = field_value.replace('\n', ' ').replace('\r', ' ')
                        if len(field_value) > 500:
                            field_value = field_value[:500] + "..."
                    
                    writer.writerow([
                        section_id, section_name, category_id, category_name,
                        entity_id, entity_name, created_at, updated_at,
                        field_label, field_type, field_value, tag_names
                    ])
            else:
                # If no fields, write entity row with empty field columns
                writer.writerow([
                    section_id, section_name, category_id, category_name,
                    entity_id, entity_name, created_at, updated_at,
                    "", "", "", tag_names
                ])
    
    db.close()
    
    # Create CSV response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=user_backup_{user["username"]}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

if __name__ == "__main__":
    app.run(debug=True)

