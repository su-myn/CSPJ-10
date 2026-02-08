import os
import zipfile
import shutil
import tempfile
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
import json
import csv
import io
from urllib.parse import urlparse
from PIL import Image

# Configure application
app = Flask(__name__)

# Configure session to use signed cookies (persists across deploys)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
THUMBNAIL_FOLDER = os.path.join(UPLOAD_FOLDER, 'thumbnails')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMBNAIL_FOLDER, exist_ok=True)

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

@app.template_filter('thumbnail_url')
def thumbnail_url_filter(filename, size=100):
    """Get thumbnail URL for an image filename"""
    if not filename:
        return ''
    base_name = os.path.splitext(filename)[0]
    thumbnail_filename = f"{base_name}_thumb{size}.jpg"
    thumbnail_path = os.path.join(THUMBNAIL_FOLDER, thumbnail_filename)
    if os.path.exists(thumbnail_path):
        return url_for('static', filename=f"uploads/thumbnails/{thumbnail_filename}")
    # Fallback to original if thumbnail doesn't exist
    return url_for('static', filename=f"uploads/{filename}")

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
    """Make PostgreSQL rows work like SQLite rows (supports both row['name'] and row[0])"""
    def __init__(self, data):
        self._data = dict(data)
        self._keys = list(self._data.keys())
    def __getitem__(self, key):
        if isinstance(key, int):
            # Support integer index access like SQLite rows: row[0], row[1], etc.
            return self._data[self._keys[key]]
        return self._data[key]
    def __contains__(self, key):
        return key in self._data
    def get(self, key, default=None):
        return self._data.get(key, default)
    def keys(self):
        return self._data.keys()
    def __iter__(self):
        return iter(self._data)
    def __len__(self):
        return len(self._data)
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
        
        # Convert SQLite INSERT OR REPLACE to PostgreSQL ON CONFLICT DO UPDATE
        import re
        upper_query = query.strip().upper()
        if upper_query.startswith('INSERT OR REPLACE'):
            query = re.sub(r'INSERT\s+OR\s+REPLACE\s+INTO', 'INSERT INTO', query, flags=re.IGNORECASE)
            # Extract table and column info to build ON CONFLICT clause
            # Pattern: INSERT INTO table (col1, col2, ...) VALUES (?, ?, ...)
            match = re.search(r'INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)', query, re.IGNORECASE)
            if match:
                table_name = match.group(1)
                columns = [c.strip() for c in match.group(2).split(',')]
                # For field_values table, conflict on (entity_id, field_id)
                if table_name == 'field_values':
                    update_cols = [c for c in columns if c not in ('entity_id', 'field_id')]
                    update_clause = ', '.join(f"{c} = EXCLUDED.{c}" for c in update_cols)
                    query = query.rstrip(';') + f' ON CONFLICT (entity_id, field_id) DO UPDATE SET {update_clause}'
        
        # Convert SQLite INSERT OR IGNORE to PostgreSQL ON CONFLICT DO NOTHING
        if query.strip().upper().startswith('INSERT OR IGNORE'):
            query = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', query, flags=re.IGNORECASE)
            query = query.rstrip(';') + ' ON CONFLICT DO NOTHING'
        
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
    
    def rollback(self):
        self.conn.rollback()
    
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
    
    # Use SQLite for local development only (no DATABASE_URL set)
    print("WARNING: DATABASE_URL not set, using SQLite (data will NOT persist on Railway!)")
    db = sqlite3.connect('database.db', timeout=10.0)
    db.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency (allows multiple readers)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.commit()
    except:
        pass  # Ignore if WAL mode can't be set
    return db

def safe_migrate(db, sql):
    """Safely run a migration SQL statement (e.g. ALTER TABLE ADD COLUMN).
    If it fails (e.g. column already exists), rollback and continue."""
    try:
        db.execute(sql)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

def init_db():
    """Initialize database with schema"""
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        print(f"=== INIT_DB: Using PostgreSQL (DATABASE_URL is set) ===")
    else:
        print(f"=== INIT_DB: WARNING - Using SQLite! DATABASE_URL is NOT set! ===")
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
    safe_migrate(db, "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    
    # Make the first user an admin if no admins exist (run this check every time)
    try:
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if admin_count == 0:
            first_user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
            if first_user:
                db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user["id"],))
                db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    
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
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE SET NULL
        )
    """)
    
    # Add missing columns to categories table (migration for both SQLite and PostgreSQL)
    safe_migrate(db, "ALTER TABLE categories ADD COLUMN section_id INTEGER")
    safe_migrate(db, "ALTER TABLE categories ADD COLUMN display_order INTEGER DEFAULT 0")
    
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
            display_order INTEGER DEFAULT 0,
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
    
    # Create index for tags
    safe_migrate(db, "CREATE INDEX IF NOT EXISTS idx_tags_category ON tags(category_id)")
    
    # Add display_order to entities if it doesn't exist (migration)
    safe_migrate(db, "ALTER TABLE entities ADD COLUMN display_order INTEGER DEFAULT 0")

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
    
    # Friendships table (friend requests and accepted friendships)
    db.execute("""
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            addressee_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (addressee_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(requester_id, addressee_id)
        )
    """)
    
    # Shared posts table (shared entity comparisons)
    db.execute("""
        CREATE TABLE IF NOT EXISTS shared_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            entity_ids TEXT NOT NULL,
            share_type TEXT NOT NULL DEFAULT 'public',
            shared_to_user_id INTEGER,
            show_like_count INTEGER DEFAULT 1,
            show_like_persons INTEGER DEFAULT 1,
            show_comments INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
            FOREIGN KEY (shared_to_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    # Add visibility columns if they don't exist (migration)
    safe_migrate(db, "ALTER TABLE shared_posts ADD COLUMN show_like_count INTEGER DEFAULT 1")
    safe_migrate(db, "ALTER TABLE shared_posts ADD COLUMN show_like_persons INTEGER DEFAULT 1")
    safe_migrate(db, "ALTER TABLE shared_posts ADD COLUMN show_comments INTEGER DEFAULT 1")
    
    # Post likes table
    db.execute("""
        CREATE TABLE IF NOT EXISTS post_likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES shared_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(post_id, user_id)
        )
    """)
    
    # Post comments table
    db.execute("""
        CREATE TABLE IF NOT EXISTS post_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES shared_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    db.commit()
    db.close()

# Initialize database on first run
try:
    init_db()
    print("=== Database initialized successfully ===")
except Exception as e:
    print(f"=== Database init error (tables may already exist, this is OK): {e} ===")
    # Tables likely already exist from a previous deployment - this is fine

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def delete_image_and_thumbnails(filename):
    """
    Delete an image file and all its associated thumbnails.
    
    Args:
        filename: The filename of the image to delete
    
    Returns:
        None (silently handles errors)
    """
    if not filename:
        return
    
    try:
        # Delete main image file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Delete thumbnails (100px, 300px, and 500px)
        base_name = os.path.splitext(filename)[0]
        thumbnail_sizes = [100, 300, 500]
        for size in thumbnail_sizes:
            thumbnail_filename = f"{base_name}_thumb{size}.jpg"
            thumbnail_path = os.path.join(THUMBNAIL_FOLDER, thumbnail_filename)
            if os.path.exists(thumbnail_path):
                try:
                    os.remove(thumbnail_path)
                except Exception as e:
                    # Log error in development (Flask debug mode)
                    if app.debug:
                        print(f"Error deleting thumbnail {thumbnail_filename}: {str(e)}")
    except Exception as e:
        # Log error in development (Flask debug mode)
        if app.debug:
            print(f"Error deleting image {filename}: {str(e)}")

def generate_thumbnail(input_path, output_path, size=100, quality=85):
    """
    Generate a thumbnail version of an image.
    
    Args:
        input_path: Path to the input image file
        output_path: Path to save the thumbnail
        size: Maximum dimension (width or height) in pixels (default 100)
        quality: JPEG quality (default 85)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        img = Image.open(input_path)
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Calculate thumbnail size maintaining aspect ratio
        width, height = img.size
        if width > height:
            new_width = size
            new_height = int(height * (size / width))
        else:
            new_height = size
            new_width = int(width * (size / height))
        
        # Resize image
        img.thumbnail((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Save thumbnail
        img.save(output_path, 'JPEG', quality=quality, optimize=True)
        return True
    except Exception as e:
        print(f"Thumbnail generation error: {str(e)}")
        return False

def compress_image(input_path, output_path, max_size_kb=400, max_dimension=1920):
    """
    Compress image to maximum 400 KB JPEG format with no visible quality loss.
    
    Args:
        input_path: Path to the input image file
        output_path: Path to save the compressed JPEG file
        max_size_kb: Maximum file size in KB (default 400)
        max_dimension: Maximum dimension (width or height) in pixels (default 1920)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Open and process the image
        img = Image.open(input_path)
        
        # Convert to RGB if necessary (for PNG/GIF with transparency)
        if img.mode in ('RGBA', 'LA', 'P'):
            # Create white background
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Resize if image is too large (helps reduce file size)
        width, height = img.size
        if width > max_dimension or height > max_dimension:
            if width > height:
                new_width = max_dimension
                new_height = int(height * (max_dimension / width))
            else:
                new_height = max_dimension
                new_width = int(width * (max_dimension / height))
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Binary search for optimal quality to get under max_size_kb
        max_size_bytes = max_size_kb * 1024
        min_quality = 60
        max_quality = 95
        optimal_quality = 85
        temp_path = output_path + '.tmp'
        
        # Binary search
        while min_quality <= max_quality:
            mid_quality = (min_quality + max_quality) // 2
            img.save(temp_path, 'JPEG', quality=mid_quality, optimize=True)
            file_size = os.path.getsize(temp_path)
            
            if file_size <= max_size_bytes:
                optimal_quality = mid_quality
                min_quality = mid_quality + 1
            else:
                max_quality = mid_quality - 1
        
        # Save final image with optimal quality
        img.save(output_path, 'JPEG', quality=optimal_quality, optimize=True)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return True
            
    except Exception as e:
        # If compression fails, return False (caller can handle)
        print(f"Image compression error: {str(e)}")
        if os.path.exists(output_path + '.tmp'):
            try:
                os.remove(output_path + '.tmp')
            except:
                pass
        return False

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
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            flash("Username already exists")
            db.close()
            return render_template("register.html")
        
        db.close()
        flash("Registration successful! Please log in.")
        return redirect("/login")
    
    return render_template("register.html")

@app.route("/set-admin")
def set_admin():
    """Set first user as admin - protected by secret key (for admin recovery)"""
    # Require secret key from environment variable or query parameter
    secret_key = os.environ.get('ADMIN_RECOVERY_KEY', 'change-this-secret-key')
    provided_key = request.args.get('key', '')
    
    if provided_key != secret_key:
        return """<html><body style="font-family: Arial, sans-serif; padding: 20px; text-align: center;">
            <h2>🔒 Access Denied</h2>
            <p>This route requires a secret key for security.</p>
            <p style="color: #666; font-size: 12px;">Add ?key=YOUR_SECRET_KEY to the URL</p>
            <p style="color: #666; font-size: 12px;">Set ADMIN_RECOVERY_KEY environment variable in Railway</p>
        </body></html>""", 403
    
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
                <h2>✅ Admin Access Restored</h2>
                <p>Admin privileges have been granted to the first user: <strong>{first_user['username']}</strong> (ID: {first_user['id']})</p>
                <p><a href="/login" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Go to Login</a></p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">✅ This route is protected by a secret key for security.</p>
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
            <p>If you can't access /admin, try logging out and logging back in to refresh your session.</p>
            <p><a href="/logout" style="display: inline-block; padding: 10px 20px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px;">Logout</a>
            <a href="/admin" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">Go to Admin Panel</a></p>
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
        "SELECT * FROM categories WHERE user_id = ? AND section_id IS NULL ORDER BY display_order, created_at DESC",
        (session["user_id"],)
    ).fetchall()
    
    # Get categories for each section
    sections_with_categories = []
    for section in sections:
        categories = db.execute(
            "SELECT * FROM categories WHERE section_id = ? ORDER BY display_order, created_at DESC",
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
        max_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) FROM categories WHERE user_id = ? AND section_id IS NULL",
            (session["user_id"],)
        ).fetchone()[0]
        db.execute(
            "INSERT INTO categories (user_id, name, display_order) VALUES (?, ?, ?)",
            (session["user_id"], name, max_order + 1)
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
    
    # Set display_order to end of target section
    if section_id is None:
        max_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) FROM categories WHERE section_id IS NULL",
            ()
        ).fetchone()[0]
    else:
        max_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) FROM categories WHERE section_id = ?",
            (section_id,)
        ).fetchone()[0]
    
    db.execute(
        "UPDATE categories SET section_id = ?, display_order = ? WHERE id = ?",
        (section_id, max_order + 1, category_id)
    )
    db.commit()
    db.close()
    
    flash("Category moved successfully!")
    return redirect("/dashboard")

@app.route("/category/reorder", methods=["POST"])
def reorder_categories():
    """Reorder categories within a section"""
    if not session.get("user_id"):
        return redirect("/login")
    
    # Get ordered list of category IDs: category_ids=1&category_ids=2&category_ids=3
    category_ids = request.form.getlist("category_ids")
    if not category_ids:
        flash("No categories to reorder")
        return redirect("/dashboard")
    
    try:
        category_ids = [int(cid) for cid in category_ids]
    except ValueError:
        flash("Invalid category IDs")
        return redirect("/dashboard")
    
    db = get_db()
    
    # Verify all categories belong to user
    for cid in category_ids:
        cat = db.execute(
            "SELECT * FROM categories WHERE id = ? AND user_id = ?",
            (cid, session["user_id"])
        ).fetchone()
        if not cat:
            flash("Category not found")
            db.close()
            return redirect("/dashboard")
    
    for idx, cid in enumerate(category_ids):
        db.execute(
            "UPDATE categories SET display_order = ? WHERE id = ? AND user_id = ?",
            (idx, cid, session["user_id"])
        )
    
    db.commit()
    db.close()
    
    flash("Order updated!")
    return redirect("/dashboard")

@app.route("/category/<int:category_id>/entity/reorder", methods=["POST"])
def reorder_entities(category_id):
    """Reorder entities within a category"""
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
    
    entity_ids = request.form.getlist("entity_ids")
    if not entity_ids:
        flash("No entities to reorder")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    try:
        entity_ids = [int(eid) for eid in entity_ids]
    except ValueError:
        flash("Invalid entity IDs")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    for idx, eid in enumerate(entity_ids):
        db.execute(
            "UPDATE entities SET display_order = ? WHERE id = ? AND category_id = ?",
            (idx, eid, category_id)
        )
    
    db.commit()
    db.close()
    
    flash("Order updated!")
    return redirect(url_for("view_category", category_id=category_id))

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
        "SELECT * FROM entities WHERE category_id = ? ORDER BY display_order, name",
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
        max_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) FROM entities WHERE category_id = ?",
            (category_id,)
        ).fetchone()[0]
        cursor = db.execute(
            "INSERT INTO entities (category_id, name, display_order) VALUES (?, ?, ?)",
            (category_id, name, max_order + 1)
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
                    # Generate filename with .jpg extension
                    base_name = os.path.splitext(secure_filename(file.filename))[0]
                    filename = secure_filename(f"{entity_id}_{field_id}_{base_name}.jpg")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Save uploaded file to temporary location
                    temp_path = filepath + '.upload'
                    file.save(temp_path)
                    
                    # Compress the image
                    if compress_image(temp_path, filepath):
                        # Generate thumbnails (100px for album, 300px for compare, 500px for category grid)
                        base_name = os.path.splitext(filename)[0]
                        thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                        thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                        thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                        generate_thumbnail(filepath, thumbnail_100_path, size=100)
                        generate_thumbnail(filepath, thumbnail_300_path, size=300)
                        generate_thumbnail(filepath, thumbnail_500_path, size=500)
                        
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        value = filename
                    else:
                        # If compression fails, use original (fallback)
                        if os.path.exists(temp_path):
                            os.rename(temp_path, filepath)
                            base_name = os.path.splitext(filename)[0]
                            thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                            thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                            thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                            generate_thumbnail(filepath, thumbnail_100_path, size=100)
                            generate_thumbnail(filepath, thumbnail_300_path, size=300)
                            generate_thumbnail(filepath, thumbnail_500_path, size=500)
                        value = filename
            
            elif field["field_type"] == "image_album":
                # Handle multiple image uploads
                files = request.files.getlist(f"field_{field_id}")
                image_filenames = []
                
                for file in files:
                    if file and file.filename and allowed_file(file.filename):
                        # Generate filename with .jpg extension
                        base_name = os.path.splitext(secure_filename(file.filename))[0]
                        filename = secure_filename(f"{entity_id}_{field_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{base_name}.jpg")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        # Save uploaded file to temporary location
                        temp_path = filepath + '.upload'
                        file.save(temp_path)
                        
                        # Compress the image
                        if compress_image(temp_path, filepath):
                            # Generate thumbnails (100px for album, 300px for compare, 500px for category grid)
                            base_name = os.path.splitext(filename)[0]
                            thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                            thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                            thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                            generate_thumbnail(filepath, thumbnail_100_path, size=100)
                            generate_thumbnail(filepath, thumbnail_300_path, size=300)
                            generate_thumbnail(filepath, thumbnail_500_path, size=500)
                            
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            image_filenames.append(filename)
                        else:
                            # If compression fails, use original (fallback)
                            if os.path.exists(temp_path):
                                os.rename(temp_path, filepath)
                                base_name = os.path.splitext(filename)[0]
                                thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                                thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                                thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                                generate_thumbnail(filepath, thumbnail_100_path, size=100)
                                generate_thumbnail(filepath, thumbnail_300_path, size=300)
                                generate_thumbnail(filepath, thumbnail_500_path, size=500)
                            image_filenames.append(filename)
                
                if image_filenames:
                    value = json.dumps(image_filenames)
                else:
                    value = ""
            
            elif field["field_type"] == "video_embed":
                # Handle video embed URLs (stored as JSON array)
                embed_urls = request.form.get(f"field_{field_id}", "")
                if embed_urls:
                    try:
                        # Validate it's valid JSON
                        urls = json.loads(embed_urls)
                        if isinstance(urls, list):
                            value = embed_urls
                        else:
                            value = ""
                    except:
                        value = ""
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
                # Check if user requested to delete the image
                clear_image = request.form.get(f"clear_image_{field_id}")
                if clear_image:
                    old_value = field_values.get(field_id)
                    if old_value:
                        delete_image_and_thumbnails(old_value)
                    value = ""
                else:
                    file = request.files.get(f"field_{field_id}")
                    if file and file.filename and allowed_file(file.filename):
                        # Delete old file and thumbnails if exists
                        old_value = field_values.get(field_id)
                        if old_value:
                            delete_image_and_thumbnails(old_value)
                        
                        # Generate filename with .jpg extension
                        base_name = os.path.splitext(secure_filename(file.filename))[0]
                        filename = secure_filename(f"{entity_id}_{field_id}_{base_name}.jpg")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        # Save uploaded file to temporary location
                        temp_path = filepath + '.upload'
                        file.save(temp_path)
                        
                        # Compress the image
                        if compress_image(temp_path, filepath):
                            # Generate thumbnails (100px for album, 300px for compare, 500px for category grid)
                            base_name = os.path.splitext(filename)[0]
                            thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                            thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                            thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                            generate_thumbnail(filepath, thumbnail_100_path, size=100)
                            generate_thumbnail(filepath, thumbnail_300_path, size=300)
                            generate_thumbnail(filepath, thumbnail_500_path, size=500)
                            
                            # Remove temporary file
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            value = filename
                        else:
                            # If compression fails, use original (fallback)
                            if os.path.exists(temp_path):
                                os.rename(temp_path, filepath)
                                # Generate thumbnails even for fallback
                                base_name = os.path.splitext(filename)[0]
                                thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                                thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                                thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                                generate_thumbnail(filepath, thumbnail_100_path, size=100)
                                generate_thumbnail(filepath, thumbnail_300_path, size=300)
                                generate_thumbnail(filepath, thumbnail_500_path, size=500)
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
                    # Delete file and thumbnails from filesystem
                    delete_image_and_thumbnails(del_img)
                
                # Handle new image uploads
                files = request.files.getlist(f"field_{field_id}")
                for file in files:
                    if file and file.filename and allowed_file(file.filename):
                        # Generate filename with .jpg extension
                        base_name = os.path.splitext(secure_filename(file.filename))[0]
                        filename = secure_filename(f"{entity_id}_{field_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{base_name}.jpg")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        # Save uploaded file to temporary location
                        temp_path = filepath + '.upload'
                        file.save(temp_path)
                        
                        # Compress the image
                        if compress_image(temp_path, filepath):
                            # Generate thumbnails (100px for album, 300px for compare, 500px for category grid)
                            base_name = os.path.splitext(filename)[0]
                            thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                            thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                            thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                            generate_thumbnail(filepath, thumbnail_100_path, size=100)
                            generate_thumbnail(filepath, thumbnail_300_path, size=300)
                            generate_thumbnail(filepath, thumbnail_500_path, size=500)
                            
                            # Remove temporary file
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            existing_images.append(filename)
                        else:
                            # If compression fails, use original (fallback)
                            if os.path.exists(temp_path):
                                os.rename(temp_path, filepath)
                                # Generate thumbnails even for fallback
                                base_name = os.path.splitext(filename)[0]
                                thumbnail_100_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb100.jpg")
                                thumbnail_300_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb300.jpg")
                                thumbnail_500_path = os.path.join(THUMBNAIL_FOLDER, f"{base_name}_thumb500.jpg")
                                generate_thumbnail(filepath, thumbnail_100_path, size=100)
                                generate_thumbnail(filepath, thumbnail_300_path, size=300)
                                generate_thumbnail(filepath, thumbnail_500_path, size=500)
                            existing_images.append(filename)
                
                if existing_images:
                    value = json.dumps(existing_images)
                else:
                    value = ""
            
            elif field["field_type"] == "video_embed":
                # Handle video embed URLs (stored as JSON array)
                embed_urls = request.form.get(f"field_{field_id}", "")
                if embed_urls:
                    try:
                        # Validate it's valid JSON
                        urls = json.loads(embed_urls)
                        if isinstance(urls, list):
                            value = embed_urls
                        else:
                            value = ""
                    except:
                        value = ""
                else:
                    value = ""
            
            # Always update when we have a value, field is required, or we're clearing image/image_album
            if value or field["required"] or field["field_type"] in ("image", "image_album"):
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
    
    # Require category name confirmation
    confirm_name = request.form.get("confirm_name", "").strip()
    if confirm_name != category["name"]:
        flash("Deletion cancelled. The category name did not match.")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
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
                    delete_image_and_thumbnails(row["value"])
                elif row["field_type"] == "image_album":
                    # Multiple images stored as JSON
                    try:
                        image_list = json.loads(row["value"])
                        for img_filename in image_list:
                            delete_image_and_thumbnails(img_filename)
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
    
    entity = db.execute(
        "SELECT * FROM entities WHERE id = ? AND category_id = ?",
        (entity_id, category_id)
    ).fetchone()
    
    if not entity:
        flash("Entity not found")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    # Require entity name confirmation
    confirm_name = request.form.get("confirm_name", "").strip()
    if confirm_name != entity["name"]:
        flash("Deletion cancelled. The entity name did not match.")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
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
                delete_image_and_thumbnails(row["value"])
            elif row["field_type"] == "image_album":
                # Multiple images stored as JSON
                try:
                    image_list = json.loads(row["value"])
                    for img_filename in image_list:
                        delete_image_and_thumbnails(img_filename)
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
    
    # Check if this comparison is already shared (sort entity IDs for consistency)
    sorted_entity_ids = sorted([str(eid) for eid in entity_ids])
    entity_ids_str = json.dumps(sorted_entity_ids)
    existing_share = db.execute(
        "SELECT * FROM shared_posts WHERE user_id = ? AND category_id = ? AND entity_ids = ?",
        (session["user_id"], category_id, entity_ids_str)
    ).fetchone()
    
    # Get all users for custom sharing
    all_users = db.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username",
        (session["user_id"],)
    ).fetchall()
    
    db.close()
    
    return render_template("compare.html",
                         category={"id": category["id"], "name": category["name"]},
                         entities_data=entities_data,
                         fields=[{"id": f["id"], "label": f["label"], "field_type": f["field_type"]} for f in fields],
                         num_entities=len(entities_data),
                         is_shared=existing_share is not None,
                         share_id=existing_share["id"] if existing_share else None,
                         all_users=[dict(u) for u in all_users])

@app.route("/category/<int:category_id>/share", methods=["POST"])
def share_category(category_id):
    """Share a category's entity comparison"""
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
    
    # Get entity IDs from form
    entity_ids = []
    for i in range(1, 5):
        entity_id = request.form.get(f"entity{i}")
        if entity_id:
            entity_ids.append(str(entity_id))  # Ensure string format for consistency
    
    if not entity_ids:
        flash("No entities selected")
        db.close()
        return redirect(url_for("view_category", category_id=category_id))
    
    share_type = request.form.get("share_type", "public")
    shared_to_user_id = request.form.get("shared_to_user_id")
    
    # Sort entity IDs to ensure consistent comparison
    entity_ids.sort()
    entity_ids_str = json.dumps(entity_ids)
    
    # Check if already shared
    existing = db.execute(
        "SELECT * FROM shared_posts WHERE user_id = ? AND category_id = ? AND entity_ids = ?",
        (session["user_id"], category_id, entity_ids_str)
    ).fetchone()
    
    if existing:
        # Update existing share
        if shared_to_user_id:
            db.execute(
                "UPDATE shared_posts SET share_type = ?, shared_to_user_id = ? WHERE id = ?",
                (share_type, int(shared_to_user_id), existing["id"])
            )
        else:
            db.execute(
                "UPDATE shared_posts SET share_type = ?, shared_to_user_id = NULL WHERE id = ?",
                (share_type, existing["id"])
            )
        flash("Share settings updated!")
    else:
        # Create new share
        if shared_to_user_id:
            db.execute(
                "INSERT INTO shared_posts (user_id, category_id, entity_ids, share_type, shared_to_user_id) VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], category_id, entity_ids_str, share_type, int(shared_to_user_id))
            )
        else:
            db.execute(
                "INSERT INTO shared_posts (user_id, category_id, entity_ids, share_type) VALUES (?, ?, ?, ?)",
                (session["user_id"], category_id, entity_ids_str, share_type)
            )
        flash("Shared successfully!")
    
    db.commit()
    db.close()
    
    # Redirect back to compare page
    params = "&".join([f"entity{i+1}={entity_ids[i]}" for i in range(len(entity_ids))])
    return redirect(f"/category/{category_id}/compare?{params}")

@app.route("/profile")
def profile():
    """User profile page showing their own shared posts"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    current_user_id = session["user_id"]
    
    # Get all shared posts by the current user
    posts = db.execute(
        "SELECT sp.*, c.name as category_name FROM shared_posts sp JOIN categories c ON sp.category_id = c.id WHERE sp.user_id = ? ORDER BY sp.created_at DESC",
        (current_user_id,)
    ).fetchall()
    
    # Get full post data
    posts_data = []
    for post in posts:
        category = db.execute(
            "SELECT * FROM categories WHERE id = ?",
            (post["category_id"],)
        ).fetchone()
        
        if not category:
            continue
        
        entity_ids = json.loads(post["entity_ids"])
        entities = []
        for entity_id in entity_ids:
            entity_id_int = int(entity_id) if isinstance(entity_id, str) else entity_id
            entity = db.execute(
                "SELECT * FROM entities WHERE id = ? AND category_id = ?",
                (entity_id_int, post["category_id"])
            ).fetchone()
            if entity:
                entities.append(entity)
        
        if not entities:
            continue
        
        fields = db.execute(
            "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
            (post["category_id"],)
        ).fetchall()
        
        # Get field values and tags for entities
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
                
                if field["field_type"] == "textarea" and raw_value:
                    raw_value = raw_value.strip()
                    if '\n' in raw_value:
                        lines = raw_value.split('\n')
                        cleaned_lines = [line.lstrip() for line in lines]
                        raw_value = '\n'.join(cleaned_lines)
                
                values[field_id] = raw_value
                
                if not primary_image and field["field_type"] == "image" and raw_value:
                    primary_image = raw_value
            return values, primary_image
        
        def get_entity_tags(entity_id):
            tags = db.execute(
                """SELECT t.* FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_id = ?""",
                (entity_id,)
            ).fetchall()
            return [{"id": tag["id"], "name": tag["name"], "color": tag["color"]} for tag in tags]
        
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
        
        # Get likes and comments stats
        like_count = db.execute(
            "SELECT COUNT(*) FROM post_likes WHERE post_id = ?",
            (post["id"],)
        ).fetchone()[0]
        
        comment_count = db.execute(
            "SELECT COUNT(*) FROM post_comments WHERE post_id = ?",
            (post["id"],)
        ).fetchone()[0]
        
        # Get all comments for the profile page (creator can always see all comments)
        comments_query = db.execute(
            "SELECT pc.*, u.username FROM post_comments pc JOIN users u ON pc.user_id = u.id WHERE pc.post_id = ? ORDER BY pc.created_at ASC",
            (post["id"],)
        ).fetchall()
        comments = [{
            "id": c["id"],
            "user_id": c["user_id"],
            "username": c["username"],
            "comment_text": c["comment_text"],
            "created_at": c["created_at"]
        } for c in comments_query]
        
        # Get share type display
        share_type_display = post["share_type"].capitalize()
        if post["share_type"] == "custom" and post["shared_to_user_id"]:
            shared_to_user = db.execute(
                "SELECT username FROM users WHERE id = ?",
                (post["shared_to_user_id"],)
            ).fetchone()
            if shared_to_user:
                share_type_display = f"Custom ({shared_to_user['username']})"
        
        # Convert post to dict first, then ensure visibility settings
        post_dict = dict(post)
        # Ensure visibility settings default to 1 if not set
        show_like_count = post_dict.get("show_like_count")
        show_like_persons = post_dict.get("show_like_persons")
        show_comments = post_dict.get("show_comments")
        
        post_dict["show_like_count"] = 1 if show_like_count is None else show_like_count
        post_dict["show_like_persons"] = 1 if show_like_persons is None else show_like_persons
        post_dict["show_comments"] = 1 if show_comments is None else show_comments
        
        posts_data.append({
            "post": post_dict,
            "category": dict(category),
            "entities_data": entities_data,
            "fields": [{"id": f["id"], "label": f["label"], "field_type": f["field_type"]} for f in fields],
            "num_entities": len(entities_data),
            "like_count": like_count,
            "comment_count": comment_count,
            "share_type_display": share_type_display,
            "comments": comments
        })
    
    # Get current user info
    user = db.execute(
        "SELECT id, username FROM users WHERE id = ?",
        (current_user_id,)
    ).fetchone()
    
    db.close()
    
    return render_template("profile.html",
                         user=dict(user),
                         posts_data=posts_data)

@app.route("/post/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    """Delete a shared post (creator only)"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    
    # Verify user is the creator
    post = db.execute(
        "SELECT * FROM shared_posts WHERE id = ? AND user_id = ?",
        (post_id, session["user_id"])
    ).fetchone()
    
    if not post:
        flash("Post not found or access denied")
        db.close()
        return redirect("/profile")
    
    # Delete the post (likes and comments will be deleted via CASCADE)
    db.execute("DELETE FROM shared_posts WHERE id = ?", (post_id,))
    db.commit()
    db.close()
    
    flash("Post deleted successfully!")
    return redirect("/profile")

@app.route("/newsfeed")
def newsfeed():
    """News feed showing shared entity comparisons"""
    if not session.get("user_id"):
        return redirect("/login")
    
    db = get_db()
    current_user_id = session["user_id"]
    
    # Get all friends (accepted friendships)
    friends_query = """
        SELECT DISTINCT 
            CASE 
                WHEN requester_id = ? THEN addressee_id 
                ELSE requester_id 
            END as friend_id
        FROM friendships
        WHERE (requester_id = ? OR addressee_id = ?) AND status = 'accepted'
    """
    friends = db.execute(friends_query, (current_user_id, current_user_id, current_user_id)).fetchall()
    friend_ids = [f["friend_id"] for f in friends]
    
    # Get shared posts that the current user can see:
    # 1. Public shares
    # 2. Shares to friends (where creator is a friend)
    # 3. Shares specifically to current user
    posts = []
    
    # Public posts
    public_posts = db.execute(
        "SELECT sp.*, u.username FROM shared_posts sp JOIN users u ON sp.user_id = u.id WHERE sp.share_type = 'public' ORDER BY sp.created_at DESC"
    ).fetchall()
    
    for post in public_posts:
        if post["user_id"] != current_user_id:  # Don't show own posts
            posts.append(dict(post))
    
    # Friend posts
    if friend_ids:
        # Build query with proper placeholders
        placeholders = ','.join(['?'] * len(friend_ids))
        query = f"SELECT sp.*, u.username FROM shared_posts sp JOIN users u ON sp.user_id = u.id WHERE sp.share_type = 'friend' AND sp.user_id IN ({placeholders}) ORDER BY sp.created_at DESC"
        friend_posts = db.execute(query, friend_ids).fetchall()
        
        for post in friend_posts:
            if post["user_id"] != current_user_id:
                posts.append(dict(post))
    
    # Custom posts (shared specifically to current user)
    custom_posts = db.execute(
        "SELECT sp.*, u.username FROM shared_posts sp JOIN users u ON sp.user_id = u.id WHERE sp.share_type = 'custom' AND sp.shared_to_user_id = ? ORDER BY sp.created_at DESC",
        (current_user_id,)
    ).fetchall()
    
    for post in custom_posts:
        posts.append(dict(post))
    
    # Remove duplicates and sort by created_at
    seen = set()
    unique_posts = []
    for post in posts:
        post_id = post["id"]
        if post_id not in seen:
            seen.add(post_id)
            unique_posts.append(post)
    
    unique_posts.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Get full post data (category, entities, fields, etc.)
    posts_data = []
    for post in unique_posts:
        category = db.execute(
            "SELECT * FROM categories WHERE id = ?",
            (post["category_id"],)
        ).fetchone()
        
        if not category:
            continue
        
        entity_ids = json.loads(post["entity_ids"])
        entities = []
        for entity_id in entity_ids:
            # Convert to int if it's a string
            entity_id_int = int(entity_id) if isinstance(entity_id, str) else entity_id
            entity = db.execute(
                "SELECT * FROM entities WHERE id = ? AND category_id = ?",
                (entity_id_int, post["category_id"])
            ).fetchone()
            if entity:
                entities.append(entity)
        
        if not entities:
            continue
        
        fields = db.execute(
            "SELECT * FROM fields WHERE category_id = ? ORDER BY display_order, id",
            (post["category_id"],)
        ).fetchall()
        
        # Get field values and tags for entities
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
                
                if field["field_type"] == "textarea" and raw_value:
                    raw_value = raw_value.strip()
                    if '\n' in raw_value:
                        lines = raw_value.split('\n')
                        cleaned_lines = [line.lstrip() for line in lines]
                        raw_value = '\n'.join(cleaned_lines)
                
                values[field_id] = raw_value
                
                if not primary_image and field["field_type"] == "image" and raw_value:
                    primary_image = raw_value
            return values, primary_image
        
        def get_entity_tags(entity_id):
            tags = db.execute(
                """SELECT t.* FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_id = ?""",
                (entity_id,)
            ).fetchall()
            return [{"id": tag["id"], "name": tag["name"], "color": tag["color"]} for tag in tags]
        
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
        
        # Get likes for this post
        like_count = db.execute(
            "SELECT COUNT(*) FROM post_likes WHERE post_id = ?",
            (post["id"],)
        ).fetchone()[0]
        
        # Check if current user liked this post
        user_liked = db.execute(
            "SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?",
            (post["id"], current_user_id)
        ).fetchone() is not None
        
        # Convert post to dict and ensure visibility settings are included
        post_dict = dict(post)
        # Ensure visibility settings default to 1 if not set
        # Use dict.get() after converting to dict, or access Row directly
        show_like_count = post_dict.get("show_like_count", 1) if post_dict.get("show_like_count") is not None else 1
        show_like_persons = post_dict.get("show_like_persons", 1) if post_dict.get("show_like_persons") is not None else 1
        show_comments = post_dict.get("show_comments", 1) if post_dict.get("show_comments") is not None else 1
        
        post_dict["show_like_count"] = show_like_count
        post_dict["show_like_persons"] = show_like_persons
        post_dict["show_comments"] = show_comments
        
        # Get likers (if visibility allows)
        likers = []
        if show_like_persons:
            likers_query = db.execute(
                "SELECT u.id, u.username FROM post_likes pl JOIN users u ON pl.user_id = u.id WHERE pl.post_id = ? ORDER BY pl.created_at DESC LIMIT 10",
                (post["id"],)
            ).fetchall()
            likers = [{"id": l["id"], "username": l["username"]} for l in likers_query]
        
        # Get comments - always fetch all comments
        # We'll filter what to show in the template based on visibility and ownership
        comments_query = db.execute(
            "SELECT pc.*, u.username FROM post_comments pc JOIN users u ON pc.user_id = u.id WHERE pc.post_id = ? ORDER BY pc.created_at ASC",
            (post["id"],)
        ).fetchall()
        comments = [{
            "id": int(c["id"]),
            "user_id": int(c["user_id"]),  # Ensure user_id is integer for comparison
            "username": c["username"],
            "comment_text": c["comment_text"],
            "created_at": c["created_at"]
        } for c in comments_query]
        
        # Check if current user has any comments on this post
        has_own_comments = any(comment["user_id"] == current_user_id for comment in comments)
        
        posts_data.append({
            "post": post_dict,
            "category": dict(category),
            "entities_data": entities_data,
            "fields": [{"id": f["id"], "label": f["label"], "field_type": f["field_type"]} for f in fields],
            "num_entities": len(entities_data),
            "like_count": like_count,
            "user_liked": user_liked,
            "likers": likers,
            "comments": comments,
            "is_creator": post["user_id"] == current_user_id,
            "show_comments_to_user": show_comments or (post["user_id"] == current_user_id),
            "current_user_id": int(current_user_id),  # Ensure current_user_id is integer
            "show_comments_value": show_comments,  # Explicit boolean value for template
            "has_own_comments": has_own_comments  # Pre-computed flag for template
        })
    
    # Get all users for friend requests
    all_users = db.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username",
        (current_user_id,)
    ).fetchall()
    
    # Get pending friend requests
    pending_requests = db.execute(
        "SELECT f.*, u.username FROM friendships f JOIN users u ON f.requester_id = u.id WHERE f.addressee_id = ? AND f.status = 'pending'",
        (current_user_id,)
    ).fetchall()
    
    # Get sent friend requests
    sent_requests = db.execute(
        "SELECT f.*, u.username FROM friendships f JOIN users u ON f.addressee_id = u.id WHERE f.requester_id = ? AND f.status = 'pending'",
        (current_user_id,)
    ).fetchall()
    
    db.close()
    
    return render_template("newsfeed.html",
                         posts_data=posts_data,
                         all_users=[dict(u) for u in all_users],
                         pending_requests=[dict(r) for r in pending_requests],
                         sent_requests=[dict(r) for r in sent_requests],
                         friends=friend_ids)

@app.route("/friend/request", methods=["POST"])
def request_friend():
    """Send a friend request"""
    if not session.get("user_id"):
        return redirect("/login")
    
    addressee_id = request.form.get("user_id")
    if not addressee_id:
        flash("User ID is required")
        return redirect("/newsfeed")
    
    db = get_db()
    
    # Check if friendship already exists
    existing = db.execute(
        "SELECT * FROM friendships WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)",
        (session["user_id"], int(addressee_id), int(addressee_id), session["user_id"])
    ).fetchone()
    
    if existing:
        flash("Friend request already exists or you are already friends")
    else:
        db.execute(
            "INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')",
            (session["user_id"], int(addressee_id))
        )
        db.commit()
        flash("Friend request sent!")
    
    db.close()
    return redirect("/newsfeed")

@app.route("/friend/accept", methods=["POST"])
def accept_friend():
    """Accept a friend request"""
    if not session.get("user_id"):
        return redirect("/login")
    
    request_id = request.form.get("request_id")
    if not request_id:
        flash("Request ID is required")
        return redirect("/newsfeed")
    
    db = get_db()
    
    # Verify the request is for the current user
    friendship = db.execute(
        "SELECT * FROM friendships WHERE id = ? AND addressee_id = ?",
        (int(request_id), session["user_id"])
    ).fetchone()
    
    if not friendship:
        flash("Friend request not found")
    else:
        db.execute(
            "UPDATE friendships SET status = 'accepted', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (int(request_id),)
        )
        db.commit()
        flash("Friend request accepted!")
    
    db.close()
    return redirect("/newsfeed")

@app.route("/friend/reject", methods=["POST"])
def reject_friend():
    """Reject a friend request"""
    if not session.get("user_id"):
        return redirect("/login")
    
    request_id = request.form.get("request_id")
    if not request_id:
        flash("Request ID is required")
        return redirect("/newsfeed")
    
    db = get_db()
    
    # Verify the request is for the current user
    friendship = db.execute(
        "SELECT * FROM friendships WHERE id = ? AND addressee_id = ?",
        (int(request_id), session["user_id"])
    ).fetchone()
    
    if not friendship:
        flash("Friend request not found")
    else:
        db.execute("DELETE FROM friendships WHERE id = ?", (int(request_id),))
        db.commit()
        flash("Friend request rejected")
    
    db.close()
    return redirect("/newsfeed")

@app.route("/api/post/<int:post_id>/like", methods=["POST"])
def toggle_like(post_id):
    """Like or unlike a post"""
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    
    # Check if user can see this post
    post = db.execute(
        "SELECT * FROM shared_posts WHERE id = ?",
        (post_id,)
    ).fetchone()
    
    if not post:
        db.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if user can see the post (public, friend, or custom)
    current_user_id = session["user_id"]
    can_see = False
    
    if post["share_type"] == "public":
        can_see = True
    elif post["share_type"] == "friend":
        # Check if they are friends
        friendship = db.execute(
            "SELECT * FROM friendships WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)) AND status = 'accepted'",
            (current_user_id, post["user_id"], post["user_id"], current_user_id)
        ).fetchone()
        can_see = friendship is not None
    elif post["share_type"] == "custom":
        can_see = post["shared_to_user_id"] == current_user_id
    
    if not can_see and post["user_id"] != current_user_id:
        db.close()
        return jsonify({"error": "Access denied"}), 403
    
    # Toggle like
    existing_like = db.execute(
        "SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?",
        (post_id, current_user_id)
    ).fetchone()
    
    if existing_like:
        # Unlike
        db.execute(
            "DELETE FROM post_likes WHERE post_id = ? AND user_id = ?",
            (post_id, current_user_id)
        )
        action = "unliked"
    else:
        # Like
        db.execute(
            "INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)",
            (post_id, current_user_id)
        )
        action = "liked"
    
    db.commit()
    
    # Get updated like count and list
    like_count = db.execute(
        "SELECT COUNT(*) FROM post_likes WHERE post_id = ?",
        (post_id,)
    ).fetchone()[0]
    
    likers = db.execute(
        "SELECT u.id, u.username FROM post_likes pl JOIN users u ON pl.user_id = u.id WHERE pl.post_id = ? ORDER BY pl.created_at DESC",
        (post_id,)
    ).fetchall()
    
    db.close()
    
    return jsonify({
        "action": action,
        "like_count": like_count,
        "likers": [{"id": l["id"], "username": l["username"]} for l in likers],
        "is_liked": action == "liked"
    })

@app.route("/api/post/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    """Add a comment to a post"""
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    
    comment_text = request.json.get("comment_text", "").strip()
    if not comment_text:
        return jsonify({"error": "Comment text is required"}), 400
    
    db = get_db()
    
    # Check if user can see this post
    post = db.execute(
        "SELECT * FROM shared_posts WHERE id = ?",
        (post_id,)
    ).fetchone()
    
    if not post:
        db.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if user can see the post
    current_user_id = session["user_id"]
    can_see = False
    
    if post["share_type"] == "public":
        can_see = True
    elif post["share_type"] == "friend":
        friendship = db.execute(
            "SELECT * FROM friendships WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)) AND status = 'accepted'",
            (current_user_id, post["user_id"], post["user_id"], current_user_id)
        ).fetchone()
        can_see = friendship is not None
    elif post["share_type"] == "custom":
        can_see = post["shared_to_user_id"] == current_user_id
    
    if not can_see and post["user_id"] != current_user_id:
        db.close()
        return jsonify({"error": "Access denied"}), 403
    
    # Add comment
    cursor = db.execute(
        "INSERT INTO post_comments (post_id, user_id, comment_text) VALUES (?, ?, ?)",
        (post_id, current_user_id, comment_text)
    )
    comment_id = cursor.lastrowid
    db.commit()
    
    # Get the new comment with user info
    comment = db.execute(
        "SELECT pc.*, u.username FROM post_comments pc JOIN users u ON pc.user_id = u.id WHERE pc.id = ?",
        (comment_id,)
    ).fetchone()
    
    db.close()
    
    return jsonify({
        "comment": {
            "id": comment["id"],
            "user_id": comment["user_id"],
            "username": comment["username"],
            "comment_text": comment["comment_text"],
            "created_at": comment["created_at"]
        }
    })

@app.route("/api/post/<int:post_id>/comments", methods=["GET"])
def get_comments(post_id):
    """Get all comments for a post"""
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    
    # Check if user can see this post
    post = db.execute(
        "SELECT * FROM shared_posts WHERE id = ?",
        (post_id,)
    ).fetchone()
    
    if not post:
        db.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if user can see the post
    current_user_id = session["user_id"]
    can_see = False
    
    if post["share_type"] == "public":
        can_see = True
    elif post["share_type"] == "friend":
        friendship = db.execute(
            "SELECT * FROM friendships WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)) AND status = 'accepted'",
            (current_user_id, post["user_id"], post["user_id"], current_user_id)
        ).fetchone()
        can_see = friendship is not None
    elif post["share_type"] == "custom":
        can_see = post["shared_to_user_id"] == current_user_id
    
    if not can_see and post["user_id"] != current_user_id:
        db.close()
        return jsonify({"error": "Access denied"}), 403
    
    # Get comments
    comments = db.execute(
        "SELECT pc.*, u.username FROM post_comments pc JOIN users u ON pc.user_id = u.id WHERE pc.post_id = ? ORDER BY pc.created_at ASC",
        (post_id,)
    ).fetchall()
    
    db.close()
    
    return jsonify({
        "comments": [{
            "id": c["id"],
            "user_id": c["user_id"],
            "username": c["username"],
            "comment_text": c["comment_text"],
            "created_at": c["created_at"]
        } for c in comments]
    })

@app.route("/api/post/<int:post_id>/visibility", methods=["POST"])
def update_post_visibility(post_id):
    """Update visibility settings for a post (creator only)"""
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # Get JSON data from request
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        db = get_db()
        
        # Check if user is the creator
        post = db.execute(
            "SELECT * FROM shared_posts WHERE id = ? AND user_id = ?",
            (post_id, session["user_id"])
        ).fetchone()
        
        if not post:
            db.close()
            return jsonify({"error": "Post not found or access denied"}), 404
        
        # Update visibility settings
        show_like_count = 1 if data.get("show_like_count", True) else 0
        show_like_persons = 1 if data.get("show_like_persons", True) else 0
        show_comments = 1 if data.get("show_comments", True) else 0
        
        db.execute(
            "UPDATE shared_posts SET show_like_count = ?, show_like_persons = ?, show_comments = ? WHERE id = ?",
            (show_like_count, show_like_persons, show_comments, post_id)
        )
        db.commit()
        db.close()
        
        return jsonify({
            "success": True,
            "show_like_count": bool(show_like_count),
            "show_like_persons": bool(show_like_persons),
            "show_comments": bool(show_comments)
        })
    except Exception as e:
        # Log the error for debugging
        print(f"Error updating visibility: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

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
    sort_by = request.args.get("sort", "display_order")
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
    valid_sort_fields = ["name", "created_at", "updated_at", "display_order"]
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
                    delete_image_and_thumbnails(row["value"])
                elif row["field_type"] == "image_album":
                    try:
                        image_list = json.loads(row["value"])
                        for img_filename in image_list:
                            delete_image_and_thumbnails(img_filename)
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
        "SELECT * FROM categories WHERE user_id = ? AND section_id IS NULL ORDER BY display_order, created_at DESC",
        (user_id,)
    ).fetchall()
    
    # Get categories for each section
    sections_with_categories = []
    for section in sections:
        categories = db.execute(
            "SELECT * FROM categories WHERE section_id = ? ORDER BY display_order, created_at DESC",
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

@app.route("/admin/user/<int:user_id>/backup/zip")
def admin_backup_user_zip(user_id):
    """Download backup for a specific user as ZIP (JSON + all images)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    # Build user backup structure (same as JSON backup)
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
    
    # Collect image filenames from field_values
    image_filenames = set()
    for cat in backup_data["user"]["categories"]:
        for entity in cat.get("entities", []):
            for fv in entity.get("field_values", []):
                val = fv.get("value")
                if not val:
                    continue
                field_id = fv.get("field_id")
                field_type = None
                for f in cat.get("fields", []):
                    if f.get("id") == field_id:
                        field_type = f.get("field_type")
                        break
                if field_type == "image":
                    image_filenames.add(val)
                elif field_type == "image_album":
                    try:
                        for img in json.loads(val):
                            image_filenames.add(img)
                    except (json.JSONDecodeError, TypeError):
                        pass
    
    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add JSON backup
        zf.writestr("backup.json", json.dumps(backup_data, indent=2, ensure_ascii=False))
        
        # Add images
        for filename in image_filenames:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                zf.write(filepath, f"images/{filename}")
            # Also add thumbnail if exists
            base_name = os.path.splitext(filename)[0]
            thumb_filename = f"{base_name}_thumb100.jpg"
            thumb_path = os.path.join(THUMBNAIL_FOLDER, thumb_filename)
            if os.path.exists(thumb_path):
                zf.write(thumb_path, f"images/thumbnails/{thumb_filename}")
    
    zip_buffer.seek(0)
    response = make_response(zip_buffer.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename=user_backup_{user["username"]}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
    
    return response

@app.route("/admin/user/<int:user_id>/import", methods=["GET", "POST"])
def admin_import_user(user_id):
    """Import user data from backup file (ZIP or JSON)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found")
        db.close()
        return redirect("/admin/users")
    
    if request.method == "GET":
        db.close()
        return render_template("admin_import.html", user=user)
    
    # POST: handle file upload
    if 'backup_file' not in request.files:
        flash("No file selected")
        db.close()
        return redirect(url_for("admin_import_user", user_id=user_id))
    
    file = request.files['backup_file']
    if file.filename == '':
        flash("No file selected")
        db.close()
        return redirect(url_for("admin_import_user", user_id=user_id))
    
    try:
        backup_data = None
        temp_dir = None
        image_map = {}  # old_filename -> new_filename (for deduplication/collision)
        
        if file.filename.lower().endswith('.zip'):
            # Extract ZIP
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, 'upload.zip')
            file.save(zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Read backup.json
                if 'backup.json' not in zf.namelist():
                    # Try root
                    for name in zf.namelist():
                        if name.endswith('.json'):
                            backup_data = json.loads(zf.read(name).decode('utf-8'))
                            break
                    if not backup_data:
                        raise ValueError("No backup.json found in ZIP")
                else:
                    backup_data = json.loads(zf.read('backup.json').decode('utf-8'))
                
                # Extract user data
                user_data = backup_data.get("user", backup_data)
                categories = user_data.get("categories", [])
                
                # Copy images to upload folder
                for name in zf.namelist():
                    if name.startswith('images/') and not name.endswith('/'):
                        # Extract to temp, then copy to uploads
                        rel_path = name[len('images/'):]
                        if 'thumbnails/' in rel_path:
                            dest_dir = THUMBNAIL_FOLDER
                            dest_name = rel_path.replace('thumbnails/', '')
                        else:
                            dest_dir = app.config['UPLOAD_FOLDER']
                            dest_name = rel_path
                        
                        dest_path = os.path.join(dest_dir, dest_name)
                        os.makedirs(os.path.dirname(dest_path) if os.path.dirname(dest_path) else dest_dir, exist_ok=True)
                        with zf.open(name) as src:
                            with open(dest_path, 'wb') as dst:
                                shutil.copyfileobj(src, dst)
                        # Map original filename (without thumbnails/) for field_values
                        if 'thumbnails/' not in rel_path:
                            image_map[dest_name] = dest_name  # same name, we copied it
        else:
            # Assume JSON file
            backup_data = json.loads(file.read().decode('utf-8'))
        
        if not backup_data:
            raise ValueError("Invalid backup file")
        
        user_data = backup_data.get("user", backup_data)
        sections_data = user_data.get("sections", [])
        categories_data = user_data.get("categories", [])
        
        # ID mapping for import (old_id -> new_id)
        section_id_map = {}
        category_id_map = {}
        field_id_map = {}
        tag_id_map = {}
        entity_id_map = {}
        
        def get_last_id(cursor):
            rid = cursor.lastrowid
            return rid() if callable(rid) else rid
        
        # Import sections
        for sec in sections_data:
            sec_id = sec.get("id")
            name = sec.get("name", "Imported Section")
            display_order = sec.get("display_order", 0)
            cur = db.execute(
                "INSERT INTO sections (user_id, name, display_order) VALUES (?, ?, ?)",
                (user_id, name, display_order)
            )
            new_section_id = get_last_id(cur)
            if new_section_id is None:
                row = db.execute("SELECT id FROM sections WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
                new_section_id = row["id"] if row else sec_id
            section_id_map[sec_id] = new_section_id
        
        # Import categories (with section_id mapping)
        for cat in categories_data:
            old_cat_id = cat.get("id")
            old_section_id = cat.get("section_id")
            new_section_id = section_id_map.get(old_section_id) if old_section_id else None
            name = cat.get("name", "Imported Category")
            display_order = cat.get("display_order", 0)
            cur = db.execute(
                "INSERT INTO categories (user_id, section_id, name, display_order) VALUES (?, ?, ?, ?)",
                (user_id, new_section_id, name, display_order)
            )
            new_cat_id = get_last_id(cur)
            if new_cat_id is None:
                row = db.execute("SELECT id FROM categories WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
                new_cat_id = row["id"] if row else old_cat_id
            category_id_map[old_cat_id] = new_cat_id
            
            # Import fields for this category
            for f in cat.get("fields", []):
                old_field_id = f.get("id")
                label = f.get("label", "")
                field_type = f.get("field_type", "text")
                options = f.get("options") or ""
                required = 1 if f.get("required") else 0
                fo = f.get("display_order", 0)
                cur = db.execute(
                    "INSERT INTO fields (category_id, label, field_type, options, required, display_order) VALUES (?, ?, ?, ?, ?, ?)",
                    (new_cat_id, label, field_type, options, required, fo)
                )
                new_field_id = get_last_id(cur)
                if new_field_id is None:
                    row = db.execute("SELECT id FROM fields WHERE category_id = ? ORDER BY id DESC LIMIT 1", (new_cat_id,)).fetchone()
                    new_field_id = row["id"] if row else old_field_id
                field_id_map[(old_cat_id, old_field_id)] = new_field_id
            
            # Import tags for this category
            for t in cat.get("tags", []):
                old_tag_id = t.get("id")
                tag_name = t.get("name", "")
                color = t.get("color", "#007bff")
                cur = db.execute(
                    "INSERT INTO tags (category_id, name, color) VALUES (?, ?, ?)",
                    (new_cat_id, tag_name, color)
                )
                new_tag_id = get_last_id(cur)
                if new_tag_id is None:
                    row = db.execute("SELECT id FROM tags WHERE category_id = ? ORDER BY id DESC LIMIT 1", (new_cat_id,)).fetchone()
                    new_tag_id = row["id"] if row else old_tag_id
                tag_id_map[(old_cat_id, old_tag_id)] = new_tag_id
            
            # Import entities for this category
            for ent in cat.get("entities", []):
                old_entity_id = ent.get("id")
                ent_name = ent.get("name", "Imported Entity")
                cur = db.execute(
                    "INSERT INTO entities (category_id, name) VALUES (?, ?)",
                    (new_cat_id, ent_name)
                )
                new_entity_id = get_last_id(cur)
                if new_entity_id is None:
                    row = db.execute("SELECT id FROM entities WHERE category_id = ? ORDER BY id DESC LIMIT 1", (new_cat_id,)).fetchone()
                    new_entity_id = row["id"] if row else old_entity_id
                entity_id_map[(old_cat_id, old_entity_id)] = new_entity_id
                
                # Import field values
                for fv in ent.get("field_values", []):
                    old_field_id = fv.get("field_id")
                    value = fv.get("value") or ""
                    new_field_id = field_id_map.get((old_cat_id, old_field_id))
                    if new_field_id:
                        db.execute(
                            "INSERT INTO field_values (entity_id, field_id, value) VALUES (?, ?, ?)",
                            (new_entity_id, new_field_id, value)
                        )
                
                # Import entity_tags
                for tag_id in ent.get("tag_ids", []):
                    new_tag_id = tag_id_map.get((old_cat_id, tag_id))
                    if new_tag_id:
                        db.execute(
                            "INSERT INTO entity_tags (entity_id, tag_id) VALUES (?, ?)",
                            (new_entity_id, new_tag_id)
                        )
        
        db.commit()
        
        flash(f"Successfully imported data for {user['username']}")
        
    except Exception as e:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        flash(f"Import failed: {str(e)}")
        db.close()
        return redirect(url_for("admin_import_user", user_id=user_id))
    
    db.close()
    return redirect(url_for("admin_view_user_data", user_id=user_id))

if __name__ == "__main__":
    app.run(debug=True)
