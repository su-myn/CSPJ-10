# Personal Database App

A Flask-based personal database application that allows users to organize and manage various types of entities (classmates, lecturers, pets, favorite millionaires, etc.) with custom fields, tags, filtering, sorting, and comparison features.

## Features

- **User Authentication**: Login and registration system
- **Category Management**: Create and manage custom categories
- **Custom Fields**: Add custom fields to categories with various types:
  - Text
  - Multiline Text
  - Email
  - Integer
  - Number (Decimal)
  - Date/Time
  - Select (Dropdown)
  - Radio Button
  - Checkbox
  - Image
- **Entity Management**: Add, edit, and delete entities within categories
- **Tag System**: Create tags and assign multiple tags to entities
- **Filtering**: Filter entities by tags
- **Sorting**: Sort entities by name, creation date, or last update date
- **Comparison**: Compare two entities side-by-side
- **Field Management**: Add, edit, delete, and reorder custom fields for each category

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Register/Login**: Create an account or log in with existing credentials
2. **Create Categories**: Click "New Category" to create categories like "Classmate", "Lecturer", "Pet", etc.
3. **Manage Fields**: For each category, click "Manage Fields" to add custom fields (Age, Net Worth, Industry, etc.)
4. **Add Entities**: Add entities to categories with all the custom field values
5. **Add Tags**: Create tags in the Tags section and assign them to entities
6. **Filter & Sort**: Use the filter and sort options on the category page
7. **Compare**: Enable "Compare Mode" and select two entities to compare them side-by-side

## Project Structure

```
CSPJ-01/
├── app.py                 # Main Flask application
├── requirements.txt        # Python dependencies
├── database.db            # SQLite database (created automatically)
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── category.html
│   ├── new_category.html
│   ├── new_entity.html
│   ├── edit_entity.html
│   ├── manage_fields.html
│   ├── tags.html
│   └── compare.html
├── static/
│   ├── css/
│   │   └── style.css      # Custom styles
│   ├── js/
│   │   └── main.js        # JavaScript functions
│   └── uploads/           # Image uploads (created automatically)
└── README.md
```

## Database Schema

- **users**: User accounts
- **categories**: User-created categories
- **fields**: Custom fields for categories
- **entities**: Entities within categories
- **tags**: User-created tags
- **entity_tags**: Many-to-many relationship between entities and tags
- **field_values**: Values for custom fields of entities

## Notes

- Images are stored in `static/uploads/` directory
- Database is automatically initialized on first run
- All data is user-specific (users can only see their own categories and entities)
- Following CS50 Flask patterns with Flask-Session for session management

