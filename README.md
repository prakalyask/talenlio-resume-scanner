<h1>Document Scanner & Credit System 🚀</h1>
<h2>Project Overview</h2>
<p>
    This Django-based project provides a comprehensive solution for document scanning, credit management, and user
    authentication.
    It includes features for scanning documents (with daily credit limits), processing credit requests, and admin
    management.
    The backend API endpoints are designed for Postman testing, while separate endpoints are used for the UI.
</p>
<h2>Features ✨</h2>
<ul>
        <li><strong>User Management:</strong> Registration, login, logout, and profile viewing.</li>
        <li><strong>Credit System:</strong> Daily credit reset (20 credits/day) with options for credit requests.</li>
        <li><strong>Document Scanning:</strong> Upload and scan documents with credit deduction.</li>
        <li><strong>Soft Delete & Hard Delete:</strong> Support for soft deletion (marking as deleted) and hard deletion (permanent removal) of records.</li>
        <li><strong>AI Integration:</strong> Utilizes AI for intelligent document analysis and pattern recognition.</li>
        <li><strong>Admin Panel:</strong> Manage user accounts, view and approve/deny credit requests, and perform deletion operations.</li>
        <li><strong>API Endpoints:</strong> 
            <ul>
                <li>Endpoints designed for Postman testing (backend API).</li>
                <li>Separate endpoints available for UI interactions.</li>
            </ul>
        </li>
        <li><strong>Django Configuration:</strong> Custom settings, URL routing, middleware configuration, and environment management.</li>
    </ul>
<h2>Setup Instructions 🔧</h2>
<h3>1. Clone the Repository</h3>
<pre><code>
git clone https://github.com/prakalyask/talenlio-resume-scanner.git
cd backend
</code></pre>
<h3>2. Set Up Virtual Environment 🛠️</h3>
<pre><code>
python3 -m venv venv
source venv/bin/activate   <!-- For Linux/Mac -->
venv\Scripts\activate      <!-- For Windows -->
</code></pre>
<h3>3. Install Requirements</h3>
<pre><code>
pip install -r requirements.txt
</code></pre>
<h3>4. Configure Environment Variables</h3>
<p>Create a <code>.env</code> file in the project root with the following variables (adjust as needed):</p>
<pre><code>
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=*
</code></pre>
<h3>5. Apply Migrations</h3>
<pre><code>
python manage.py migrate
</code></pre>
<h3>6. Create Superuser (for Admin Access)</h3>
<pre><code>
python manage.py createsuperuser
</code></pre>
<h3>7. Run Development Server</h3>
<pre><code>
python manage.py runserver
</code></pre>
<h2>Django Configuration ⚙️</h2>
<p>
    The Django configuration is set up as follows:
</p>
<ul>
    <li><strong>settings.py:</strong> Contains the configuration for installed apps, middleware, database settings,
        and static/media files.</li>
    <li><strong>urls.py:</strong> Routes incoming requests to the appropriate apps and views. It includes separate
        URL patterns for API endpoints and the UI.</li>
    <li><strong>Middleware:</strong> Configured to handle authentication, security, and session management.</li>
    <li><strong>Environment-Specific Settings:</strong> Using a <code>.env</code> file to manage sensitive
        information and switch configurations between development and production.</li>
</ul>
<h2>API Endpoints for Postman Testing 📬</h2>
<p>The following endpoints are primarily intended for Postman or API testing. Separate endpoints are provided for UI
    interactions.</p>
<h3>Authentication</h3>
<ul>
    <li><code>POST /users/register/</code> - Register a new user.</li>
    <li><code>POST /users/login/</code> - Login user.</li>
    <li><code>POST /users/logout/</code> - Logout user.</li>
    <li><code>GET /users/profile/</code> - Fetch user profile.</li>
</ul>
<h3>Credits Management</h3>
<ul>
    <li><code>POST /users/credits/request/</code> - Request additional credits.</li>
    <li><code>GET /users/credits/requests/</code> - Admin view of all credit requests.</li>
    <li><code>POST /users/credits/requests/&lt;id&gt;/approve/</code> - Approve a credit request (admin).</li>
    <li><code>POST /users/credits/requests/&lt;id&gt;/deny/</code> - Deny a credit request (admin).</li>
</ul>
<h3>Document Scanning</h3>
<ul>
    <li><code>POST /users/scan/</code> - Upload and scan a document (this will deduct credits).</li>
</ul>
<h2>Additional UI Endpoints 🌐</h2>
<p>
    The UI endpoints are designed to serve the frontend application. These endpoints may return HTML or JSON
    formatted for UI rendering and are different from the API endpoints used in Postman testing.
</p>
<h2>Contributing 🤝</h2>
<p>
    Contributions are welcome! Please follow the standard pull request guidelines and ensure your changes pass all
    tests before merging.
</p>
