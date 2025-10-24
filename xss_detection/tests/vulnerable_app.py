"""
Simple vulnerable web application for XSS testing
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class VulnerableHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        # Parse URL and parameters
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # Set response headers
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Create vulnerable responses
        if parsed_path.path == '/':
            # Home page - reflects search parameter without escaping
            search_term = query_params.get('q', [''])[0]
            search_term2 = query_params.get('search', [''])[0]
            
            response = f"""
            <html>
            <head><title>Vulnerable Test App</title></head>
            <body>
                <h1>Welcome to Vulnerable Test App</h1>
                <p>This app has XSS vulnerabilities for testing</p>
                
                <form action="/search" method="get">
                    <input type="text" name="q" placeholder="Search...">
                    <input type="submit" value="Search">
                </form>
                
                <h2>Search Results</h2>
                <p>You searched for: {search_term}</p>
                <p>Alternative search: {search_term2}</p>
                
                <h2>Test Links</h2>
                <ul>
                    <li><a href="/search?q=test">Search Page</a></li>
                    <li><a href="/contact">Contact Page</a></li>
                    <li><a href="/profile?name=user">Profile Page</a></li>
                </ul>
            </body>
            </html>
            """
            
        elif parsed_path.path == '/search':
            # Search page - reflects query without escaping (VULNERABLE)
            query = query_params.get('q', [''])[0]
            response = f"""
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results</h1>
                <p>Results for: <strong>{query}</strong></p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
            
        elif parsed_path.path == '/contact':
            # Contact page - safe (escaped output)
            name = query_params.get('name', [''])[0]
            # HTML escape the name
            safe_name = name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            response = f"""
            <html>
            <head><title>Contact Us</title></head>
            <body>
                <h1>Contact Us</h1>
                <p>Hello, {safe_name}!</p>
                <p>This page is safe - inputs are escaped.</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
            
        elif parsed_path.path == '/profile':
            # Profile page - vulnerable to XSS in URL parameters
            username = query_params.get('name', [''])[0]
            response = f"""
            <html>
            <head><title>User Profile</title></head>
            <body>
                <h1>User Profile</h1>
                <p>Welcome, {username}!</p>
                <div id="user-info">
                    Username: {username}
                </div>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
            
        else:
            # 404 for unknown pages
            response = """
            <html>
            <head><title>404 Not Found</title></head>
            <body>
                <h1>404 - Page Not Found</h1>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
        
        self.wfile.write(response.encode('utf-8'))
    
    def do_POST(self):
        # Handle POST requests for stored XSS testing
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        post_params = urllib.parse.parse_qs(post_data)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        if self.path == '/comment':
            # Simulate storing a comment (in memory)
            comment = post_params.get('comment', [''])[0]
            response = f"""
            <html>
            <head><title>Comment Submitted</title></head>
            <body>
                <h1>Comment Submitted</h1>
                <p>Your comment: {comment}</p>
                <p><em>Comment would be stored here in a real app</em></p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
        else:
            response = """
            <html>
            <body>
                <h1>Form Submitted</h1>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
        
        self.wfile.write(response.encode('utf-8'))

def run_server(port=8080):
    """Run the vulnerable test server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, VulnerableHandler)
    print(f"Starting vulnerable test server on http://localhost:{port}")
    print("This server has intentional XSS vulnerabilities for testing")
    print("Press Ctrl+C to stop the server")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()