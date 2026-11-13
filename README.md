# Litec
A lightweight, beginner-friendly C web framework with clean syntax, simple routing, templates, forms, sessions, and more.



# LiteC

### Build web applications with C, the simple way.

LiteC is a lightweight and beginner-friendly web framework written in C, designed to make web development simpler, cleaner, and more accessible.

Inspired by the simplicity of frameworks like Flask, LiteC provides an expressive API that allows developers to build web applications without dealing with unnecessary boilerplate or complicated request-handling code.

## ✨ Features

- **Simple Routing** – Define routes using clean `GET()` and `POST()` syntax.
- **Templates** – Render HTML pages with ease.
- **Form Handling** – Easily receive and process submitted form data.
- **Sessions** – Manage user sessions and authentication.
- **File Uploads** – Handle file uploads with simple API calls.
- **HTTP Responses** – Send responses without repetitive boilerplate.
- **Lightweight** – Built in C with minimal dependencies.
- **Beginner-Friendly** – Designed to make C web development approachable.

## 💡 Philosophy

LiteC follows one simple idea:

**Less boilerplate. More building.**

You shouldn't need hundreds of lines of code to create a simple web application in C.

LiteC aims to make C web development feel natural, readable, and enjoyable.

## 🚀 Getting Started

Include LiteC in your C application:

```c
#include "lite.h"
```

### Hello World

```c
#include "lite.h"

GET("/") {
    return html("<h1>Hello from LiteC!</h1>");
}

int main() {
    run(8080);
}
```

Start your application and visit:

`http://127.0.0.1:8080`

## 📚 Examples

### 1. Routing

Define routes using simple and readable syntax.

```c
#include "lite.h"

GET("/") {
    return html("<h1>Home Page</h1>");
}

GET("/about") {
    return html("<h1>About LiteC</h1>");
}

GET("/contact") {
    return html("<h1>Contact Us</h1>");
}

int main() {
    run(8080);
}
```

### 2. POST Requests

Handle submitted data using POST routes.

```c
#include "lite.h"

GET("/") {
    return html(
        "<form method='POST' action='/login'>"
        "<input name='username' placeholder='Username'>"
        "<button>Login</button>"
        "</form>"
    );
}

POST("/login") {
    const char *username = form_get("username", "");

    return html("<h1>Welcome!</h1>");
}

int main() {
    run(8080);
}
```

### 3. HTML Responses

Return HTML directly from your routes.

```c
#include "lite.h"

GET("/") {
    return html(
        "<h1>Welcome to LiteC</h1>"
        "<p>Build something amazing.</p>"
    );
}

int main() {
    run(8080);
}
```

### 4. Templates

Keep your HTML separate from your C code.

```c
#include "lite.h"

GET("/") {
    return render("index.html");
}

int main() {
    run(8080);
}
```

Example `index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>My LiteC App</title>
</head>
<body>
    <h1>Hello from LiteC!</h1>
    <p>Welcome to my application.</p>
</body>
</html>
```

### 5. Form Handling

Retrieve submitted form values using `form_get()`.

```c
#include "lite.h"

POST("/register") {
    const char *name = form_get("name", "");
    const char *email = form_get("email", "");

    return html("<h1>Registration received!</h1>");
}

int main() {
    run(8080);
}
```

You can also retrieve numeric values:

```c
POST("/profile") {
    const char *name = form_get("name", "");
    int age = form_get("age", 0);

    return html("<h1>Profile received!</h1>");
}
```

### 6. Sessions

Manage user sessions with simple function calls.

**Set a session:**

```c
POST("/login") {
    const char *username = form_get("username", "");

    session_set("username", username);

    return redirect("/dashboard");
}
```

**Read a session:**

```c
GET("/dashboard") {
    const char *username = session_get("username");

    if (!username) {
        return redirect("/");
    }

    return html("<h1>Welcome back!</h1>");
}
```

**Clear a session:**

```c
GET("/logout") {
    session_clear();

    return redirect("/");
}
```

### 7. File Uploads

Handle uploaded files using `upload_save()`.

```c
#include "lite.h"

POST("/upload") {
    int status;

    upload_save("avatar", status, "uploads/");

    return html("<h1>Upload processed!</h1>");
}

int main() {
    run(8080);
}
```

The status variable allows you to check the upload result.

### 8. Complete Mini Application

A simple login application combining routing, forms, sessions, and responses.

```c
#include "lite.h"

GET("/") {
    return html(
        "<form method='POST' action='/login'>"
        "<input name='username' placeholder='Username'>"
        "<button>Login</button>"
        "</form>"
    );
}

POST("/login") {
    const char *username = form_get("username", "");

    if (!username[0]) {
        return html("<h1>Username required</h1>");
    }

    session_set("username", username);

    return redirect("/dashboard");
}

GET("/dashboard") {
    const char *username = session_get("username");

    if (!username) {
        return redirect("/");
    }

    return html("<h1>Welcome to your dashboard!</h1>");
}

GET("/logout") {
    session_clear();

    return redirect("/");
}

int main() {
    run(8080);
}
```

## 🎯 Goal

To make building web applications in C easier for everyone, from beginners learning C to experienced developers who want a lightweight alternative to traditional web frameworks.

## 🤝 Contributing

Contributions, suggestions, bug reports, and ideas are welcome.

If you like LiteC, consider giving the project a ⭐ on GitHub.

## 📜 License

See the repository's LICENSE file for licensing information.

---

**LiteC — Web development, simplified.**
