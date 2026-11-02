# Marianna Limone · English Lessons

Interactive English lessons, published with GitHub Pages.

## Add a new lesson
1. Put the lesson's HTML file in the `lessons/` folder.
2. In `index.html`, copy one `<li>…</li>` block inside `#lessonList` and update the link, title and description.
3. Commit and push — the site updates in about a minute.

## Teacher's Area (password-protected)
Pages for teachers only live in `private/` on this computer (never uploaded).
`tools/encrypt.mjs` encrypts them into `teacher/`, which is what gets published.

1. Save or edit the page in `private/` and add it to the list in `private/index.html`.
2. Run `node tools/encrypt.mjs --publish` and type the password.

Change password: `node tools/encrypt.mjs --new-password --publish`.
⚠ Keep a backup of `private/`: it is not on GitHub.
