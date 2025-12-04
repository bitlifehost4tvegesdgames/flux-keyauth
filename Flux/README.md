# Flux Licensing (Advanced Sidebar + Settings)

- Sidebar navigation (Dashboard, Validate, Settings, Login/Logout)
- Settings page: change Site Name & Accent, upload logo (stored at `static/logo.png`)
- Everything else: create/revoke/delete keys, validation API with activations

## Run
```
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
copy .env.example .env
python app.py
```
Open http://127.0.0.1:5000

## Notes
- Put your real logo at `static/logo.png` (PNG recommended).
- If uploading via Settings page, file saved to `static/logo.png`.


## Our discord

https://discord.gg/darkmoonlove 