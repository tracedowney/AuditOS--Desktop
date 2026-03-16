Write-Host "Building AuditOS release..."

pip install pyinstaller

pyinstaller --noconfirm --windowed --name AuditOS app/main.py

Write-Host "Build complete."
