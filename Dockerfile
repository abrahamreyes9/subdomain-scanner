FROM python:3.11-slim

# Install amass
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && AMASS_VERSION=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
 && curl -fsSL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_amd64.zip" \
      -o /tmp/amass.zip \
 && unzip -j /tmp/amass.zip "*/amass" -d /usr/local/bin \
 && chmod +x /usr/local/bin/amass \
 && rm /tmp/amass.zip \
 && apt-get purge -y --auto-remove curl unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
