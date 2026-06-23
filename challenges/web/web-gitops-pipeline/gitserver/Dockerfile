FROM python:3.11-slim

RUN apt-get update && apt-get install -y git --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install flask==3.0.0 --no-cache-dir

# Initialize the git repository with intentional secrets in history
RUN git config --global user.email "ci@corp.local" \
    && git config --global user.name "CI System" \
    && git config --global init.defaultBranch main

RUN mkdir -p /repo && cd /repo && git init \
    && echo "WEBHOOK_SECRET=sup3rs3cr3t_hmac_k3y" > .env \
    && echo "DB_PASSWORD=Pr0d_DB_P4ssw0rd!" >> .env \
    && git add .env \
    && git commit -m "Initial commit: add pipeline config" \
    && git rm .env \
    && echo "# Corp CI/CD Pipeline" > README.md \
    && echo "" >> README.md \
    && echo "Internal GitOps pipeline for automated deployments." >> README.md \
    && echo "" >> README.md \
    && echo "## Setup" >> README.md \
    && echo "Register a webhook via POST /webhook/register" >> README.md \
    && echo "webhook_url: http://webhook-runner:9001/run" > pipeline.yml \
    && echo "branch: main" >> pipeline.yml \
    && echo "steps:" >> pipeline.yml \
    && echo "  - name: test" >> pipeline.yml \
    && echo "    run: pytest tests/" >> pipeline.yml \
    && echo "  - name: deploy" >> pipeline.yml \
    && echo "    run: ./deploy.sh" >> pipeline.yml \
    && echo "#!/bin/bash" > deploy.sh \
    && echo "echo 'Deploying to production...'" >> deploy.sh \
    && chmod +x deploy.sh \
    && git add README.md pipeline.yml deploy.sh \
    && git commit -m "Remove secrets from repo, use vault instead"

COPY gitserver/app/ /app/
EXPOSE 8080
CMD ["python", "app.py"]
