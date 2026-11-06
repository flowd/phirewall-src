FROM node:24-slim
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV HOST=0.0.0.0
ENV PORT=4321
EXPOSE 4321

RUN echo 'shopt -s histappend\nexport PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> ~/.bashrc

RUN corepack enable

RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip libgtk-3-0 libgbm-dev libnotify-dev libnss3 libxss1 libasound2 libxtst6 xauth xvfb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["pnpm", "dev"]
