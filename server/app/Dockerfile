FROM python:3.11

WORKDIR /app

COPY requirements.txt .

RUN pip install -i https://mirrors.ustc.edu.cn/pypi/simple/ --no-cache-dir -r requirements.txt

COPY . .

CMD ["tail", "-f", "/dev/null"]
