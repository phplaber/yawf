FROM selenium/standalone-chrome

WORKDIR /opt/yawf

COPY requirements.txt requirements.txt
RUN sudo apt-get update && sudo apt-get install -y python3-pip
RUN sudo pip3 install --break-system-packages -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

COPY . .

ENTRYPOINT ["python3"]
