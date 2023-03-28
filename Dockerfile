FROM selenium/standalone-chrome

WORKDIR /opt/yawf

COPY requirements.txt requirements.txt
RUN sudo apt-get update && sudo apt-get install -y python3-pip
RUN pip3 install -r requirements.txt -i http://pypi.doubanio.com/simple --trusted-host pypi.doubanio.com

COPY . .

ENTRYPOINT ["python3"]
