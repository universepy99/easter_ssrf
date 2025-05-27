TO INSTALATION 
#IN KALI LINUX/DEBIAN/UBUNTU
sudo apt update
sudo apt install -y python3 python3-pip nmap sqlmap
pip3 install -r requirements.txt

#IN ARCH LINUX
sudo pacman -Syu python python-pip nmap sqlmap
pip install -r requirements.txt

# IN DOCKER
FROM python:3.11-slim

RUN apt update && apt install -y nmap sqlmap curl

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "your_script_name.py"]

                                                                                  #GREY_HAT 
