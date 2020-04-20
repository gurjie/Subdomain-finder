FROM python:3
ADD intel_script.py /
RUN pip install censys
RUN pip install requests
RUN pip install IPy
RUN pip install beautifulsoup4
RUN pip install google
RUN pip install urllib3
RUN pip install pydig
RUN apt-get update && apt-get install -y dnsutils
ENTRYPOINT [ "python", "./intel_script.py"  ]
