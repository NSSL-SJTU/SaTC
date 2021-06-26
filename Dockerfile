FROM smile0304/satc_ubuntu:v1.3

MAINTAINER TT <tt.jiaqi@gmail.com>


RUN su - satc -c "source /usr/local/bin/virtualenvwrapper.sh && \
                    cd ~ && git clone https://github.com/NSSL-SJTU/SaTC.git \
                    && cd ~/SaTC/satc_front \
                    && mkvirtualenv satc -p python3.8 \
                    && pip install -r requirements.txt \
                    && cd ~/SaTC/satc_front/jsparse \
                    && npm install \
                    && echo 'workon satc' >> /home/satc/.bashrc"

CMD su - satc
