sudo make docker
sudo docker run -p 81:4433 --rm -it -v /home/debian/Code/kratos/contrib/quickstart/kratos/email-password:/etc/config/kratos oryd/kratos:latest serve -c /etc/config/kratos/kratos.yml
