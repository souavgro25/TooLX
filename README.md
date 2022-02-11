# TooLX

Passive and active recon tool

installation(this installation is for ubuntu/linux)

steps to setup repositry

1. install vs code in ubuntu

1 > sudo snap install --classic code

2. install mysql

1 > sudo apt install mysql-server mysql-client

2 > apt-get install libmysqlclient-dev

3. creating enviroment

1 > pip/pip3 install virtualenv

if it wont work then run

sudo apt install virtaulenv

then run

2 > virtualenv project

3 > cd project

4 > source bin/activate

this will look like this now

(project) sourabh@sourabh-Lenovo-ideapad-330-15IKB:~/Desktop/project$

4. now install git in ubuntu

1 > sudo apt install git

then clone the repositry

git clone https://github.com/souavgro25/TooLX

then go into repositry and find requirements.txt

pip install -r requirements.txt

5. create a user in mysql

commands

1 > sudo mysql

2 > CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';

3 > GRANT ALL PRIVILEGES ON _ . _ TO 'newuser'@'localhost';

in newuser , password give your username and password to create a user with all previleges

6. create a database by logging into the mysql

1 > mysql -u username -p password

2 > create database dbname

7. go into the repository and search for setting files and change database info

DATABASES = {

    'default': {

        'ENGINE': 'django.db.backends.mysql',

        'NAME': 'yourdbname',

        'USER': 'yourusername',

        'PASSWORD': 'yourpassword',

        'HOST': 'localhost',

    }

}
save the file

8. run migrations to create the tables in db

1 > python manage.py migrate

9. run local to server to access to website

1 > python manage.py runserver

    this will start the localserver with 8000 default port if it gives error on 8000 port is already in use
    try with different port like

2 > python manage.py runserver 9000

    9000 here is specified port on which i want to start the service
