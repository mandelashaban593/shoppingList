
Create a virtual environment for the project and activate it:
```
virtualenv shoplstmgt_env
source shoplstmgt_env/bin/activate
```

Install the required packages:
```
pip install -r requirements.txt
```

## Database configuration
You will need to create a MySQL user your terminal, as well as a MySQL database. Then, grant all privileges on your database to your user, like so:

```
$ mysql -u root

mysql> CREATE USER 'dt_adminshop'@'localhost' IDENTIFIED BY 'dt2016shop';;

mysql> CREATE DATABASE dreamteam_dbshop;

mysql> GRANT ALL PRIVILEGES ON dreamteam_dbshop . * TO 'dt_adminshop'@'localhost';
```

Note that `dt_adminshop` is the database user and `dt2016shop` is the user password. After creating the database, run migrations as follows:

* `flask db migrate`
* `flask db upgrade`

## instance/config.py file
Create a directory, `instance`, and in it create a `config.py` file. This file should contain configuration variables that should not be publicly shared, such as passwords and secret keys. The app requires you to have the following configuration
variables:
* SECRET_KEY
* SQLALCHEMY_DATABASE_URI (`'mysql://dt_admin:dt2016shop@localhost/dreamteam_dbshop'`)

## Launching the Program
Set the FLASK_APP and FLASK_CONFIG variables as follows:

* `export FLASK_APP=run.py`
* `export FLASK_CONFIG=development`

You can now run the app with the following command: `flask run`

## Testing
First, create a test database and grant all privileges on your test database to your user:

```
$ mysql -u root

mysql> CREATE DATABASE dreamteam_testshop;

mysql> GRANT ALL PRIVILEGES ON dreamteam_testshop . * TO 'dt_adminshop'@'localhost';
```

To test, run the following command: `python tests.py`

## Built With...
* [Flask](http://flask.pocoo.org/)

## Credits and License

Copyright (c) 2017 [Mandela Shaban](https://github.com/mandelashaban593)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
