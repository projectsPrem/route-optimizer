pip install awsebcli
eb init
eb create route-optimizer-env  
eb setenv $(cat .env | grep -v ^# | xargs)
eb deploy