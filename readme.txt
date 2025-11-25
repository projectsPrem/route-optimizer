eb init
eb create route-optimization-env --service-role LabRole --instance_profile LabInstanceProfile
not required - eb setenv $(cat .env | grep -v ^# | xargs)
eb deploy


eb create route-optimization-env --service-role aws-elasticbeanstalk-ec2-role --instance_profile aws-elasticbeanstalk-ec2-role