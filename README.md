# django-rest-framework
# ========================= install  =================================
###### ======== virtualenv ======== ######
### install virtualenv ###
python -m pip install virtualenv 
### use virtualenv ###
virtualenv venv 
### activate virtualenv ###
source venv/bin/activate


###### ======== dependencies ======== ######
python -m pip install django
python -m pip install djangorestframework-simplejwt
python -m pip install drf-yasg

python -m pip install faker



###### ======== redis ======== ######
docker run -p 6379:6379 -d redis:5